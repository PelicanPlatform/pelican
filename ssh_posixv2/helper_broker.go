/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package ssh_posixv2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// HelperBroker manages reverse connections between the origin and the SSH helper.
// It acts as a mini-broker that allows the origin to reach the helper through
// connection reversal - the helper polls the origin for pending requests, then
// calls back to establish connections that get reversed.
type HelperBroker struct {
	mu sync.Mutex

	// pendingRequests holds requests waiting for a helper connection
	pendingRequests map[string]*helperRequest

	// connectionPool holds available reverse connections to the helper
	connectionPool chan net.Conn

	// ctx is the context for the broker
	ctx context.Context

	// authCookie is used to authenticate helper requests
	authCookie string
}

// helperRequest represents a pending request waiting for a helper connection
type helperRequest struct {
	id         string
	responseCh chan http.ResponseWriter
	createdAt  time.Time
}

// helperRetrieveRequest is the request body for the retrieve endpoint
type helperRetrieveRequest struct {
	// AuthCookie authenticates the helper
	AuthCookie string `json:"auth_cookie"`
}

// helperRetrieveResponse is the response for the retrieve endpoint
type helperRetrieveResponse struct {
	Status    string `json:"status"` // "ok", "timeout", "error"
	RequestID string `json:"request_id,omitempty"`
	Msg       string `json:"msg,omitempty"`
}

// helperCallbackRequest is the request body for the callback endpoint
type helperCallbackRequest struct {
	RequestID  string `json:"request_id"`
	AuthCookie string `json:"auth_cookie"`
}

// helperCallbackResponse is the response for the callback endpoint
type helperCallbackResponse struct {
	Status string `json:"status"` // "ok", "error"
	Msg    string `json:"msg,omitempty"`
}

// oneShotListener is a listener that accepts exactly one connection
type oneShotListener struct {
	conn atomic.Pointer[net.Conn]
	addr net.Addr
}

var (
	// globalHelperBroker is the singleton broker instance
	globalHelperBroker *HelperBroker
	helperBrokerMu     sync.Mutex
)

// NewHelperBroker creates a new helper broker
func NewHelperBroker(ctx context.Context, authCookie string) *HelperBroker {
	return &HelperBroker{
		pendingRequests: make(map[string]*helperRequest),
		connectionPool:  make(chan net.Conn, 10), // Buffer for connection reuse
		ctx:             ctx,
		authCookie:      authCookie,
	}
}

// GetHelperBroker returns the global helper broker instance
func GetHelperBroker() *HelperBroker {
	helperBrokerMu.Lock()
	defer helperBrokerMu.Unlock()
	return globalHelperBroker
}

// SetHelperBroker sets the global helper broker instance
func SetHelperBroker(broker *HelperBroker) {
	helperBrokerMu.Lock()
	defer helperBrokerMu.Unlock()
	globalHelperBroker = broker
}

// ResetHelperBroker clears the global helper broker (for testing)
func ResetHelperBroker() {
	helperBrokerMu.Lock()
	defer helperBrokerMu.Unlock()
	if globalHelperBroker != nil {
		// Drain the connection pool
		close(globalHelperBroker.connectionPool)
		for conn := range globalHelperBroker.connectionPool {
			if conn != nil {
				conn.Close()
			}
		}
		globalHelperBroker = nil
	}
}

// generateRequestID generates a random request ID using crypto/rand
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen, but log if it does
		log.Warnf("crypto/rand failed: %v", err)
	}
	return hex.EncodeToString(b)
}

// RequestConnection requests a reverse connection to the helper.
// This blocks until a connection is available or the context is cancelled.
func (b *HelperBroker) RequestConnection(ctx context.Context) (net.Conn, error) {
	// First, check if there's an available connection in the pool
	select {
	case conn := <-b.connectionPool:
		if conn != nil {
			return conn, nil
		}
	default:
		// No pooled connection available
	}

	// Create a pending request
	reqID := generateRequestID()
	responseCh := make(chan http.ResponseWriter, 1)

	b.mu.Lock()
	b.pendingRequests[reqID] = &helperRequest{
		id:         reqID,
		responseCh: responseCh,
		createdAt:  time.Now(),
	}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.pendingRequests, reqID)
		b.mu.Unlock()
	}()

	// Wait for the helper to call back
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.ctx.Done():
		return nil, errors.New("helper broker shutdown")
	case writer := <-responseCh:
		// The helper has called back - hijack the connection
		return b.hijackConnection(writer, reqID)
	}
}

// hijackConnection hijacks the HTTP connection and reverses it.
// The TLS connection is preserved to maintain encryption on the reversed connection.
func (b *HelperBroker) hijackConnection(writer http.ResponseWriter, reqID string) (net.Conn, error) {
	hj, ok := writer.(http.Hijacker)
	if !ok {
		// Write error response
		resp := helperCallbackResponse{
			Status: "error",
			Msg:    "Unable to reverse TCP connection; HTTP/2 in use",
		}
		respBytes, _ := json.Marshal(&resp)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		if _, err := writer.Write(respBytes); err != nil {
			log.Warnf("Failed to write error response: %v", err)
		}
		return nil, errors.New("HTTP hijacking not supported")
	}

	// Write success response before hijacking
	resp := helperCallbackResponse{
		Status: "ok",
	}
	respBytes, err := json.Marshal(&resp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal callback response")
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	writer.WriteHeader(http.StatusOK)
	if _, err = writer.Write(respBytes); err != nil {
		return nil, errors.Wrap(err, "failed to write callback response")
	}

	// Flush the response
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	// Hijack the connection. We keep the TLS connection intact to maintain
	// encryption when the connection is reversed.
	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to hijack connection")
	}

	log.Debugf("Helper broker: hijacked TLS connection for request %s", reqID)
	return conn, nil
}

// hasPendingRequest checks if there are any pending requests
func (b *HelperBroker) hasPendingRequest() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for id := range b.pendingRequests {
		return id, true
	}
	return "", false
}

// RegisterHelperBrokerHandlers registers the HTTP handlers for the helper broker
func RegisterHelperBrokerHandlers(router *gin.Engine, ctx context.Context) {
	router.POST("/api/v1.0/origin/ssh/retrieve", func(c *gin.Context) {
		handleHelperRetrieve(ctx, c)
	})
	router.POST("/api/v1.0/origin/ssh/callback", func(c *gin.Context) {
		handleHelperCallback(ctx, c)
	})
}

// handleHelperRetrieve handles the retrieve endpoint that the helper polls
func handleHelperRetrieve(ctx context.Context, c *gin.Context) {
	broker := GetHelperBroker()
	if broker == nil {
		c.JSON(http.StatusServiceUnavailable, helperRetrieveResponse{
			Status: "error",
			Msg:    "SSH backend not initialized",
		})
		return
	}

	// Parse request
	var req helperRetrieveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, helperRetrieveResponse{
			Status: "error",
			Msg:    "Invalid request",
		})
		return
	}

	// Verify auth cookie
	if req.AuthCookie != broker.authCookie {
		c.JSON(http.StatusUnauthorized, helperRetrieveResponse{
			Status: "error",
			Msg:    "Invalid auth cookie",
		})
		return
	}

	// Parse timeout from header
	timeoutStr := c.GetHeader("X-Pelican-Timeout")
	timeout := 5 * time.Second
	if timeoutStr != "" {
		if parsed, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = parsed
		}
	}

	// Return early to ensure the OK response is received before the helper times out.
	// Return 200ms before the specified timeout; if timeout < 200ms, return at half the timeout.
	earlyReturn := 200 * time.Millisecond
	if timeout < 200*time.Millisecond {
		earlyReturn = timeout / 2
	}
	effectiveTimeout := timeout - earlyReturn
	if effectiveTimeout < 0 {
		effectiveTimeout = 0
	}

	// Wait for a pending request or timeout
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeoutCh := time.After(effectiveTimeout)

	for {
		select {
		case <-ctx.Done():
			c.JSON(http.StatusServiceUnavailable, helperRetrieveResponse{
				Status: "error",
				Msg:    "Server shutting down",
			})
			return
		case <-c.Done():
			return
		case <-timeoutCh:
			c.JSON(http.StatusOK, helperRetrieveResponse{
				Status: "timeout",
			})
			return
		case <-ticker.C:
			if reqID, ok := broker.hasPendingRequest(); ok {
				c.JSON(http.StatusOK, helperRetrieveResponse{
					Status:    "ok",
					RequestID: reqID,
				})
				return
			}
		}
	}
}

// handleHelperCallback handles the callback endpoint where the helper connects
func handleHelperCallback(ctx context.Context, c *gin.Context) {
	broker := GetHelperBroker()
	if broker == nil {
		c.JSON(http.StatusServiceUnavailable, helperCallbackResponse{
			Status: "error",
			Msg:    "SSH backend not initialized",
		})
		return
	}

	// Parse request
	var req helperCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, helperCallbackResponse{
			Status: "error",
			Msg:    "Invalid request",
		})
		return
	}

	// Verify auth cookie
	if req.AuthCookie != broker.authCookie {
		c.JSON(http.StatusUnauthorized, helperCallbackResponse{
			Status: "error",
			Msg:    "Invalid auth cookie",
		})
		return
	}

	// Find the pending request
	broker.mu.Lock()
	pending, ok := broker.pendingRequests[req.RequestID]
	broker.mu.Unlock()

	if !ok {
		c.JSON(http.StatusBadRequest, helperCallbackResponse{
			Status: "error",
			Msg:    "No such request ID",
		})
		return
	}

	// Pass the response writer to the waiting goroutine
	select {
	case <-ctx.Done():
		c.JSON(http.StatusServiceUnavailable, helperCallbackResponse{
			Status: "error",
			Msg:    "Server shutting down",
		})
		return
	case <-c.Done():
		return
	case pending.responseCh <- c.Writer:
		// The hijackConnection will handle the response
		// Wait for it to complete by blocking here
		<-pending.responseCh
	}
}

// newOneShotListener creates a one-shot listener from a connection
func newOneShotListener(conn net.Conn, addr net.Addr) net.Listener {
	l := &oneShotListener{addr: addr}
	l.conn.Store(&conn)
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	connPtr := l.conn.Swap(nil)
	if connPtr == nil {
		return nil, net.ErrClosed
	}
	return *connPtr, nil
}

func (l *oneShotListener) Close() error {
	l.conn.Swap(nil)
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.addr
}

// HelperTransport is an http.RoundTripper that uses reverse connections to the helper
type HelperTransport struct {
	broker *HelperBroker
}

// NewHelperTransport creates a new transport that uses the helper broker
func NewHelperTransport(broker *HelperBroker) *HelperTransport {
	return &HelperTransport{broker: broker}
}

// RoundTrip implements http.RoundTripper
func (t *HelperTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get a connection to the helper
	conn, err := t.broker.RequestConnection(req.Context())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get connection to helper")
	}

	// Create a client that uses the reverse connection.
	// The helper will be the server, we are the client.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	// Forward the request to the helper
	// Modify the URL to point to the helper's local address
	helperReq := req.Clone(req.Context())
	helperReq.URL.Scheme = "http" // Connection is already established
	helperReq.URL.Host = "helper" // Placeholder, connection is pre-established

	resp, err := client.Do(helperReq)
	if err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "failed to send request to helper")
	}

	return resp, nil
}

// GetAuthCookie returns the auth cookie for this broker
func (b *HelperBroker) GetAuthCookie() string {
	return b.authCookie
}

// StartCleanupRoutine starts a goroutine that periodically cleans up old requests.
// The goroutine is managed by the provided errgroup and respects context cancellation.
func (b *HelperBroker) StartCleanupRoutine(ctx context.Context, egrp *errgroup.Group, maxAge time.Duration, interval time.Duration) {
	egrp.Go(func() error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				b.cleanupOldRequests(maxAge)
			}
		}
	})
}

// cleanupOldRequests removes requests older than the specified duration
func (b *HelperBroker) cleanupOldRequests(maxAge time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for id, req := range b.pendingRequests {
		if now.Sub(req.createdAt) > maxAge {
			close(req.responseCh)
			delete(b.pendingRequests, id)
			log.Debugf("Cleaned up stale request %s (age: %v)", id, now.Sub(req.createdAt))
		}
	}
}
