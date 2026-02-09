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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_utils"
)

// HelperProcess represents the remote helper process
type HelperProcess struct {
	config *HelperConfig

	// httpServer is the HTTP server for handling broker callbacks
	httpServer *http.Server

	// webdavHandlers maps federation prefixes to WebDAV handlers
	webdavHandlers map[string]*webdav.Handler

	// lastHTTPKeepalive is the time of the last HTTP keepalive received
	lastHTTPKeepalive atomic.Value // time.Time

	// mu protects shared state
	mu sync.Mutex

	// ctx is the helper context
	ctx context.Context

	// cancel cancels the helper context
	cancel context.CancelFunc

	// startTime is when the helper started
	startTime time.Time
}

// HelperKeepaliveRequest is sent by the origin to check if the helper is alive
type HelperKeepaliveRequest struct {
	Cookie string `json:"cookie"`
}

// HelperKeepaliveResponse is the helper's response to a keepalive
type HelperKeepaliveResponse struct {
	OK        bool      `json:"ok"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

// RunHelper is the main entry point for the SSH helper process
// It reads configuration from stdin and runs the WebDAV server
func RunHelper(ctx context.Context) error {
	log.Info("SSH helper process starting")

	// Read configuration from stdin
	config, err := readHelperConfig()
	if err != nil {
		return errors.Wrap(err, "failed to read helper config from stdin")
	}

	log.Infof("Helper configured with %d exports", len(config.Exports))

	// Create the helper process
	ctx, cancel := context.WithCancel(ctx)
	helper := &HelperProcess{
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
	}
	helper.lastHTTPKeepalive.Store(time.Now())

	// Initialize the WebDAV handlers
	if err := helper.initializeHandlers(); err != nil {
		return errors.Wrap(err, "failed to initialize handlers")
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Start the keepalive monitor
	go helper.runKeepaliveMonitor()

	// Start listening for broker connections
	go helper.runBrokerListener()

	// Wait for signal or context cancellation
	select {
	case sig := <-sigChan:
		log.Infof("Received signal %v, shutting down", sig)
	case <-ctx.Done():
		log.Info("Context cancelled, shutting down")
	}

	// Graceful shutdown
	helper.shutdown()

	log.Info("SSH helper process exiting")
	return nil
}

// readHelperConfig reads the HelperConfig from stdin
func readHelperConfig() (*HelperConfig, error) {
	reader := bufio.NewReader(os.Stdin)

	// Read until newline
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, errors.Wrap(err, "failed to read from stdin")
	}

	var config HelperConfig
	if err := json.Unmarshal(line, &config); err != nil {
		return nil, errors.Wrap(err, "failed to parse config JSON")
	}

	return &config, nil
}

// initializeHandlers sets up the WebDAV handlers for each export
func (h *HelperProcess) initializeHandlers() error {
	h.webdavHandlers = make(map[string]*webdav.Handler)

	for _, export := range h.config.Exports {
		// Create a base filesystem rooted at StoragePrefix
		// Using afero.NewBasePathFs to restrict access to the storage prefix
		baseFs := afero.NewBasePathFs(afero.NewOsFs(), export.StoragePrefix)

		// Wrap with auto-directory creation
		fs := newHelperAutoCreateDirFs(baseFs)

		// Create the WebDAV handler
		logger := func(r *http.Request, err error) {
			if err != nil {
				log.Debugf("WebDAV error for %s %s: %v", r.Method, r.URL.Path, err)
			}
		}

		afs := &helperAferoFileSystem{
			fs:     fs,
			prefix: "",
			logger: logger,
		}

		handler := &webdav.Handler{
			FileSystem: afs,
			LockSystem: webdav.NewMemLS(),
			Logger:     logger,
		}

		h.webdavHandlers[export.FederationPrefix] = handler
		log.Infof("Initialized WebDAV handler for %s -> %s", export.FederationPrefix, export.StoragePrefix)
	}

	return nil
}

// runKeepaliveMonitor monitors keepalive messages and shuts down if no keepalive received
func (h *HelperProcess) runKeepaliveMonitor() {
	timeout := h.config.KeepaliveTimeout
	if timeout <= 0 {
		timeout = DefaultKeepaliveTimeout
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			lastKeepalive := h.lastHTTPKeepalive.Load().(time.Time)
			if time.Since(lastKeepalive) > timeout {
				log.Warnf("HTTP keepalive timeout exceeded (last: %v ago, timeout: %v), shutting down",
					time.Since(lastKeepalive), timeout)
				h.cancel()
				return
			}
		}
	}
}

// runBrokerListener listens for incoming broker connections
func (h *HelperProcess) runBrokerListener() {
	// Register with the broker using the provided callback URL
	// The helper will poll the broker for reverse connection requests
	// and serve WebDAV over those connections

	log.Infof("Connecting to broker at %s", h.config.OriginCallbackURL)

	// Create the HTTP handler for serving WebDAV
	mux := http.NewServeMux()

	// Add keepalive endpoint
	mux.HandleFunc("/api/v1.0/ssh-helper/keepalive", h.handleKeepalive)

	// Add WebDAV handlers for each export
	for prefix, handler := range h.webdavHandlers {
		mux.Handle(prefix+"/", http.StripPrefix(prefix, h.wrapWithAuth(handler)))
		log.Debugf("Registered WebDAV handler at %s", prefix)
	}

	// Start serving on a local port and register with the broker
	// The broker will forward connections to us
	h.serveWithBroker(mux)
}

// handleKeepalive handles keepalive requests from the origin
func (h *HelperProcess) handleKeepalive(w http.ResponseWriter, r *http.Request) {
	// Parse the request
	var req HelperKeepaliveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate the cookie
	if req.Cookie != h.config.AuthCookie {
		log.Warn("Keepalive request with invalid cookie")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Update the last keepalive time
	h.lastHTTPKeepalive.Store(time.Now())

	// Send response
	resp := HelperKeepaliveResponse{
		OK:        true,
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Warnf("Failed to encode keepalive response: %v", err)
	}
}

// wrapWithAuth wraps a handler with authentication and capability enforcement
func (h *HelperProcess) wrapWithAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find the matching export for capability checks
		var matchingExport *ExportConfig
		for i := range h.config.Exports {
			if matchesPrefix(r.URL.Path, h.config.Exports[i].FederationPrefix) {
				matchingExport = &h.config.Exports[i]
				break
			}
		}

		// Enforce capability restrictions at the helper layer (defense in depth)
		// These checks apply regardless of authentication status
		if matchingExport != nil {
			// Check write capability for write operations
			isWriteMethod := r.Method == http.MethodPut || r.Method == http.MethodDelete ||
				r.Method == "MKCOL" || r.Method == "MOVE"
			if isWriteMethod && !matchingExport.Capabilities.Writes {
				http.Error(w, "writes not permitted for this export", http.StatusForbidden)
				return
			}

			// Check listings capability for directory listings (PROPFIND with Depth > 0)
			if r.Method == "PROPFIND" && !matchingExport.Capabilities.Listings {
				depth := r.Header.Get("Depth")
				if depth == "1" || depth == "infinity" {
					http.Error(w, "listings not permitted for this export", http.StatusForbidden)
					return
				}
			}
		}

		// Check for auth cookie in header
		cookie := r.Header.Get("X-Pelican-Auth-Cookie")
		if cookie != h.config.AuthCookie {
			// For WebDAV, we need to check authorization more carefully
			// Allow public reads if configured
			if matchingExport != nil {
				if matchingExport.Capabilities.PublicReads && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
					handler.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// matchesPrefix checks if a path matches a prefix
func matchesPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// serveWithBroker serves HTTP via the broker reverse connection mechanism.
// The helper polls the origin's retrieve endpoint for pending connection requests.
// When a request is pending, the helper connects to the origin's callback endpoint,
// and the connection gets reversed - the helper becomes the HTTP server while the
// origin becomes the client.
func (h *HelperProcess) serveWithBroker(handler http.Handler) {
	log.Info("Starting broker-based reverse connection listener")

	// Get the origin callback URL from config
	callbackURL := h.config.OriginCallbackURL
	if callbackURL == "" {
		log.Error("No origin callback URL configured")
		return
	}

	// Construct the retrieve and callback endpoints
	// The origin exposes /api/v1.0/origin/ssh/retrieve and /api/v1.0/origin/ssh/callback
	retrieveURL := callbackURL[:len(callbackURL)-len("/callback")] + "/retrieve"

	// Create HTTP client for polling (with TLS using origin's certificate chain)
	client, err := h.createBrokerClient()
	if err != nil {
		log.Errorf("Failed to create broker client: %v", err)
		return
	}

	// Use errgroup for proper goroutine management
	egrp, ctx := errgroup.WithContext(h.ctx)

	// Number of concurrent polling goroutines
	numPollers := 3

	for i := 0; i < numPollers; i++ {
		egrp.Go(func() error {
			h.pollAndServe(ctx, client, retrieveURL, callbackURL, handler)
			return nil
		})
	}

	// Wait for all pollers to finish
	if err := egrp.Wait(); err != nil {
		log.Debugf("Broker pollers finished with error: %v", err)
	}
	log.Info("Broker listener shutting down")
}

// createBrokerClient creates an HTTP client for communicating with the origin.
// It uses the origin's certificate chain for TLS verification.
func (h *HelperProcess) createBrokerClient() (*http.Client, error) {
	// Parse the origin's certificate chain to create a trusted root pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(h.config.CertificateChain)) {
		return nil, errors.New("failed to parse origin certificate chain")
	}

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Disable HTTP/2 to allow connection hijacking
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// pollAndServe continuously polls the origin for connection requests and serves them
func (h *HelperProcess) pollAndServe(ctx context.Context, client *http.Client, retrieveURL, callbackURL string, handler http.Handler) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Poll the retrieve endpoint
		reqID, err := h.pollRetrieve(ctx, client, retrieveURL)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Debugf("Poll retrieve error: %v", err)
			}
			// Brief backoff on error
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}

		if reqID == "" {
			// No pending request (timeout), continue polling
			continue
		}

		// Got a request - callback to origin and serve
		log.Debugf("Got connection request %s, calling back to origin", reqID)
		if err := h.callbackAndServe(ctx, client, callbackURL, reqID, handler); err != nil {
			log.Errorf("Failed to handle connection request %s: %v", reqID, err)
		}
	}
}

// pollRetrieve polls the origin's retrieve endpoint for pending requests
func (h *HelperProcess) pollRetrieve(ctx context.Context, client *http.Client, retrieveURL string) (string, error) {
	reqBody := helperRetrieveRequest{
		AuthCookie: h.config.AuthCookie,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal retrieve request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, retrieveURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", errors.Wrap(err, "failed to create retrieve request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pelican-Timeout", "5s")

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "retrieve request failed")
	}
	defer resp.Body.Close()

	var respBody helperRetrieveResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", errors.Wrap(err, "failed to decode retrieve response")
	}

	if respBody.Status == "error" {
		return "", errors.Errorf("retrieve error: %s", respBody.Msg)
	}

	if respBody.Status == "timeout" {
		return "", nil // No pending request
	}

	return respBody.RequestID, nil
}

// callbackAndServe connects to the origin's callback endpoint and serves HTTP.
// The TLS connection established during the callback is reused for serving HTTP
// in the reverse direction, maintaining encryption throughout.
func (h *HelperProcess) callbackAndServe(ctx context.Context, client *http.Client, callbackURL, reqID string, handler http.Handler) error {
	reqBody := helperCallbackRequest{
		RequestID:  reqID,
		AuthCookie: h.config.AuthCookie,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to marshal callback request")
	}

	// Parse the origin's certificate chain for TLS verification
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(h.config.CertificateChain)) {
		return errors.New("failed to parse origin certificate chain")
	}

	// Create a custom transport that captures the TLS connection for reversal.
	// We capture the TLS connection itself (not the underlying TCP) to maintain
	// encryption on the reversed connection.
	var capturedConn net.Conn
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
		// Disable HTTP/2 to allow connection hijacking
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Dial and perform TLS handshake
			dialer := &tls.Dialer{
				Config: &tls.Config{
					RootCAs: certPool,
				},
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				capturedConn = conn
			}
			return conn, err
		},
	}

	callbackClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrap(err, "failed to create callback request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := callbackClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "callback request failed")
	}
	defer resp.Body.Close()

	var respBody helperCallbackResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return errors.Wrap(err, "failed to decode callback response")
	}

	if respBody.Status != "ok" {
		return errors.Errorf("callback failed: %s", respBody.Msg)
	}

	// Connection should now be reversed - we become the server.
	// The TLS connection is still valid and encrypted.
	if capturedConn == nil {
		return errors.New("no connection captured for reversal")
	}

	// Close idle connections to ensure the transport releases our connection
	// without sending a close_notify. The connection is still valid for us to use.
	callbackClient.CloseIdleConnections()

	// Serve a single HTTP request on the TLS-encrypted reversed connection
	log.Debugf("Serving HTTP on reversed TLS connection for request %s", reqID)
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Create a one-shot listener using the TLS connection
	listener := newOneShotConnListener(capturedConn)
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// ErrServerClosed is expected after serving one request
		if !errors.Is(err, net.ErrClosed) {
			return errors.Wrap(err, "failed to serve on reversed connection")
		}
	}

	return nil
}

// oneShotConnListener is a net.Listener that accepts exactly one connection
type oneShotConnListener struct {
	conn   net.Conn
	addr   net.Addr
	closed atomic.Bool
}

func newOneShotConnListener(conn net.Conn) net.Listener {
	return &oneShotConnListener{
		conn: conn,
		addr: conn.LocalAddr(),
	}
}

func (l *oneShotConnListener) Accept() (net.Conn, error) {
	if l.closed.Swap(true) {
		return nil, net.ErrClosed
	}
	return l.conn, nil
}

func (l *oneShotConnListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (l *oneShotConnListener) Addr() net.Addr {
	return l.addr
}

// shutdown gracefully shuts down the helper
func (h *HelperProcess) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.httpServer.Shutdown(ctx); err != nil {
			log.Warnf("Failed to shutdown HTTP server: %v", err)
		}
	}

	h.cancel()
}

// HelperStatusCmd handles the `ssh-helper --command status` invocation
func HelperStatusCmd() (string, error) {
	status := HelperStatus{
		State:   HelperStateRunning,
		Message: "Helper is running",
		Uptime:  "unknown", // Would need IPC to get actual uptime
	}

	data, err := json.Marshal(status)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ConvertExportsToSSH converts server_utils.OriginExport to ssh_posixv2.ExportConfig
func ConvertExportsToSSH(exports []server_utils.OriginExport) []ExportConfig {
	result := make([]ExportConfig, len(exports))
	for i, export := range exports {
		result[i] = ExportConfig{
			FederationPrefix: export.FederationPrefix,
			StoragePrefix:    export.StoragePrefix,
			Capabilities: ExportCapabilities{
				PublicReads: export.Capabilities.PublicReads,
				Reads:       export.Capabilities.Reads,
				Writes:      export.Capabilities.Writes,
				Listings:    export.Capabilities.Listings,
				DirectReads: export.Capabilities.DirectReads,
			},
		}
	}
	return result
}

// PrintHelperUsage prints usage for the ssh-helper command
func PrintHelperUsage() {
	fmt.Println(`SSH Helper Process

This command is intended to be run by the SSH backend on a remote host.
It reads its configuration from stdin as JSON.

Usage:
  pelican ssh-helper [flags]

Flags:
  --command <cmd>   Run a specific command (status, shutdown)
  --help            Print this help message

The helper process:
  1. Reads configuration from stdin (JSON format)
  2. Initializes WebDAV handlers for each export
  3. Connects to the broker to receive reverse connections
  4. Serves WebDAV requests from the origin
  5. Maintains keepalives with the origin
  6. Shuts down if keepalives stop

Example configuration JSON:
  {
    "origin_callback_url": "https://origin.example.com/api/v1.0/ssh-helper/callback",
    "broker_url": "https://broker.example.com/api/v1.0/broker",
    "auth_cookie": "random_hex_string",
    "exports": [
      {
        "federation_prefix": "/test",
        "storage_prefix": "/data/test",
        "capabilities": {"public_reads": true, "reads": true, "writes": true}
      }
    ],
    "certificate_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "keepalive_interval": 5000000000,
    "keepalive_timeout": 20000000000
  }`)
}
