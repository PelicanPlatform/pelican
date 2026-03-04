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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

	// lastStdinKeepalive is the time of the last stdin keepalive received from origin
	lastStdinKeepalive atomic.Value // time.Time

	// stdinReader is a buffered reader for stdin
	stdinReader *bufio.Reader

	// stdinMu protects stdin read operations
	stdinMu sync.Mutex

	// stdoutMu protects stdout write operations
	stdoutMu sync.Mutex

	// mu protects shared state
	mu sync.Mutex

	// ctx is the helper context
	ctx context.Context

	// cancel cancels the helper context
	cancel context.CancelFunc

	// brokerTransport is the HTTP transport used for broker polling.
	// Stored here so shutdown can call CloseIdleConnections() to
	// force-abort stuck TLS handshakes through the tunnel.
	brokerTransport *http.Transport

	// startTime is when the helper started
	startTime time.Time
}

// HelperKeepaliveResponse is the helper's response to a keepalive
type HelperKeepaliveResponse struct {
	OK        bool      `json:"ok"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

// StdinMessage is a message sent over stdin from the origin to the helper
type StdinMessage struct {
	Type string `json:"type"` // "ping" or "shutdown"
}

// StdoutMessage is a message sent over stdout from the helper to the origin
type StdoutMessage struct {
	Type       string    `json:"type"` // "pong", "ready", "listening", or "goodbye"
	Timestamp  time.Time `json:"timestamp"`
	Uptime     string    `json:"uptime,omitempty"`
	SocketPath string    `json:"socket_path,omitempty"` // direct-listen mode: Unix socket path
}

// RunHelper is the main entry point for the SSH helper process
// It reads configuration from stdin and runs the WebDAV server
func RunHelper(ctx context.Context) error {
	sshLog.Info("SSH helper process starting")

	// Read configuration from stdin
	config, stdinReader, err := readHelperConfig()
	if err != nil {
		return errors.Wrap(err, "failed to read helper config from stdin")
	}

	// Use JSON formatter so the origin can reliably parse our log output
	// from stderr and relay it with structured fields (daemon=ssh-helper).
	log.SetFormatter(&log.JSONFormatter{})

	// Apply the log level from the origin, if provided
	if config.LogLevel != "" {
		if lvl, err := log.ParseLevel(config.LogLevel); err == nil {
			log.SetLevel(lvl)
			sshLog.Debugf("Log level set to %s (from origin)", lvl)
		} else {
			sshLog.Warnf("Ignoring unrecognised log level %q from origin: %v", config.LogLevel, err)
		}
	}

	sshLog.Infof("Helper configured with %d exports", len(config.Exports))

	// Create the helper process
	ctx, cancel := context.WithCancel(ctx)
	helper := &HelperProcess{
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
		startTime:   time.Now(),
		stdinReader: stdinReader,
	}
	helper.lastHTTPKeepalive.Store(time.Now())
	helper.lastStdinKeepalive.Store(time.Now())

	// Initialize the WebDAV handlers
	if err := helper.initializeHandlers(); err != nil {
		return errors.Wrap(err, "failed to initialize handlers")
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Send ready message to origin
	if err := helper.sendStdoutMessage(StdoutMessage{
		Type:      "ready",
		Timestamp: time.Now(),
	}); err != nil {
		sshLog.Warnf("Failed to send ready message: %v", err)
	}

	// Use errgroup to track all goroutines
	egrp, egrpCtx := errgroup.WithContext(ctx)

	// Start the stdin keepalive handler (origin drives, helper responds)
	egrp.Go(func() error {
		return helper.runStdinKeepalive(egrpCtx)
	})

	// Start the keepalive monitor (checks both HTTP and stdin keepalives)
	egrp.Go(func() error {
		helper.runKeepaliveMonitor(egrpCtx)
		return nil
	})

	// Start the broker listener
	if helper.config.DirectListenMode {
		// Direct-listen mode: start an HTTP server on localhost and report
		// the port.  The origin dials through SSH, so no TLS brokering needed.
		egrp.Go(func() error {
			helper.runDirectListener(egrpCtx)
			return nil
		})
	} else {
		// Broker mode: poll the origin for reverse-connection requests.
		egrp.Go(func() error {
			helper.runBrokerListener(egrpCtx)
			return nil
		})
	}

	// Wait for signal, context cancellation, or errgroup error
	select {
	case sig := <-sigChan:
		sshLog.Infof("Received signal %v, shutting down", sig)
		cancel()
	case <-egrpCtx.Done():
		sshLog.Info("Context cancelled, shutting down")
	}

	// Graceful shutdown
	helper.shutdown()

	// Wait for all goroutines to finish
	if err := egrp.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		sshLog.Debugf("Errgroup finished with error: %v", err)
	}

	// Send a goodbye message so the origin can log acknowledgment.
	if err := helper.sendStdoutMessage(StdoutMessage{
		Type:      "goodbye",
		Timestamp: time.Now(),
		Uptime:    time.Since(helper.startTime).String(),
	}); err != nil {
		sshLog.Debugf("Failed to send goodbye message: %v", err)
	}

	sshLog.Info("SSH helper process exiting")
	return nil
}

// readHelperConfig reads the HelperConfig from stdin
// Returns the config and the buffered reader for continued stdin use
func readHelperConfig() (*HelperConfig, *bufio.Reader, error) {
	reader := bufio.NewReader(os.Stdin)

	// Read until newline
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, nil, errors.Wrap(err, "failed to read from stdin")
	}

	var config HelperConfig
	if err := json.Unmarshal(line, &config); err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse config JSON")
	}

	return &config, reader, nil
}

// initializeHandlers sets up the WebDAV handlers for each export
func (h *HelperProcess) initializeHandlers() error {
	h.webdavHandlers = make(map[string]*webdav.Handler)

	for _, export := range h.config.Exports {
		// Use OsRootFs from server_utils to prevent symlink traversal attacks
		// This uses Go 1.25's os.Root to ensure all file operations
		// stay within the designated storage prefix
		osRootFs, err := server_utils.NewOsRootFs(export.StoragePrefix)
		if err != nil {
			return errors.Wrapf(err, "failed to create OsRootFs for %s", export.StoragePrefix)
		}

		// Wrap with auto-directory creation using server_utils
		autoFs := server_utils.NewAutoCreateDirFs(osRootFs)

		// Create the WebDAV handler
		logger := func(r *http.Request, err error) {
			if err != nil {
				sshLog.Debugf("WebDAV error for %s %s: %v", r.Method, r.URL.Path, err)
			}
		}

		// Use server_utils AferoFileSystem
		afs := server_utils.NewAferoFileSystem(autoFs, "", logger)

		handler := &webdav.Handler{
			FileSystem: afs,
			LockSystem: webdav.NewMemLS(),
			Logger:     logger,
		}

		h.webdavHandlers[export.FederationPrefix] = handler
		sshLog.Infof("Initialized WebDAV handler for %s -> %s", export.FederationPrefix, export.StoragePrefix)
	}

	return nil
}

// runStdinKeepalive handles ping/pong keepalive messages from the origin via stdin.
// The origin drives the keepalive rate - it sends "ping" messages and the helper
// responds with "pong". The origin can also send "shutdown" to gracefully stop the helper.
func (h *HelperProcess) runStdinKeepalive(ctx context.Context) error {
	// Use a single persistent goroutine for reading stdin to avoid orphaned goroutines.
	// The reader goroutine will exit when stdin is closed (EOF) or on read error.
	type readResult struct {
		line []byte
		err  error
	}
	resultChan := make(chan readResult)

	// Start a single reader goroutine that persists for the lifetime of this function
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			h.stdinMu.Lock()
			line, err := h.stdinReader.ReadBytes('\n')
			h.stdinMu.Unlock()

			select {
			case resultChan <- readResult{line: line, err: err}:
				if err != nil {
					// Exit on any error (including EOF)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Ensure the reader goroutine is cleaned up when we exit
	defer func() {
		// Close stdin to unblock the reader goroutine if it's waiting
		os.Stdin.Close()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-resultChan:
			if result.err != nil {
				if result.err == io.EOF {
					sshLog.Info("Stdin closed, shutting down")
					h.cancel()
					return nil
				}
				sshLog.Warnf("Error reading from stdin: %v", result.err)
				h.cancel()
				return result.err
			}

			var msg StdinMessage
			if err := json.Unmarshal(result.line, &msg); err != nil {
				sshLog.Debugf("Failed to parse stdin message: %v", err)
				continue
			}

			switch msg.Type {
			case "ping":
				// Update last keepalive time
				h.lastStdinKeepalive.Store(time.Now())

				// Send pong response
				if err := h.sendStdoutMessage(StdoutMessage{
					Type:      "pong",
					Timestamp: time.Now(),
					Uptime:    time.Since(h.startTime).String(),
				}); err != nil {
					sshLog.Warnf("Failed to send pong: %v", err)
				}

			case "shutdown":
				sshLog.Info("Received shutdown message from origin")
				h.cancel()
				return nil

			default:
				sshLog.Debugf("Unknown stdin message type: %s", msg.Type)
			}
		}
	}
}

// sendStdoutMessage sends a JSON message to stdout
func (h *HelperProcess) sendStdoutMessage(msg StdoutMessage) error {
	h.stdoutMu.Lock()
	defer h.stdoutMu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(os.Stdout, "%s\n", data)
	return err
}

// runKeepaliveMonitor monitors keepalive messages and shuts down if no keepalive received.
// It checks both HTTP keepalives (from WebDAV requests) and stdin keepalives (from origin).
func (h *HelperProcess) runKeepaliveMonitor(ctx context.Context) {
	timeout := h.config.KeepaliveTimeout
	if timeout <= 0 {
		timeout = DefaultKeepaliveTimeout
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check both HTTP and stdin keepalives
			lastHTTP := h.lastHTTPKeepalive.Load().(time.Time)
			lastStdin := h.lastStdinKeepalive.Load().(time.Time)

			// Use the more recent of the two
			lastKeepalive := lastHTTP
			if lastStdin.After(lastHTTP) {
				lastKeepalive = lastStdin
			}

			if time.Since(lastKeepalive) > timeout {
				sshLog.Warnf("Keepalive timeout exceeded (last HTTP: %v ago, last stdin: %v ago, timeout: %v), shutting down",
					time.Since(lastHTTP), time.Since(lastStdin), timeout)
				h.cancel()
				return
			}
		}
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware wraps an http.Handler and logs every request at Debug level.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip keepalive endpoint — it's high-frequency and uninteresting.
		if r.URL.Path == "/api/v1.0/ssh-helper/keepalive" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		sshLog.WithFields(log.Fields{
			"method":      r.Method,
			"resource":    r.URL.Path,
			"status":      rec.status,
			"fields.time": time.Since(start).Round(time.Microsecond).String(),
		}).Debug("Served Request")
	})
}

// createHTTPHandler builds the HTTP handler used by both broker and direct-listen modes.
func (h *HelperProcess) createHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	// Add keepalive endpoint
	mux.HandleFunc("/api/v1.0/ssh-helper/keepalive", h.handleKeepalive)

	// Add WebDAV handlers for each export
	for prefix, handler := range h.webdavHandlers {
		mux.Handle(prefix+"/", http.StripPrefix(prefix, h.wrapWithAuth(handler)))
		sshLog.Debugf("Registered WebDAV handler at %s", prefix)
	}
	return loggingMiddleware(mux)
}

// runBrokerListener listens for incoming broker connections
func (h *HelperProcess) runBrokerListener(ctx context.Context) {
	// Register with the broker using the provided callback URL
	// The helper will poll the broker for reverse connection requests
	// and serve WebDAV over those connections

	sshLog.Infof("Connecting to broker at %s", h.config.OriginCallbackURL)

	handler := h.createHTTPHandler()

	// Start serving on a local port and register with the broker
	// The broker will forward connections to us
	h.serveWithBroker(ctx, handler)
}

// runDirectListener starts a plain HTTP server on a Unix domain socket and
// reports the socket path to the origin via stdout.  The origin will connect
// to this socket through an SSH direct-streamlocal channel, so no TLS or
// complex brokering is needed — the SSH channel already provides encryption
// and authentication.
//
// The socket is placed in a temporary directory under ~/.cache/pelican/ with
// 0700 permissions so that other users on the host cannot connect to it.
// If the resulting path would exceed the platform's sun_path limit (104 on
// macOS, 108 on Linux), we fall back to /tmp which is always short enough.
func (h *HelperProcess) runDirectListener(ctx context.Context) {
	handler := h.createHTTPHandler()

	// Build the base directory: ~/.cache/pelican (same tree as the binary
	// cache).  os.UserCacheDir returns ~/.cache on Linux and
	// ~/Library/Caches on macOS.
	baseDir, err := os.UserCacheDir()
	if err != nil {
		sshLog.Errorf("Failed to determine user cache directory: %v", err)
		return
	}
	baseDir = filepath.Join(baseDir, "pelican")

	// Unix domain socket paths are limited to 104 bytes on macOS and 108 on
	// Linux (the sun_path field of struct sockaddr_un).  Estimate the final
	// path length: baseDir + "/ssh-helper-XXXXXXXXXX" (21) + "/s" (2) + NUL.
	// The template used by MkdirTemp appends up to 10 random characters.
	const maxSocketPath = 104 // use the stricter macOS limit
	const suffixLen = 21 + 2 + 1
	if len(baseDir)+suffixLen > maxSocketPath {
		sshLog.Infof("Cache dir path too long for unix socket (%d + %d > %d); falling back to /tmp",
			len(baseDir), suffixLen, maxSocketPath)
		baseDir = "/tmp"
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		sshLog.Errorf("Failed to create base directory %s: %v", baseDir, err)
		return
	}

	// Create a private temporary directory for the socket.
	sockDir, err := os.MkdirTemp(baseDir, "ssh-helper-")
	if err != nil {
		sshLog.Errorf("Failed to create socket temp directory: %v", err)
		return
	}
	defer os.RemoveAll(sockDir)

	// Ensure 0700 permissions so other users cannot access the socket.
	if err := os.Chmod(sockDir, 0700); err != nil {
		sshLog.Errorf("Failed to chmod socket directory: %v", err)
		return
	}

	socketPath := filepath.Join(sockDir, "s")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		sshLog.Errorf("Failed to listen on unix socket %s: %v", socketPath, err)
		return
	}
	defer listener.Close()

	// Report the socket path to the origin via stdout so it can dial
	// through an SSH direct-streamlocal channel.
	if err := h.sendStdoutMessage(StdoutMessage{
		Type:       "listening",
		SocketPath: socketPath,
		Timestamp:  time.Now(),
	}); err != nil {
		sshLog.Errorf("Failed to send listening message: %v", err)
		return
	}

	sshLog.Infof("Direct listener started on unix socket %s", socketPath)

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		sshLog.Errorf("Direct listener error: %v", err)
	}
}

// handleKeepalive handles keepalive requests from the origin
func (h *HelperProcess) handleKeepalive(w http.ResponseWriter, r *http.Request) {
	// Validate via the Authorization header, consistent with all other endpoints.
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token == authHeader || token != h.config.AuthCookie {
		sshLog.Warn("Keepalive request with invalid or missing authorization")
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
		sshLog.Warnf("Failed to encode keepalive response: %v", err)
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

		// Check for auth token in Authorization header (Bearer token)
		authHeader := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if token != h.config.AuthCookie {
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
//
// Each poller loops: poll for a request, launch callbackAndServe in an errgroup
// goroutine, and immediately loop back to polling. This keeps the pollers always
// available while serving happens concurrently.
func (h *HelperProcess) serveWithBroker(ctx context.Context, handler http.Handler) {
	sshLog.Info("Starting broker-based reverse connection listener")

	// Get the origin callback URL from config
	callbackURL := h.config.OriginCallbackURL
	if callbackURL == "" {
		sshLog.Error("No origin callback URL configured")
		return
	}

	// Construct the retrieve and callback endpoints
	// The origin exposes /api/v1.0/origin/ssh/retrieve and /api/v1.0/origin/ssh/callback
	retrieveURL := callbackURL[:len(callbackURL)-len("/callback")] + "/retrieve"

	// Create HTTP client for polling (with TLS using origin's certificate chain)
	client, err := h.createBrokerClient()
	if err != nil {
		sshLog.Errorf("Failed to create broker client: %v", err)
		return
	}

	// Use errgroup for proper goroutine management
	egrp, egrpCtx := errgroup.WithContext(ctx)

	// When the context is cancelled (shutdown), force-close any in-flight
	// HTTP connections so TLS handshakes stuck in the tunnel don't block
	// the pollers from exiting.
	egrp.Go(func() error {
		<-egrpCtx.Done()
		if h.brokerTransport != nil {
			h.brokerTransport.CloseIdleConnections()
		}
		return nil
	})

	// Fixed number of pollers. Each poller loops continuously, launching
	// callbackAndServe in a separate goroutine so the poller immediately
	// returns to polling.
	numPollers := 3
	for i := 0; i < numPollers; i++ {
		egrp.Go(func() error {
			h.pollAndServe(egrpCtx, egrp, client, retrieveURL, callbackURL, handler)
			return nil
		})
	}

	// Wait for all pollers to finish
	if err := egrp.Wait(); err != nil {
		sshLog.Debugf("Broker pollers finished with error: %v", err)
	}
	sshLog.Info("Broker listener shutting down")
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

	// When using SSH tunnel mode, the helper connects to 127.0.0.1 on a
	// forwarded port, but the origin's TLS certificate is issued for the
	// origin's actual hostname. Override the ServerName so TLS verification
	// checks the certificate against the real hostname.
	if h.config.TLSServerName != "" {
		tlsConfig.ServerName = h.config.TLSServerName
		sshLog.Debugf("Using TLS ServerName override: %s", h.config.TLSServerName)
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		// Disable HTTP/2 to allow connection hijacking
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
		// Explicit dial timeout prevents unbounded hangs from the default
		// zero-timeout dialer when tunnels are in use.
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// Do not pool connections across requests — each poll/callback
		// cycle should use a fresh connection so that context-driven
		// cancellation during shutdown can immediately close it.
		DisableKeepAlives: true,
	}

	// Store the transport so serveWithBroker can close it during shutdown.
	h.brokerTransport = transport

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// pollAndServe continuously polls the origin for connection requests.
// When it picks up a request, it launches callbackAndServe in an errgroup
// goroutine and immediately loops back to polling.
func (h *HelperProcess) pollAndServe(ctx context.Context, egrp *errgroup.Group, client *http.Client, retrieveURL, callbackURL string, handler http.Handler) {
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
				sshLog.Debugf("Poll retrieve error: %v", err)
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

		// Got a request - serve it in a separate goroutine so this
		// poller can immediately loop back to polling.
		serveReqID := reqID
		egrp.Go(func() error {
			sshLog.Debugf("Got connection request %s, calling back to origin", serveReqID)
			if err := h.callbackAndServe(ctx, client, callbackURL, serveReqID, handler); err != nil {
				sshLog.Errorf("Failed to handle connection request %s: %v", serveReqID, err)
			}
			return nil
		})
	}
}

// pollRetrieve polls the origin's retrieve endpoint for pending requests
func (h *HelperProcess) pollRetrieve(ctx context.Context, client *http.Client, retrieveURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, retrieveURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create retrieve request")
	}
	req.Header.Set("Authorization", "Bearer "+h.config.AuthCookie)
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
		RequestID: reqID,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to marshal callback request")
	}

	// Parse the callback URL to get host and path
	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return errors.Wrap(err, "failed to parse callback URL")
	}

	// Parse the origin's certificate chain for TLS verification
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(h.config.CertificateChain)) {
		return errors.New("failed to parse origin certificate chain")
	}

	// Establish a raw TLS connection to the origin.
	// We do NOT use Go's http.Client because its transport takes ownership of the
	// connection and runs background goroutines (readLoop/writeLoop) that interfere
	// with connection reversal. Instead, we do manual HTTP over the TLS connection
	// so we retain full control for the reverse-serving step.
	callbackTLSConfig := &tls.Config{
		RootCAs: certPool,
	}
	// When using SSH tunnel mode, override ServerName for TLS verification
	// (same reason as in createBrokerClient — connecting to 127.0.0.1 but cert
	// is for the origin's actual hostname).
	if h.config.TLSServerName != "" {
		callbackTLSConfig.ServerName = h.config.TLSServerName
	}
	dialer := &tls.Dialer{
		Config: callbackTLSConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", parsedURL.Host)
	if err != nil {
		return errors.Wrap(err, "failed to establish TLS connection for callback")
	}

	// Write the HTTP request manually
	reqLine := fmt.Sprintf("POST %s HTTP/1.1\r\n", parsedURL.RequestURI())
	headers := fmt.Sprintf("Host: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Bearer %s\r\nConnection: keep-alive\r\n\r\n",
		parsedURL.Host, len(bodyBytes), h.config.AuthCookie)

	if _, err := io.WriteString(conn, reqLine+headers); err != nil {
		conn.Close()
		return errors.Wrap(err, "failed to write callback request headers")
	}
	if _, err := conn.Write(bodyBytes); err != nil {
		conn.Close()
		return errors.Wrap(err, "failed to write callback request body")
	}

	// Read the HTTP response manually
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return errors.Wrap(err, "failed to read callback response")
	}

	var respBody helperCallbackResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		resp.Body.Close()
		conn.Close()
		return errors.Wrap(err, "failed to decode callback response")
	}
	// Drain and close the response body
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if respBody.Status != "ok" {
		conn.Close()
		return errors.Errorf("callback failed: %s", respBody.Msg)
	}

	// Connection is now reversed - we become the HTTP server.
	// The TLS connection is still valid and encrypted, and we have full ownership
	// since no Go HTTP transport goroutines are associated with it.

	// Serve a single HTTP request on the TLS-encrypted reversed connection
	sshLog.Debugf("Serving HTTP on reversed TLS connection for request %s", reqID)
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Shut the single-request server down when the context is cancelled so
	// the helper can exit promptly during graceful shutdown.
	go func() {
		<-ctx.Done()
		// Use a short timeout — the connection is already being abandoned.
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	// Create a one-shot listener using the TLS connection
	listener := newOneShotConnListener(conn)
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
	sshLog.Info("Helper shutdown initiated")
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.httpServer != nil {
		sshLog.Debug("Shutting down HTTP server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.httpServer.Shutdown(ctx); err != nil {
			sshLog.Warnf("Failed to shutdown HTTP server: %v", err)
		}
	}

	sshLog.Debug("Cancelling helper context")
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
