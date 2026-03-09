/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

// Flusher is an interface for writers that support flushing buffered data
type Flusher interface {
	Flush() error
}

// pendingAuth stores the state for an in-progress device authentication
type pendingAuth struct {
	authInfo  *client.DeviceAuthInfo
	url       string
	createdAt time.Time
}

// cachedToken stores an acquired token for a namespace
type cachedToken struct {
	token     string
	namespace string // The namespace prefix this token is valid for
	createdAt time.Time
}

// Server implements the MCP server
type Server struct {
	reader       *bufio.Reader
	writer       io.Writer
	ctx          context.Context
	initialized  bool
	pendingAuths map[string]*pendingAuth // Map from URL to pending auth info
	cachedTokens map[string]*cachedToken // Map from namespace prefix to cached token
	authMutex    sync.Mutex
}

// NewServer creates a new MCP server
func NewServer(ctx context.Context, reader io.Reader, writer io.Writer) *Server {
	return &Server{
		reader:       bufio.NewReader(reader),
		writer:       writer,
		ctx:          ctx,
		pendingAuths: make(map[string]*pendingAuth),
		cachedTokens: make(map[string]*cachedToken),
	}
}

// ensureInitialized initializes the Pelican client if not already done
func (s *Server) ensureInitialized() error {
	if !s.initialized {
		// Set environment variable to skip terminal check for device auth flow.
		// The MCP server runs as a subprocess spawned by AI assistants (like Claude Code or
		// VS Code Copilot) which don't have a TTY attached. The terminal check in oauth2.AcquireToken
		// would normally prevent device auth from working in non-terminal environments.
		// By setting this env var, we enable the device auth flow to work, allowing the MCP server
		// to return verification URLs that users can click to authenticate.
		// This is safe because the MCP protocol allows returning the verification URL to the user
		// through the AI assistant's interface.
		os.Setenv(config.GetPreferredPrefix().String()+"_SKIP_TERMINAL_CHECK", "true")

		if err := config.InitClient(); err != nil {
			log.Errorf("Failed to initialize Pelican client: %v", err)
			return fmt.Errorf("failed to initialize Pelican client: %w", err)
		}
		s.initialized = true
		log.Info("Pelican client initialized")
	}
	return nil
}

// cacheToken stores a token for a given namespace
func (s *Server) cacheToken(namespace, token string) {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()
	s.cachedTokens[namespace] = &cachedToken{
		token:     token,
		namespace: namespace,
		createdAt: time.Now(),
	}
	log.Infof("Cached token for namespace: %s", namespace)
}

// getTokenForURL attempts to find a cached token that matches the given URL
func (s *Server) getTokenForURL(urlStr string) string {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()

	// Extract the path from the URL
	var path string
	if strings.HasPrefix(urlStr, "pelican://") || strings.HasPrefix(urlStr, "osdf://") {
		// URL format: pelican://host/path or osdf://path
		parts := strings.SplitN(urlStr, "://", 2)
		if len(parts) == 2 {
			hostAndPath := parts[1]
			slashIdx := strings.Index(hostAndPath, "/")
			if slashIdx != -1 {
				path = hostAndPath[slashIdx:]
			}
		}
	}

	if path == "" {
		return ""
	}

	// Check each cached token to see if its namespace matches the URL path
	for namespace, cached := range s.cachedTokens {
		if strings.HasPrefix(path, namespace) {
			log.Debugf("Found cached token for URL %s (namespace: %s)", urlStr, namespace)
			return cached.token
		}
	}
	return ""
}

// Run starts the MCP server and handles requests
func (s *Server) Run() error {
	log.Info("Pelican MCP server started")

	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Info("Client disconnected")
				return nil
			}
			log.Errorf("Error reading request: %v", err)
			return fmt.Errorf("error reading request: %w", err)
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Errorf("Error parsing JSON-RPC request: %v (raw: %s)", err, string(line))
			if sendErr := s.sendError(nil, -32700, "Parse error", nil); sendErr != nil {
				log.Errorf("Failed to send error response: %v", sendErr)
			}
			continue
		}

		log.Infof("Received request: method=%s, id=%v", req.Method, req.ID)

		if err := s.handleRequest(&req); err != nil {
			log.Errorf("Error handling request %s: %v", req.Method, err)
		}
	}
}

// handleRequest processes a JSON-RPC request
func (s *Server) handleRequest(req *JSONRPCRequest) error {
	// Check if this is a notification (no ID) - these should not get responses
	isNotification := req.ID == nil

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "initialized":
		// This is a notification sent after initialize - no response needed
		log.Debug("Received initialized notification")
		return nil
	case "tools/list":
		return s.handleListTools(req)
	case "tools/call":
		return s.handleCallTool(req)
	case "ping":
		if isNotification {
			return nil
		}
		return s.sendResponse(req.ID, map[string]interface{}{})
	case "notifications/cancelled":
		// Handle cancellation notification
		log.Debug("Received cancellation notification")
		return nil
	default:
		// Don't respond to unknown notifications
		if isNotification {
			log.Debugf("Ignoring unknown notification: %s", req.Method)
			return nil
		}
		return s.sendError(req.ID, -32601, "Method not found", nil)
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(req *JSONRPCRequest) error {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.sendError(req.ID, -32602, "Invalid params", err.Error())
	}

	log.Infof("Received initialize request from client: %s (protocol version: %s)",
		params.ClientInfo.Name, params.ProtocolVersion)

	result := InitializeResult{
		// Use a stable protocol version that's compatible with MCP clients
		// The MCP protocol uses dates as version strings; 2024-11-05 is widely supported
		ProtocolVersion: "2024-11-05",
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		ServerInfo: ServerInfo{
			Name:    "pelican-mcp-server",
			Version: "1.0.0",
		},
	}

	log.Infof("Sending initialize response with protocol version: %s", result.ProtocolVersion)
	return s.sendResponse(req.ID, result)
}

// handleListTools handles the tools/list request
func (s *Server) handleListTools(req *JSONRPCRequest) error {
	result := ListToolsResult{Tools: getToolsList()}
	return s.sendResponse(req.ID, result)
}

// handleCallTool handles the tools/call request
func (s *Server) handleCallTool(req *JSONRPCRequest) error {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.sendError(req.ID, -32602, "Invalid params", err.Error())
	}

	log.Infof("Calling tool: %s with arguments: %v", params.Name, params.Arguments)

	var result CallToolResult

	switch params.Name {
	case "pelican_download":
		result = s.handleDownload(params.Arguments)
	case "pelican_stat":
		result = s.handleStat(params.Arguments)
	case "pelican_list":
		result = s.handleList(params.Arguments)
	case "pelican_auth":
		result = s.handleAuth(params.Arguments)
	case "pelican_auth_complete":
		result = s.handleAuthComplete(params.Arguments)
	default:
		return s.sendError(req.ID, -32602, "Unknown tool", params.Name)
	}

	return s.sendResponse(req.ID, result)
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(id interface{}, result interface{}) error {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("Error marshaling response: %v", err)
		return fmt.Errorf("error marshaling response: %w", err)
	}

	data = append(data, '\n')
	n, err := s.writer.Write(data)
	if err != nil {
		log.Errorf("Error writing response: %v", err)
		return fmt.Errorf("error writing response: %w", err)
	}

	if n != len(data) {
		log.Errorf("Incomplete write: wrote %d of %d bytes", n, len(data))
		return fmt.Errorf("incomplete write: wrote %d of %d bytes", n, len(data))
	}

	// Flush if the writer supports it (e.g., bufio.Writer)
	if flusher, ok := s.writer.(Flusher); ok {
		if err := flusher.Flush(); err != nil {
			log.Errorf("Error flushing response: %v", err)
			return fmt.Errorf("error flushing response: %w", err)
		}
	}

	log.Infof("Sent response for ID: %v (%d bytes)", id, len(data))
	return nil
}

// sendError sends a JSON-RPC error response
func (s *Server) sendError(id interface{}, code int, message string, data interface{}) error {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("Error marshaling error response: %v", err)
		return fmt.Errorf("error marshaling error response: %w", err)
	}

	respData = append(respData, '\n')
	n, err := s.writer.Write(respData)
	if err != nil {
		log.Errorf("Error writing error response: %v", err)
		return fmt.Errorf("error writing error response: %w", err)
	}

	if n != len(respData) {
		log.Errorf("Incomplete write: wrote %d of %d bytes", n, len(respData))
		return fmt.Errorf("incomplete write: wrote %d of %d bytes", n, len(respData))
	}

	// Flush if the writer supports it
	if flusher, ok := s.writer.(Flusher); ok {
		if err := flusher.Flush(); err != nil {
			log.Errorf("Error flushing error response: %v", err)
			return fmt.Errorf("error flushing error response: %w", err)
		}
	}

	log.Infof("Sent error response for ID: %v (code: %d, message: %s)", id, code, message)
	return nil
}
