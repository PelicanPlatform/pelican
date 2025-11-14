/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

// Server implements the MCP server
type Server struct {
	reader      *bufio.Reader
	writer      io.Writer
	ctx         context.Context
	initialized bool
}

// NewServer creates a new MCP server
func NewServer(ctx context.Context, reader io.Reader, writer io.Writer) *Server {
	return &Server{
		reader: bufio.NewReader(reader),
		writer: writer,
		ctx:    ctx,
	}
}

// ensureInitialized initializes the Pelican client if not already done
func (s *Server) ensureInitialized() error {
	if !s.initialized {
		if err := config.InitClient(); err != nil {
			log.Errorf("Failed to initialize Pelican client: %v", err)
			return fmt.Errorf("failed to initialize Pelican client: %w", err)
		}
		s.initialized = true
		log.Info("Pelican client initialized")
	}
	return nil
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
			return fmt.Errorf("error reading request: %w", err)
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Errorf("Error parsing JSON-RPC request: %v", err)
			s.sendError(nil, -32700, "Parse error", nil)
			continue
		}

		log.Debugf("Received request: %s (ID: %v)", req.Method, req.ID)

		if err := s.handleRequest(&req); err != nil {
			log.Errorf("Error handling request: %v", err)
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

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		ServerInfo: ServerInfo{
			Name:    "pelican-mcp-server",
			Version: "1.0.0",
		},
	}

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
		return fmt.Errorf("error marshaling response: %w", err)
	}

	data = append(data, '\n')
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("error writing response: %w", err)
	}

	log.Debugf("Sent response for ID: %v", id)
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
		return fmt.Errorf("error marshaling error response: %w", err)
	}

	respData = append(respData, '\n')
	if _, err := s.writer.Write(respData); err != nil {
		return fmt.Errorf("error writing error response: %w", err)
	}

	log.Debugf("Sent error response for ID: %v", id)
	return nil
}
