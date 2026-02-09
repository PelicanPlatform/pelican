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
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	// upgrader is the WebSocket upgrader
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Allow connections from any origin - admin authentication should be handled separately
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// activeWebSockets tracks active WebSocket connections per host
	activeWebSockets   = make(map[string]*websocket.Conn)
	activeWebSocketsMu sync.RWMutex
)

// WebSocketMessage represents a message sent over the WebSocket
type WebSocketMessage struct {
	// Type is the message type
	Type string `json:"type"`

	// Payload contains the message data
	Payload json.RawMessage `json:"payload"`
}

// WebSocketMessageType constants
const (
	WsMsgTypeChallenge = "challenge"
	WsMsgTypeResponse  = "response"
	WsMsgTypeStatus    = "status"
	WsMsgTypeError     = "error"
	WsMsgTypePing      = "ping"
	WsMsgTypePong      = "pong"
)

// RegisterWebSocketHandler registers the WebSocket endpoint for keyboard-interactive auth
func RegisterWebSocketHandler(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) {
	// The websocket is under /api/v1.0/origin/ssh/auth for admin access
	router.GET("/api/v1.0/origin/ssh/auth", handleWebSocket(ctx))
	router.GET("/api/v1.0/origin/ssh/status", handleSSHStatus(ctx))

	// Register the helper broker endpoints for reverse connections
	RegisterHelperBrokerHandlers(router, ctx)
}

// handleWebSocket handles the WebSocket connection for keyboard-interactive authentication
func handleWebSocket(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the host from query parameter
		host := c.Query("host")
		if host == "" {
			// Try to get from the global backend
			backend := GetBackend()
			if backend != nil {
				conns := backend.GetAllConnections()
				for h := range conns {
					host = h
					break
				}
			}
		}

		if host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no SSH connection available"})
			return
		}

		// Get the connection for this host
		backend := GetBackend()
		if backend == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "SSH backend not initialized"})
			return
		}

		conn := backend.GetConnection(host)
		if conn == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no connection for host: " + host})
			return
		}

		// Upgrade the HTTP connection to a WebSocket
		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Errorf("Failed to upgrade to WebSocket: %v", err)
			return
		}
		defer ws.Close()

		// Register this WebSocket connection
		activeWebSocketsMu.Lock()
		if existing, ok := activeWebSockets[host]; ok {
			existing.Close()
		}
		activeWebSockets[host] = ws
		activeWebSocketsMu.Unlock()

		defer func() {
			activeWebSocketsMu.Lock()
			delete(activeWebSockets, host)
			activeWebSocketsMu.Unlock()
		}()

		log.Infof("WebSocket connection established for SSH auth to %s", host)

		// Handle the WebSocket connection
		handleWebSocketConnection(ctx, ws, conn)
	}
}

// handleWebSocketConnection handles messages on the WebSocket connection
func handleWebSocketConnection(ctx context.Context, ws *websocket.Conn, conn *SSHConnection) {
	// Start goroutines for reading and writing
	done := make(chan struct{})

	// Goroutine to read messages from WebSocket
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_, message, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Errorf("WebSocket read error: %v", err)
				}
				return
			}

			// Parse the message
			var msg WebSocketMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Warnf("Failed to parse WebSocket message: %v", err)
				sendWebSocketError(ws, "invalid message format")
				continue
			}

			// Handle the message based on type
			switch msg.Type {
			case WsMsgTypeResponse:
				// Parse the response payload
				var response KeyboardInteractiveResponse
				if err := json.Unmarshal(msg.Payload, &response); err != nil {
					log.Warnf("Failed to parse keyboard-interactive response: %v", err)
					sendWebSocketError(ws, "invalid response format")
					continue
				}

				// Send the response to the SSH connection
				select {
				case conn.GetResponseChannel() <- response:
					log.Debug("Forwarded keyboard-interactive response")
				case <-time.After(5 * time.Second):
					log.Warn("Timeout sending keyboard-interactive response")
					sendWebSocketError(ws, "timeout sending response")
				}

			case WsMsgTypePing:
				// Respond with pong
				if err := sendWebSocketMessage(ws, WsMsgTypePong, nil); err != nil {
					log.Warnf("Failed to send pong: %v", err)
				}

			default:
				log.Warnf("Unknown WebSocket message type: %s", msg.Type)
			}
		}
	}()

	// Goroutine to forward challenges to WebSocket
	challengeChan := conn.GetKeyboardChannel()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case challenge := <-challengeChan:
			// Forward the challenge to the WebSocket
			if err := sendWebSocketMessage(ws, WsMsgTypeChallenge, challenge); err != nil {
				log.Errorf("Failed to send challenge to WebSocket: %v", err)
				return
			}
			log.Debug("Sent keyboard-interactive challenge to WebSocket")
		}
	}
}

// sendWebSocketMessage sends a message on the WebSocket
func sendWebSocketMessage(ws *websocket.Conn, msgType string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "failed to marshal payload")
	}

	msg := WebSocketMessage{
		Type:    msgType,
		Payload: payloadBytes,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "failed to marshal message")
	}

	return ws.WriteMessage(websocket.TextMessage, msgBytes)
}

// sendWebSocketError sends an error message on the WebSocket
func sendWebSocketError(ws *websocket.Conn, errorMsg string) {
	err := sendWebSocketMessage(ws, WsMsgTypeError, map[string]string{"error": errorMsg})
	if err != nil {
		log.Warnf("Failed to send WebSocket error: %v", err)
	}
}

// handleSSHStatus returns the current SSH connection status
func handleSSHStatus(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		backend := GetBackend()
		if backend == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not_initialized",
			})
			return
		}

		connections := backend.GetAllConnections()
		status := make(map[string]interface{})

		for host, conn := range connections {
			status[host] = conn.GetConnectionInfo()
		}

		c.JSON(http.StatusOK, gin.H{
			"connections": status,
		})
	}
}

// BroadcastChallenge broadcasts a challenge to all connected WebSocket clients for a host
func BroadcastChallenge(host string, challenge KeyboardInteractiveChallenge) error {
	activeWebSocketsMu.RLock()
	ws, ok := activeWebSockets[host]
	activeWebSocketsMu.RUnlock()

	if !ok {
		return errors.New("no WebSocket connection for host: " + host)
	}

	return sendWebSocketMessage(ws, WsMsgTypeChallenge, challenge)
}

// HasActiveWebSocket checks if there's an active WebSocket for keyboard-interactive auth
func HasActiveWebSocket(host string) bool {
	activeWebSocketsMu.RLock()
	defer activeWebSocketsMu.RUnlock()
	_, ok := activeWebSockets[host]
	return ok
}

// CloseWebSocket closes the WebSocket for a host
func CloseWebSocket(host string) {
	activeWebSocketsMu.Lock()
	defer activeWebSocketsMu.Unlock()

	if ws, ok := activeWebSockets[host]; ok {
		ws.Close()
		delete(activeWebSockets, host)
	}
}
