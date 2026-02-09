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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// PTYAuthClient handles interactive keyboard-interactive authentication via PTY
type PTYAuthClient struct {
	// wsURL is the WebSocket URL to connect to
	wsURL string

	// conn is the WebSocket connection
	conn *websocket.Conn

	// stdin is the input reader (usually os.Stdin)
	stdin io.Reader

	// stdout is the output writer (usually os.Stdout)
	stdout io.Writer

	// stderr is the error writer (usually os.Stderr)
	stderr io.Writer

	// termFd is the file descriptor for the terminal (for password masking)
	termFd int

	// isTerminal indicates if stdin is a terminal
	isTerminal bool
}

// NewPTYAuthClient creates a new PTY-based authentication client
func NewPTYAuthClient(wsURL string) *PTYAuthClient {
	fd := int(os.Stdin.Fd())
	return &PTYAuthClient{
		wsURL:      wsURL,
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		termFd:     fd,
		isTerminal: term.IsTerminal(fd),
	}
}

// Connect connects to the WebSocket server
func (c *PTYAuthClient) Connect(ctx context.Context) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	// Parse the URL to add scheme if needed
	wsURL := c.wsURL
	if !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
		// Try to construct from HTTP URL
		if strings.HasPrefix(wsURL, "http://") {
			wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
		} else if strings.HasPrefix(wsURL, "https://") {
			wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
		} else {
			wsURL = "wss://" + wsURL
		}
	}

	// Parse and validate URL
	u, err := url.Parse(wsURL)
	if err != nil {
		return errors.Wrap(err, "invalid WebSocket URL")
	}

	// Ensure path is set
	if u.Path == "" {
		u.Path = "/api/v1.0/origin/ssh/auth"
	}

	log.Infof("Connecting to WebSocket: %s", u.String())

	conn, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			return errors.Wrapf(err, "WebSocket dial failed (status %d)", resp.StatusCode)
		}
		return errors.Wrap(err, "WebSocket dial failed")
	}

	c.conn = conn
	return nil
}

// Close closes the WebSocket connection
func (c *PTYAuthClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Run runs the interactive authentication session
func (c *PTYAuthClient) Run(ctx context.Context) error {
	if c.conn == nil {
		return errors.New("not connected")
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Set up ping/pong for keepalive
	c.conn.SetPongHandler(func(appData string) error {
		return nil
	})

	// Start ping goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	fmt.Fprintln(c.stdout, "Connected to SSH authentication WebSocket.")
	fmt.Fprintln(c.stdout, "Waiting for keyboard-interactive challenge...")
	fmt.Fprintln(c.stdout, "")

	// Main loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig := <-sigCh:
			fmt.Fprintf(c.stderr, "\nReceived %v, disconnecting...\n", sig)
			return nil
		default:
		}

		// Set read deadline
		if err := c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			log.Warnf("Failed to set read deadline: %v", err)
		}

		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				fmt.Fprintln(c.stdout, "Connection closed by server.")
				return nil
			}
			if err, ok := err.(*websocket.CloseError); ok {
				return errors.Wrapf(err, "WebSocket closed: %d", err.Code)
			}
			// Timeout - continue waiting
			continue
		}

		// Parse the message
		var msg WebSocketMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Warnf("Failed to parse WebSocket message: %v", err)
			continue
		}

		switch msg.Type {
		case WsMsgTypeChallenge:
			if err := c.handleChallenge(msg.Payload); err != nil {
				return errors.Wrap(err, "failed to handle challenge")
			}

		case WsMsgTypeStatus:
			var status map[string]interface{}
			if err := json.Unmarshal(msg.Payload, &status); err == nil {
				fmt.Fprintf(c.stdout, "Status: %v\n", status)
			}

		case WsMsgTypeError:
			var errMsg map[string]string
			if err := json.Unmarshal(msg.Payload, &errMsg); err == nil {
				fmt.Fprintf(c.stderr, "Error from server: %s\n", errMsg["error"])
			}

		case WsMsgTypePong:
			// Ignore pong responses

		default:
			log.Debugf("Unknown message type: %s", msg.Type)
		}
	}
}

// handleChallenge handles a keyboard-interactive challenge
func (c *PTYAuthClient) handleChallenge(payload json.RawMessage) error {
	var challenge KeyboardInteractiveChallenge
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return errors.Wrap(err, "failed to parse challenge")
	}

	fmt.Fprintln(c.stdout, "")
	fmt.Fprintln(c.stdout, "=== SSH Authentication ===")
	if challenge.Instruction != "" {
		fmt.Fprintln(c.stdout, challenge.Instruction)
		fmt.Fprintln(c.stdout, "")
	}

	// Collect answers
	answers := make([]string, len(challenge.Questions))
	reader := bufio.NewReader(c.stdin)

	for i, question := range challenge.Questions {
		fmt.Fprint(c.stdout, question.Prompt)

		var answer string
		var err error

		if question.Echo {
			// Echo is enabled - read normally
			answer, err = reader.ReadString('\n')
			if err != nil {
				return errors.Wrap(err, "failed to read input")
			}
			answer = strings.TrimSpace(answer)
		} else {
			// Echo is disabled - read password securely
			if c.isTerminal {
				passwordBytes, err := term.ReadPassword(c.termFd)
				if err != nil {
					return errors.Wrap(err, "failed to read password")
				}
				answer = string(passwordBytes)
				fmt.Fprintln(c.stdout, "") // Print newline after hidden input
			} else {
				// Not a terminal - just read the line
				answer, err = reader.ReadString('\n')
				if err != nil {
					return errors.Wrap(err, "failed to read input")
				}
				answer = strings.TrimSpace(answer)
			}
		}

		answers[i] = answer
	}

	// Send response
	response := KeyboardInteractiveResponse{
		SessionID: challenge.SessionID,
		Answers:   answers,
	}

	responsePayload, err := json.Marshal(response)
	if err != nil {
		return errors.Wrap(err, "failed to marshal response")
	}

	msg := WebSocketMessage{
		Type:    WsMsgTypeResponse,
		Payload: responsePayload,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "failed to marshal message")
	}

	if err := c.conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		return errors.Wrap(err, "failed to send response")
	}

	fmt.Fprintln(c.stdout, "Response sent.")
	return nil
}

// RunInteractiveAuth starts an interactive authentication session
// This is the main entry point for the CLI command
func RunInteractiveAuth(ctx context.Context, originURL string, host string) error {
	// Build the WebSocket URL
	wsURL := originURL
	if !strings.HasSuffix(wsURL, "/") {
		wsURL += "/"
	}
	wsURL += "api/v1.0/origin/ssh/auth"

	// Add host parameter if specified
	if host != "" {
		wsURL += "?host=" + url.QueryEscape(host)
	}

	client := NewPTYAuthClient(wsURL)

	if err := client.Connect(ctx); err != nil {
		return err
	}
	defer client.Close()

	return client.Run(ctx)
}

// GetConnectionStatus retrieves the current SSH connection status from an origin
func GetConnectionStatus(ctx context.Context, originURL string) (map[string]interface{}, error) {
	// Build the status URL
	statusURL := originURL
	if !strings.HasSuffix(statusURL, "/") {
		statusURL += "/"
	}
	statusURL += "api/v1.0/origin/ssh/status"

	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return result, nil
}
