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
	"net"
	"net/http"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// SSHTunnelTransport is an http.RoundTripper that reaches the helper
// process by opening SSH direct-streamlocal channels to a Unix domain
// socket on the remote host.  Each RoundTrip dials the helper's socket
// through the SSH connection, which provides encryption and avoids the
// complexity of reverse-connection brokering.
//
// The transport starts in a "not ready" state.  Callers will block in
// RoundTrip until SetReady is called (or the request context expires).
type SSHTunnelTransport struct {
	mu         sync.Mutex
	sshClient  *ssh.Client
	socketPath string // Unix socket path on the remote host
	authCookie string

	// readyCh is closed when the SSH client and socket path are set.
	readyCh chan struct{}
	once    sync.Once
}

// NewSSHTunnelTransport creates a tunnel transport.  It is initially not
// ready; call SetReady once the SSH connection is up and the helper has
// reported its listening socket.
func NewSSHTunnelTransport(authCookie string) *SSHTunnelTransport {
	return &SSHTunnelTransport{
		authCookie: authCookie,
		readyCh:    make(chan struct{}),
	}
}

// SetReady stores the SSH client and remote helper socket path and unblocks
// any in-flight RoundTrip calls.
func (t *SSHTunnelTransport) SetReady(client *ssh.Client, socketPath string) {
	t.mu.Lock()
	t.sshClient = client
	t.socketPath = socketPath
	t.mu.Unlock()
	t.once.Do(func() { close(t.readyCh) })
}

// IsReady returns true when the transport has an active SSH client and
// helper socket, meaning RoundTrip will not block.  This is a non-blocking
// check intended for fast-fail health gates.
func (t *SSHTunnelTransport) IsReady() bool {
	select {
	case <-t.readyCh:
		return true
	default:
		return false
	}
}

// SetNotReady resets the transport so that new RoundTrip calls block
// until SetReady is called again.  Used when the SSH connection is lost
// and the connection manager will re-establish a new one.
func (t *SSHTunnelTransport) SetNotReady() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sshClient = nil
	t.socketPath = ""
	t.readyCh = make(chan struct{})
	t.once = sync.Once{}
}

// RoundTrip implements http.RoundTripper.  It opens an SSH
// direct-streamlocal channel to the helper's Unix socket and sends the
// HTTP request over that channel.  The SSH connection provides encryption,
// so plain HTTP is used inside the channel.
func (t *SSHTunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Wait until the transport is ready (SSH connected, helper socket known).
	select {
	case <-t.readyCh:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}

	t.mu.Lock()
	client := t.sshClient
	sp := t.socketPath
	t.mu.Unlock()

	if client == nil {
		return nil, errors.New("SSH tunnel transport: SSH client is nil")
	}

	// Open an SSH direct-streamlocal channel to the helper's Unix socket.
	conn, err := client.Dial("unix", sp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial helper via SSH streamlocal channel")
	}

	// Build a single-use HTTP client over the SSH channel.
	singleUseTransport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
	}
	httpClient := &http.Client{
		Transport: singleUseTransport,
		// Do not follow redirects — each channel carries one exchange.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Clone the request for the helper (plain HTTP, auth injected).
	// The host is irrelevant since we use a pre-dialed connection,
	// but set something sensible for log clarity.
	helperReq := req.Clone(req.Context())
	helperReq.URL.Scheme = "http"
	helperReq.URL.Host = "ssh-helper"
	helperReq.Header.Set("Authorization", "Bearer "+t.authCookie)

	resp, err := httpClient.Do(helperReq)
	if err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "failed to send request to helper via SSH tunnel")
	}

	return resp, nil
}
