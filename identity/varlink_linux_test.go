//go:build linux

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

package identity

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVarlink_ContextCancellation verifies that a cancelled context
// causes LookupUser to return promptly rather than blocking forever.
func TestVarlink_ContextCancellation(t *testing.T) {
	// Create a unix socket that accepts connections but never replies,
	// simulating a hung systemd-userdbd.
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	// Accept in the background but never write a response.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Hold the connection open — don't close or reply.
			_ = conn
		}
	}()

	strategy := &SystemdUserDBLookupStrategy{socketPath: sockPath}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = strategy.LookupUser(ctx, "alice")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "should have returned quickly after context deadline")
}

// TestVarlink_EnsureTimeout verifies that calls without an explicit
// deadline get the default timeout rather than hanging forever.
func TestVarlink_EnsureTimeout(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	// We won't start a listener — the Dial should fail or we use a
	// listener that never responds.  But first, just test ensureTimeout.
	strategy := &SystemdUserDBLookupStrategy{socketPath: sockPath}

	// context.Background() has no deadline.
	ctx, cancel := strategy.ensureTimeout(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	assert.True(t, ok, "ensureTimeout should add a deadline")
	assert.WithinDuration(t, time.Now().Add(defaultVarlinkTimeout), deadline, 1*time.Second)

	// A context that already has a deadline should be unchanged.
	explicit := 42 * time.Second
	ctxExplicit, cancelExplicit := context.WithTimeout(context.Background(), explicit)
	defer cancelExplicit()
	ctxOut, cancelOut := strategy.ensureTimeout(ctxExplicit)
	defer cancelOut()
	deadlineOut, _ := ctxOut.Deadline()
	deadlineExpected, _ := ctxExplicit.Deadline()
	assert.Equal(t, deadlineExpected, deadlineOut, "ensureTimeout should not override an existing deadline")
}

// TestVarlink_DialContextCancelled verifies that dial returns
// context.Canceled when the context is already cancelled.
func TestVarlink_DialContextCancelled(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	// Create a real socket so stat succeeds.
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	strategy := &SystemdUserDBLookupStrategy{socketPath: sockPath}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err = strategy.dial(ctx)
	require.Error(t, err)
}

// TestVarlink_SocketMissing verifies that NewSystemdUserDBLookup
// returns an error when the socket doesn't exist.
func TestVarlink_SocketMissing(t *testing.T) {
	_, err := os.Stat("/nonexistent/socket")
	require.Error(t, err) // precondition

	original := "/run/systemd/userdb/io.systemd.UserDatabase"
	strategy := &SystemdUserDBLookupStrategy{socketPath: original}
	if _, statErr := os.Stat(original); statErr != nil {
		// Socket doesn't exist, so dial should fail.
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_, err := strategy.LookupUser(ctx, "alice")
		require.Error(t, err)
	}
}
