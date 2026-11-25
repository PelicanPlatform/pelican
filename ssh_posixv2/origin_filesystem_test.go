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
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// helperFunc stands in for the transport to the helper: it answers each
// request the SSH filesystem sends with whatever the function returns.
type helperFunc func(*http.Request) (*http.Response, error)

func (f helperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// captureLogs collects everything logged at debug level or above until the
// test ends.
func captureLogs(t *testing.T) *logrustest.Hook {
	t.Helper()
	logger := log.StandardLogger()
	origLevel := logger.GetLevel()
	origHooks := logger.ReplaceHooks(make(log.LevelHooks))
	logger.SetLevel(log.DebugLevel)
	hook := logrustest.NewLocal(logger)
	t.Cleanup(func() {
		logger.ReplaceHooks(origHooks)
		logger.SetLevel(origLevel)
	})
	return hook
}

// messagesAt returns the messages the hook collected at the given level.
func messagesAt(hook *logrustest.Hook, level log.Level) []string {
	var msgs []string
	for _, entry := range hook.AllEntries() {
		if entry.Level == level {
			msgs = append(msgs, entry.Message)
		}
	}
	return msgs
}

// TestSSHFileReadLogsBrokenStream verifies what the origin logs when the
// helper's response ends before the object does.
func TestSSHFileReadLogsBrokenStream(t *testing.T) {
	// A helper that sends seven bytes of the object and then fails.
	brokenHelper := helperFunc(func(req *http.Request) (*http.Response, error) {
		body := io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(io.ErrUnexpectedEOF))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body), Request: req}, nil
	})

	t.Run("warns-with-object-and-offset", func(t *testing.T) {
		hook := captureLogs(t)
		fs := NewSSHFileSystem(brokenHelper, "/test", "/data")
		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		_, err = io.ReadAll(f)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)

		warnings := messagesAt(hook, log.WarnLevel)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "/object.bin")
		assert.Contains(t, warnings[0], "offset 7")
		assert.Contains(t, warnings[0], io.ErrUnexpectedEOF.Error())
	})

	t.Run("cancelled-request-is-not-a-warning", func(t *testing.T) {
		hook := captureLogs(t)
		ctx, cancel := context.WithCancel(context.Background())
		fs := NewSSHFileSystem(brokenHelper, "/test", "/data")
		f, err := fs.OpenFile(ctx, "/object.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		cancel()
		_, err = io.ReadAll(f)
		require.Error(t, err)

		assert.Empty(t, messagesAt(hook, log.WarnLevel))
		assert.Len(t, messagesAt(hook, log.DebugLevel), 1)
	})

	t.Run("complete-object-logs-nothing", func(t *testing.T) {
		hook := captureLogs(t)
		fs := NewSSHFileSystem(helperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("complete")), Request: req}, nil
		}), "/test", "/data")
		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		body, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.Equal(t, "complete", string(body))
		assert.Empty(t, hook.AllEntries())
	})
}

// sshFSOverPipe returns an SSH filesystem whose requests are answered by
// handler, running in the helper's HTTP server.  Each request travels over
// its own in-memory connection, as it does on the real transports.  It must
// be called inside a synctest bubble.
func sshFSOverPipe(t *testing.T, handler http.Handler, stallTimeout time.Duration) *SSHFileSystem {
	t.Helper()
	fs := NewSSHFileSystem(helperFunc(func(req *http.Request) (*http.Response, error) {
		conn := serveHelperOnPipe(t, handler)
		return newSingleUseClient(conn, 0).Transport.RoundTrip(req)
	}), "/test", "/data")
	fs.stallTimeout = stallTimeout
	return fs
}

// TestSSHFileReadAbandonsStalledHelper verifies that a download is given up
// once the helper has sent nothing for the stall timeout, and that the
// helper's request is released when that happens.
func TestSSHFileReadAbandonsStalledHelper(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const stallTimeout = 100 * time.Second
		const firstPart = "first part"
		hook := captureLogs(t)

		// A helper that sends the start of the object and then goes silent
		// with the request still open.
		helperDone := make(chan struct{})
		fs := sshFSOverPipe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(helperDone)
			_, _ = io.WriteString(w, firstPart)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}), stallTimeout)

		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		buf := make([]byte, len(firstPart))
		_, err = io.ReadFull(f, buf)
		require.NoError(t, err)
		assert.Equal(t, firstPart, string(buf))

		start := time.Now()
		_, err = f.Read(buf)
		var stalled *helperStalledError
		require.ErrorAs(t, err, &stalled)
		assert.Equal(t, stallTimeout, time.Since(start))

		<-helperDone

		warnings := messagesAt(hook, log.WarnLevel)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "/object.bin")
		assert.Contains(t, warnings[0], "Client.StoppedTransferTimeout")
	})
}

// TestSSHFileReadToleratesSlowCaller verifies that a download survives a
// caller that waits longer than the stall timeout between reads, as the
// origin does when its own client is slow.
func TestSSHFileReadToleratesSlowCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const stallTimeout = 100 * time.Second
		const pause = 150 * time.Second
		const chunks = 4
		chunk := bytes.Repeat([]byte("r"), 1024)

		fs := sshFSOverPipe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < chunks; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}), stallTimeout)

		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		start := time.Now()
		buf := make([]byte, len(chunk))
		for i := 0; i < chunks; i++ {
			<-time.After(pause)
			_, err = io.ReadFull(f, buf)
			require.NoError(t, err)
			assert.Equal(t, chunk, buf)
		}
		_, err = f.Read(buf)
		assert.ErrorIs(t, err, io.EOF)
		assert.GreaterOrEqual(t, time.Since(start), chunks*pause)
	})
}

// TestSSHFileWriteAbandonsStalledHelper verifies that an upload is given up
// once the helper has accepted nothing for the stall timeout.
func TestSSHFileWriteAbandonsStalledHelper(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const stallTimeout = 100 * time.Second
		chunk := bytes.Repeat([]byte("w"), 64*1024)

		// A helper that reads the start of the object and then hangs, as it
		// would in a write to storage that does not return.  Once the write
		// returns it goes back to the request body.
		storageHung := make(chan struct{})
		nextRead := make(chan error, 1)
		fs := sshFSOverPipe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.CopyN(io.Discard, r.Body, int64(len(chunk)))
			select {
			case <-storageHung:
			case <-t.Context().Done():
			}
			_, err := r.Body.Read(make([]byte, 1))
			nextRead <- err
		}), stallTimeout)

		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		require.NoError(t, err)

		_, err = f.Write(chunk)
		require.NoError(t, err)

		// The helper takes nothing more, so within a few chunks a write
		// can make no progress.
		start := time.Now()
		for i := 0; i < 16 && err == nil; i++ {
			_, err = f.Write(chunk)
		}
		var stalled *helperStalledError
		require.ErrorAs(t, err, &stalled)
		assert.Equal(t, stallTimeout, time.Since(start))

		assert.ErrorAs(t, f.Close(), &stalled)

		// The helper finds the request gone as soon as its write returns.
		close(storageHung)
		assert.Error(t, <-nextRead)
	})
}

// TestSSHFileWriteToleratesSlowCaller verifies that an upload survives a
// caller that waits longer than the stall timeout between writes.
func TestSSHFileWriteToleratesSlowCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const stallTimeout = 100 * time.Second
		const pause = 150 * time.Second
		const chunks = 4
		chunk := bytes.Repeat([]byte("w"), 1024)

		received := make(chan int64, 1)
		fs := sshFSOverPipe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			received <- n
			w.WriteHeader(http.StatusCreated)
		}), stallTimeout)

		f, err := fs.OpenFile(context.Background(), "/object.bin", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		require.NoError(t, err)

		start := time.Now()
		for i := 0; i < chunks; i++ {
			<-time.After(pause)
			_, err = f.Write(chunk)
			require.NoError(t, err)
		}
		require.NoError(t, f.Close())
		assert.Equal(t, int64(chunks*len(chunk)), <-received)
		assert.GreaterOrEqual(t, time.Since(start), chunks*pause)
	})
}

// TestHelperTimeoutsFollowConfig verifies which parameters set the limits
// the origin applies to the helper.
func TestHelperTimeoutsFollowConfig(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Transport_ResponseHeaderTimeout.Set(7*time.Second))
	require.NoError(t, param.Client_StoppedTransferTimeout.Set(42*time.Second))

	assert.Equal(t, 7*time.Second, NewHelperTransport(nil).responseHeaderTimeout)
	assert.Equal(t, 7*time.Second, NewSSHTunnelTransport("cookie").responseHeaderTimeout)
	assert.Equal(t, 42*time.Second, NewSSHFileSystem(nil, "/test", "/data").stallTimeout)
}
