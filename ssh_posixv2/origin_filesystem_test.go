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
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
