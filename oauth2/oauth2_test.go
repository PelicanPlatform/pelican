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

package oauth2

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

// verificationCall records one invocation of a VerificationURLHandler.
type verificationCall struct {
	verificationURL string
	userCode        string
}

// verificationRecorder is a VerificationURLHandler that remembers what it was
// given.
type verificationRecorder struct {
	calls []verificationCall
}

func (recorder *verificationRecorder) handle(verificationURL, userCode string) {
	recorder.calls = append(recorder.calls, verificationCall{verificationURL, userCode})
}

// captureVerificationURLs installs a recorder as the handler and removes it
// again when the test ends, so that the process-wide handler does not leak into
// the next test.
func captureVerificationURLs(t *testing.T) *verificationRecorder {
	t.Helper()
	recorder := &verificationRecorder{}
	SetVerificationURLHandler(recorder.handle)
	t.Cleanup(func() {
		SetVerificationURLHandler(nil)
	})
	return recorder
}

func TestAnnounceVerification(t *testing.T) {
	t.Run("complete-uri-is-printed-alone", func(t *testing.T) {
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://issuer.example.com/device",
			VerificationURIComplete: "https://issuer.example.com/device?user_code=ABCD-EFGH",
		})
		assert.Contains(t, out.String(), "https://issuer.example.com/device?user_code=ABCD-EFGH")
		// The complete URI carries the code, so the user is not asked to type it.
		assert.NotContains(t, out.String(), "enter the following code")
	})

	t.Run("uri-and-code-are-printed-when-no-complete-uri", func(t *testing.T) {
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:        "ABCD-EFGH",
			VerificationURI: "https://issuer.example.com/device",
		})
		// Regression: this branch used to print VerificationURIComplete, which
		// is by definition empty here, so the user was told to navigate to a
		// blank line and then handed a code with nowhere to type it.
		assert.Contains(t, out.String(), "https://issuer.example.com/device")
		assert.Contains(t, out.String(), "enter the following code")
		assert.Contains(t, out.String(), "ABCD-EFGH")
	})
}

func TestVerificationURLHandler(t *testing.T) {
	t.Run("no-handler-installed-is-a-no-op", func(t *testing.T) {
		SetVerificationURLHandler(nil)
		out := &strings.Builder{}
		// The point is that this neither panics nor suppresses the output a
		// user with no embedder relies on.
		announceVerification(out, &DeviceAuth{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://issuer.example.com/device",
			VerificationURIComplete: "https://issuer.example.com/device?user_code=ABCD-EFGH",
		})
		assert.Contains(t, out.String(), "https://issuer.example.com/device?user_code=ABCD-EFGH")
	})

	t.Run("handler-gets-the-complete-uri-and-no-code", func(t *testing.T) {
		recorder := captureVerificationURLs(t)
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://issuer.example.com/device",
			VerificationURIComplete: "https://issuer.example.com/device?user_code=ABCD-EFGH",
		})
		require.Len(t, recorder.calls, 1)
		// The complete URI already carries the code, so there is nothing for
		// the embedder to show alongside it.
		assert.Equal(t, "https://issuer.example.com/device?user_code=ABCD-EFGH", recorder.calls[0].verificationURL)
		assert.Empty(t, recorder.calls[0].userCode)
		// The handler REPLACES the terminal announcement: an embedder that
		// has somewhere better to put the URL does not also get it sprayed
		// across a terminal nobody is watching.
		assert.Empty(t, out.String(), "nothing should be printed while a handler is installed")
	})

	t.Run("handler-gets-the-uri-and-the-code", func(t *testing.T) {
		recorder := captureVerificationURLs(t)
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:        "ABCD-EFGH",
			VerificationURI: "https://issuer.example.com/device",
		})
		require.Len(t, recorder.calls, 1)
		assert.Equal(t, "https://issuer.example.com/device", recorder.calls[0].verificationURL)
		assert.Equal(t, "ABCD-EFGH", recorder.calls[0].userCode)
		assert.Empty(t, out.String(), "nothing should be printed while a handler is installed")
	})

	t.Run("handler-can-be-replaced-and-removed", func(t *testing.T) {
		first := captureVerificationURLs(t)

		second := &verificationRecorder{}
		SetVerificationURLHandler(second.handle)
		announceVerification(&strings.Builder{}, &DeviceAuth{VerificationURIComplete: "https://issuer.example.com/one"})
		assert.Empty(t, first.calls, "the replaced handler should no longer be called")
		require.Len(t, second.calls, 1)

		SetVerificationURLHandler(nil)
		announceVerification(&strings.Builder{}, &DeviceAuth{VerificationURIComplete: "https://issuer.example.com/two"})
		assert.Len(t, second.calls, 1, "a removed handler should no longer be called")
	})

	t.Run("handler-is-not-called-without-a-url", func(t *testing.T) {
		recorder := captureVerificationURLs(t)
		// An issuer response naming neither URI is malformed, but it should
		// not send an embedder off to open the empty string.
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{UserCode: "ABCD-EFGH"})
		assert.Empty(t, recorder.calls)
		// With no URL there is nothing to hand over, so the printed output
		// stays as the only record that a flow was attempted -- the one case
		// where an installed handler does not suppress it.
		assert.Contains(t, out.String(), "To approve credentials")
	})
}

func TestVerificationTargetAvailable(t *testing.T) {
	skipVar := config.GetPreferredPrefix().String() + "_SKIP_TERMINAL_CHECK"

	stdoutIsTerminal := func(t *testing.T) bool {
		t.Helper()
		fileInfo, err := os.Stdout.Stat()
		return err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0
	}

	t.Run("no-terminal-no-handler-no-escape-is-refused", func(t *testing.T) {
		if stdoutIsTerminal(t) {
			t.Skip("stdout is a terminal here, so the case under test cannot arise")
		}
		t.Setenv(skipVar, "")
		SetVerificationURLHandler(nil)
		assert.False(t, verificationTargetAvailable())
	})

	t.Run("a-handler-is-a-target-without-a-terminal", func(t *testing.T) {
		if stdoutIsTerminal(t) {
			t.Skip("stdout is a terminal here, so this proves nothing about the handler")
		}
		t.Setenv(skipVar, "")
		captureVerificationURLs(t)
		// This is the whole point of the change: an embedder showing the URL
		// on a page has somewhere to put it, and no terminal.
		assert.True(t, verificationTargetAvailable())
	})

	t.Run("the-escape-hatch-still-works", func(t *testing.T) {
		t.Setenv(skipVar, "1")
		SetVerificationURLHandler(nil)
		assert.True(t, verificationTargetAvailable())
	})
}
