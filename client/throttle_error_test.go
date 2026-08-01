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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// shedReasonTypes is the contract between the scheduler's shed reasons (the
// "error" field a cache writes into its 429 JSON body) and the Pelican error
// type the client classifies each into. It is deliberately keyed on the
// ShedReason constants rather than fresh string literals: if a constant's
// value is renamed on the producer side, these tests fail instead of the
// client silently degrading every shed to the generic fallback.
//
// If a new ShedReason constant is added, it must be added here (and to
// throttleErrorForReason / parseThrottleReason) as well.
var shedReasonTypes = map[ShedReason]string{
	ShedOriginUnresponsive: "Transfer.OriginUnresponsive",
	ShedOriginSlow:         "Transfer.OriginSlow",
	ShedCacheOverloaded:    "Transfer.CacheOverloaded",
}

// wrapErrorByStatusCode maps HTTP 429 to a retryable Pelican error rather than
// to the generic Specification bucket the other 4xx codes land in. A shed says
// "come back later", so classifying it as a fatal client error would make the
// caller give up on a server that was merely busy.
func TestWrapStatusCode429IsRetryable(t *testing.T) {
	wrapped := wrapErrorByStatusCode(http.StatusTooManyRequests, errors.New("shed"))
	var pe *error_codes.PelicanError
	require.ErrorAs(t, wrapped, &pe)
	assert.True(t, pe.IsRetryable(), "429 must be retryable")
	assert.True(t, IsRetryable(wrapped), "IsRetryable must report 429 as retryable")
}

// Every declared ShedReason must map to its own specific retryable error
// type; unknown or empty reasons fall back to cache-overloaded.
func TestThrottleErrorForReason(t *testing.T) {
	for reason, errType := range shedReasonTypes {
		t.Run(string(reason), func(t *testing.T) {
			err := throttleErrorForReason(string(reason), errors.New("x"))
			var pe *error_codes.PelicanError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, errType, pe.ErrorType())
			assert.True(t, pe.IsRetryable())
		})
	}
	for _, reason := range []string{"", "garbage"} {
		t.Run("fallback/"+reason, func(t *testing.T) {
			err := throttleErrorForReason(reason, errors.New("x"))
			var pe *error_codes.PelicanError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, "Transfer.CacheOverloaded", pe.ErrorType())
			assert.True(t, pe.IsRetryable())
		})
	}
}

func TestParseThrottleReason(t *testing.T) {
	// Round-trip every ShedReason constant through the same JSON shape the
	// cache's handleError writes; this welds the producer constants to the
	// consumer's parser.
	for reason := range shedReasonTypes {
		body, err := json.Marshal(map[string]string{"error": string(reason), "detail": "..."})
		require.NoError(t, err)
		assert.Equal(t, string(reason), parseThrottleReason(string(body)))
	}
	// Anything that is not a known reason is rejected: the body comes from
	// a remote peer, and an arbitrary string must not flow into logs or
	// error messages.
	assert.Equal(t, "", parseThrottleReason(""))
	assert.Equal(t, "", parseThrottleReason("not json"))
	assert.Equal(t, "", parseThrottleReason(`{"other":"field"}`))
	assert.Equal(t, "", parseThrottleReason(`{"error":"made_up_reason"}`))
	assert.Equal(t, "", parseThrottleReason(`{"error":"origin_slow\nfake log line"}`))
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, 60*time.Second, parseRetryAfter("60"))
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-5"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("garbage"))
	// Values are clamped so a misbehaving server cannot push an absurd
	// backoff (or overflow the duration into a negative) downstream.
	assert.Equal(t, maxRetryAfter, parseRetryAfter("7200"))
	assert.Equal(t, maxRetryAfter, parseRetryAfter("9223372036854775807"))
	// HTTP-date form: a time in the future yields a positive duration; a
	// past date yields zero; a far-future date is clamped.
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	d := parseRetryAfter(future)
	assert.Greater(t, d, time.Duration(0))
	assert.LessOrEqual(t, d, 30*time.Second)
	past := time.Now().Add(-30 * time.Second).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), parseRetryAfter(past))
	farFuture := time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat)
	assert.Equal(t, maxRetryAfter, parseRetryAfter(farFuture))
}

// Server-provided detail strings are truncated at storage and quoted at
// display: control characters a hostile server embeds render as escapes
// (\n, \r) in the error message, so they cannot forge log records.
func TestThrottleDetailQuotedAndTruncated(t *testing.T) {
	err := newCacheThrottleError(string(ShedOriginSlow), "line one\nFAKE-LOG-LINE", "cache.example.org:8443", 0)
	msg := err.Error()
	assert.NotContains(t, msg, "\n", "raw newlines must not survive into the error message")
	assert.Contains(t, msg, `line one\nFAKE-LOG-LINE`, "detail must be rendered with escapes, not dropped")

	long := strings.Repeat("x", 2048)
	assert.LessOrEqual(t, len(truncateErrorDetail(long)), 512+len("…"))
	assert.True(t, strings.HasSuffix(truncateErrorDetail(long), "…"))
}

// A CacheThrottleError built from a cache's 429 wraps the specific retryable
// Pelican error and matches ErrTooManyRequests, so a remote shed satisfies
// the same errors.Is check as a shed by this process's own scheduler, and
// IsRetryable/ShouldRetry hold; it carries the reason + backoff hint.
func TestCacheThrottleErrorIsRetryable(t *testing.T) {
	err := newCacheThrottleError(string(ShedOriginUnresponsive), "origin is over its share", "cache.example.org:8443", 60*time.Second)
	assert.Equal(t, string(ShedOriginUnresponsive), err.Reason)
	assert.Equal(t, 60*time.Second, err.RetryAfter)
	assert.Equal(t, "cache.example.org:8443", err.Endpoint)

	var pe *error_codes.PelicanError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "Transfer.OriginUnresponsive", pe.ErrorType())
	assert.True(t, IsRetryable(err), "a cache throttle must be retryable")
	assert.True(t, ShouldRetry(err), "ShouldRetry must honor a cache throttle")
	assert.True(t, errors.Is(err, ErrTooManyRequests),
		"a remote 429 must satisfy the same errors.Is check as a local scheduler shed")

	// Recoverable as a typed error so external retriers can read RetryAfter.
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, 60*time.Second, throttled.RetryAfter)
}

// wrapDownloadError must pass a CacheThrottleError through unmodified: the
// typed reason and Retry-After hint must survive to the caller even as other
// error kinds get rewrapped.
func TestWrapDownloadErrorPreservesThrottle(t *testing.T) {
	orig := newCacheThrottleError(string(ShedOriginSlow), "detail", "cache.example.org:8443", 60*time.Second)
	wrapped, _, _ := wrapDownloadError(orig, "https://cache.example.org:8443", "", "")
	var throttled *CacheThrottleError
	require.ErrorAs(t, wrapped, &throttled,
		"wrapDownloadError must not bury the CacheThrottleError type")
	assert.Equal(t, string(ShedOriginSlow), throttled.Reason)
	assert.Equal(t, 60*time.Second, throttled.RetryAfter)
	assert.True(t, ShouldRetry(wrapped))
}

// A 429 observed by the actual download path must come back as a typed,
// retryable CacheThrottleError carrying the parsed reason, the Retry-After
// hint, and the serving host.
func TestDownloadHTTP429(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[param.Param]any{})

	cases := []struct {
		name       string
		body       string
		retryAfter string
		wantReason string
		wantHint   time.Duration
		wantType   string
	}{
		{
			name:       "StructuredReason",
			body:       fmt.Sprintf(`{"error":%q,"detail":"origin is over its share"}`, string(ShedOriginUnresponsive)),
			retryAfter: "60",
			wantReason: string(ShedOriginUnresponsive),
			wantHint:   60 * time.Second,
			wantType:   "Transfer.OriginUnresponsive",
		},
		{
			name:       "EmptyBody",
			body:       "",
			retryAfter: "60",
			wantReason: "",
			wantHint:   60 * time.Second,
			wantType:   "Transfer.CacheOverloaded",
		},
		{
			name:       "GarbageBodyNoRetryAfter",
			body:       "<html>not json</html>",
			retryAfter: "",
			wantReason: "",
			wantHint:   0,
			wantType:   "Transfer.CacheOverloaded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, _ := test_utils.TestContext(context.Background(), t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)

			fname := filepath.Join(t.TempDir(), "test.txt")
			writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
			require.NoError(t, err)
			defer writer.Close()

			_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
				transferAttemptDetails{Url: serverURL, Proxy: false},
				fname, writer, 0, -1, -1, "", "", nil, nil)
			require.Error(t, err)

			var throttled *CacheThrottleError
			require.ErrorAs(t, err, &throttled, "429 must produce a CacheThrottleError")
			assert.Equal(t, tc.wantReason, throttled.Reason)
			assert.Equal(t, tc.wantHint, throttled.RetryAfter)
			assert.Equal(t, serverURL.Host, throttled.Endpoint)
			var pe *error_codes.PelicanError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, tc.wantType, pe.ErrorType())
			assert.True(t, ShouldRetry(err), "a throttled download must be retryable")
			assert.True(t, errors.Is(err, ErrTooManyRequests))
		})
	}
}

// A 429 on the upload (PUT) path must get the same typed classification as a
// download: reason parsed from the body, Retry-After hint carried, retryable.
func TestUploadObject429(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[param.Param]any{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Report the destination object as absent for the pre-upload stat.
		if r.Method == "PROPFIND" || r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Drain the PUT body before answering: otherwise the client-side
		// transport may still hold the upload file open when the test's
		// TempDir cleanup runs, which fails on Windows (open files cannot
		// be deleted there).
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"error":%q,"detail":"cache is saturated"}`, string(ShedCacheOverloaded))))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	localFile := filepath.Join(t.TempDir(), "upload.txt")
	require.NoError(t, os.WriteFile(localFile, []byte("upload me"), 0o644))

	transfer := &transferFile{
		ctx:       context.Background(),
		localPath: localFile,
		remoteURL: serverURL,
		xferType:  transferTypeUpload,
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test/upload.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					CollectionsUrl: serverURL,
				},
			},
		},
		attempts: []transferAttemptDetails{{Url: serverURL, Proxy: false}},
	}

	// uploadObject reports per-attempt failures via transferResult.Error (a
	// TransferErrors accumulator), not its error return; asserting through
	// it also proves the throttle type survives the accumulator's unwrap
	// chain — the same path the plugin's retryable-exit logic walks.
	transferResult, err := uploadObject(transfer)
	require.NoError(t, err)
	require.Error(t, transferResult.Error)
	var throttled *CacheThrottleError
	require.ErrorAs(t, transferResult.Error, &throttled, "a 429 on PUT must produce a CacheThrottleError")
	assert.Equal(t, string(ShedCacheOverloaded), throttled.Reason)
	assert.Equal(t, 60*time.Second, throttled.RetryAfter)
	assert.True(t, ShouldRetry(transferResult.Error), "a throttled upload must be retryable")
}

// TestParseRetryAfterSaturates pins the out-of-range path. A value too large
// for a 64-bit integer must still yield the clamp: parsing it as an error and
// falling through to the date parser would drop the hint entirely, so a server
// could suppress the backoff advice with a nonsense number rather than an
// absurd one.
func TestParseRetryAfterSaturates(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"BeyondInt64", "99999999999999999999", maxRetryAfter},
		{"FarBeyondInt64", "1" + strings.Repeat("0", 40), maxRetryAfter},
		{"NegativeBeyondInt64", "-99999999999999999999", 0},
		{"MaxInt64", "9223372036854775807", maxRetryAfter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseRetryAfter(tt.value))
		})
	}
}

// TestParseThrottleBodyDetail pins which text is kept as the human-readable
// detail. It is rendered into error messages, so a body that is not the shape
// the cache emits must not be silently dropped, and the reason must not be
// repeated as its own detail.
func TestParseThrottleBodyDetail(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
		wantDetail string
	}{
		{
			name:       "ReasonAndDetail",
			body:       `{"error":"origin_slow","detail":"origin already holds its share"}`,
			wantReason: "origin_slow",
			wantDetail: "origin already holds its share",
		},
		{
			// The reason is reported on its own, so echoing the raw body here
			// would just print it twice.
			name:       "ReasonWithoutDetail",
			body:       `{"error":"origin_slow"}`,
			wantReason: "origin_slow",
			wantDetail: "",
		},
		{
			// Not the shape we emit, but a person still needs to see it.
			name:       "NonJSONPassedThroughWhole",
			body:       "upstream proxy refused the connection",
			wantReason: "",
			wantDetail: "upstream proxy refused the connection",
		},
		{
			name:       "UnknownReasonKeepsDetail",
			body:       `{"error":"please_stop","detail":"go away"}`,
			wantReason: "",
			wantDetail: "go away",
		},
		{
			name:       "JSONWithNeitherField",
			body:       `{"something":"else"}`,
			wantReason: "",
			wantDetail: `{"something":"else"}`,
		},
		{"Empty", "   ", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, detail := parseThrottleBody(tt.body)
			assert.Equal(t, tt.wantReason, reason)
			assert.Equal(t, tt.wantDetail, detail)
		})
	}
}
