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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/error_codes"
)

// wrapErrorByStatusCode wraps an error based on HTTP status code using the same mapping as wrapStatusCodeError
func wrapErrorByStatusCode(code int, err error) error {
	switch {
	case code == http.StatusNotFound:
		return error_codes.NewSpecification_FileNotFoundError(err)
	case code == http.StatusGatewayTimeout:
		return error_codes.NewTransfer_TimedOutError(err)
	case code == http.StatusTooManyRequests:
		// 429 means the serving cache's fair scheduler shed the request. It is
		// retryable. This is the generic fallback used when the response body
		// carries no structured reason; the download path parses the body and
		// substitutes a more specific origin_unresponsive / origin_slow
		// classification via throttleErrorForReason.
		return error_codes.NewTransfer_CacheOverloadedError(err)
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		// 401/403 are authorization errors
		return error_codes.NewAuthorizationError(err)
	case code >= 500 && code < 600:
		// 5xx are server errors - use Transfer error (retryable)
		return error_codes.NewTransferError(err)
	case code >= 400 && code < 500:
		// Other 4xx are client/specification errors
		return error_codes.NewSpecificationError(err)
	default:
		// For other status codes, wrap as Transfer error
		return error_codes.NewTransferError(err)
	}
}

// maxErrorBodySize bounds how much of an error-response body the client reads
// and retains. Error bodies come from remote peers that are not necessarily
// trustworthy; without a cap, a hostile server could feed each transfer worker
// an arbitrarily large body.
const maxErrorBodySize = 64 << 10

// maxRetryAfter clamps the Retry-After hint carried on throttle errors so a
// misbehaving server cannot push an absurd backoff to external retriers.
const maxRetryAfter = time.Hour

// throttleErrorForReason maps the machine-parseable reason string carried in a
// cache's 429 response body (the "error" field written by the cache's
// handleError) to the specific retryable Pelican error type. Unknown or empty
// reasons fall back to the generic cache-overloaded classification.
func throttleErrorForReason(reason string, err error) error {
	switch ShedReason(reason) {
	case ShedOriginUnresponsive:
		return error_codes.NewTransfer_OriginUnresponsiveError(err)
	case ShedOriginSlow:
		return error_codes.NewTransfer_OriginSlowError(err)
	case ShedCacheOverloaded:
		return error_codes.NewTransfer_CacheOverloadedError(err)
	default:
		return error_codes.NewTransfer_CacheOverloadedError(err)
	}
}

// parseThrottleBody extracts the machine-parseable reason and the
// human-readable detail from a cache's 429 JSON body of the form
// {"error": "<reason>", "detail": "..."}.
//
// The reason is validated against the known ShedReason constants — the body
// comes from a remote peer, and an arbitrary string must not flow into logs,
// HTCondor ClassAds, or error messages. It is "" when the body is not JSON,
// has no "error" field, or carries an unrecognized reason; callers then fall
// back to the generic throttle classification.
//
// The detail is free-form server text and is not validated (it is bounded by
// truncateErrorDetail and quoted at display time). A body that is not the
// expected JSON shape is passed through whole as the detail so an error
// message from some other kind of server is not silently dropped.
func parseThrottleBody(body string) (reason, detail string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", ""
	}
	var parsed struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return "", body
	}
	switch ShedReason(parsed.Error) {
	case ShedOriginUnresponsive, ShedOriginSlow, ShedCacheOverloaded:
		// The reason is reported on its own, so falling back to the raw body
		// here would just print it a second time.
		return parsed.Error, parsed.Detail
	}
	if parsed.Detail != "" {
		return "", parsed.Detail
	}
	return "", body
}

// parseThrottleReason returns just the validated reason from a 429 body.
func parseThrottleReason(body string) string {
	reason, _ := parseThrottleBody(body)
	return reason
}

// truncateErrorDetail bounds a server-provided message before it is retained
// on an error value. Escaping for safe display happens at formatting time
// (the detail is rendered with %q, so control characters a hostile server
// embeds cannot forge log records).
func truncateErrorDetail(detail string) string {
	const maxDetail = 512
	if len(detail) > maxDetail {
		detail = detail[:maxDetail] + "…"
	}
	return strings.TrimSpace(detail)
}

// parseRetryAfter parses an HTTP Retry-After header value. Per RFC 7231 it may
// be a number of seconds or an HTTP date; the cache emits seconds. Returns 0
// if absent or unparsable; values are clamped to maxRetryAfter.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	// ParseInt rather than Atoi: Atoi is int-wide, so on a 32-bit build a
	// perfectly ordinary "3000000000" would be a range error. On overflow
	// ParseInt still returns the saturated bound, which the clamps below turn
	// into maxRetryAfter (or 0) instead of falling through to the date parse
	// and yielding no hint at all.
	secs, err := strconv.ParseInt(v, 10, 64)
	if err == nil || errors.Is(err, strconv.ErrRange) {
		if secs < 0 {
			return 0
		}
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		return 0
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// wrapStatusCodeError wraps a StatusCodeError with the appropriate PelicanError based on the status code
func wrapStatusCodeError(sce *StatusCodeError) error {
	return wrapErrorByStatusCode(int(*sce), sce)
}

// isDNSError checks if an error is a DNS resolution error
func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// DNS errors are often wrapped in url.Error
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isDNSError(urlErr.Unwrap())
	}
	return false
}

// isTLSError checks if an error is a TLS/certificate error
func isTLSError(err error) bool {
	// Check for TLS errors wrapped in url.Error
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		innerErr := urlErr.Unwrap()
		// Check for common TLS error strings (more reliable than type checking)
		errStr := innerErr.Error()
		if strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "tls") ||
			strings.Contains(errStr, "TLS") ||
			strings.Contains(errStr, "x509") {
			return true
		}
		// Recursively check inner errors
		return isTLSError(innerErr)
	}
	// Check error message directly
	errStr := err.Error()
	return strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "TLS") ||
		strings.Contains(errStr, "x509")
}

// isTLSCertificateValidationError checks if an error is a TLS certificate validation error
// (as opposed to a network issue during TLS handshake). Certificate validation errors
// are not retryable (configuration issue), while handshake network errors might be.
func isTLSCertificateValidationError(err error) bool {
	// tls.AlertError represents TLS handshake errors (like bad_certificate alert),
	// which are retryable handshake failures, not certificate validation errors.
	// Explicitly exclude them from being classified as certificate validation errors.
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return false
	}
	errStr := err.Error()
	// Certificate validation errors typically mention:
	// - "certificate" + ("expired", "not valid", "invalid", "hostname", "name", "verify")
	// - "x509" + ("certificate", "verification")
	// These are configuration/specification issues, not transient network problems
	return (strings.Contains(errStr, "certificate") &&
		(strings.Contains(errStr, "expired") ||
			strings.Contains(errStr, "not valid") ||
			strings.Contains(errStr, "invalid") ||
			strings.Contains(errStr, "hostname") ||
			strings.Contains(errStr, "name") ||
			strings.Contains(errStr, "verify"))) ||
		(strings.Contains(errStr, "x509") &&
			(strings.Contains(errStr, "certificate") ||
				strings.Contains(errStr, "verification")))
}

// isDialError checks if an error is a dial/connection setup error
func isDialError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	// Dial errors are often wrapped in url.Error
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isDialError(urlErr.Unwrap())
	}
	return false
}

// isContextDeadlineError checks if an error is a context deadline exceeded error
func isContextDeadlineError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

// isIdleConnectionError checks if an error is caused by the server closing an idle connection
// This is a normal occurrence when attempting to reuse a connection that the server has closed.
// Note: We use string matching because the Go standard library does not export a specific error type
// for this condition. While this error message is consistently produced by the Go HTTP client,
// it's an implementation detail rather than a documented stable API contract.
func isIdleConnectionError(err error) bool {
	if err == nil {
		return false
	}
	// Check if the error message contains "server closed idle connection" or "tls: unexpected message"
	// These are specific error messages from the Go HTTP client indicating connection issues
	return strings.Contains(err.Error(), "server closed idle connection") ||
		strings.Contains(err.Error(), "tls: unexpected message")
}

// isRetryableWebDavError checks if an error should trigger a retry for WebDAV operations
// This includes idle connection errors and timeout errors
func isRetryableWebDavError(err error) bool {
	if err == nil {
		return false
	}
	// Check for idle connection errors
	if isIdleConnectionError(err) {
		return true
	}
	// Check for timeout errors (both connection timeout and response header timeout)
	errStr := err.Error()
	return strings.Contains(errStr, "timeout awaiting response headers")
}

// ConnectionSetupError methods

func (e *ConnectionSetupError) Error() string {
	if e.Err != nil {
		if len(e.URL) > 0 {
			return "failed connection setup to " + e.URL + ": " + e.Err.Error()
		} else {
			return "failed connection setup: " + e.Err.Error()
		}
	} else {
		return "Connection to remote server failed"
	}
}

func (e *ConnectionSetupError) Unwrap() error {
	return e.Err
}

func (e *ConnectionSetupError) Is(target error) bool {
	_, ok := target.(*ConnectionSetupError)
	return ok
}

// StatusCodeError methods

func (e *StatusCodeError) Error() string {
	if int(*e) == http.StatusGatewayTimeout {
		return "cache timed out waiting on origin"
	}
	return fmt.Sprintf("server returned %d %s", int(*e), http.StatusText(int(*e)))
}

func (e *StatusCodeError) Is(target error) bool {
	sce, ok := target.(*StatusCodeError)
	if !ok {
		return false
	}
	return int(*sce) == int(*e)
}

// ChecksumMismatchError methods

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf(
		"checksum mismatch for %s; client computed %s, server reported %s",
		HttpDigestFromChecksum(e.Info.Algorithm),
		checksumValueToHttpDigest(e.Info.Algorithm, e.Info.Value),
		checksumValueToHttpDigest(e.Info.Algorithm, e.ServerValue),
	)
}

// HeaderTimeoutError methods

func (e *HeaderTimeoutError) Error() string {
	return "timeout waiting for HTTP response (TCP connection successful)"
}

func (e *HeaderTimeoutError) Is(target error) bool {
	_, ok := target.(*HeaderTimeoutError)
	return ok
}

// NetworkResetError methods

func (e *NetworkResetError) Error() string {
	return "the existing TCP connection was broken (potentially caused by server restart or NAT/firewall issue)"
}

// StoppedTransferError methods

func (e *StoppedTransferError) Error() (errMsg string) {
	if e.StoppedTime > 0 {
		errMsg = "no progress for more than " + e.StoppedTime.Truncate(time.Millisecond).String()
	} else {
		errMsg = "no progress"
	}
	errMsg += " after " + ByteCountSI(e.BytesTransferred) + " transferred"
	if !e.Upload {
		if e.CacheHit {
			errMsg += " (cache hit)"
		} else {
			errMsg += " (cache miss)"
		}
	}
	return
}

func (e *StoppedTransferError) Is(target error) bool {
	_, ok := target.(*StoppedTransferError)
	return ok
}

// allocateMemoryError methods

func (e *allocateMemoryError) Error() string {
	return e.Err.Error()
}

func (e *allocateMemoryError) Unwrap() error {
	return e.Err
}

func (e *allocateMemoryError) Is(target error) bool {
	_, ok := target.(*allocateMemoryError)
	return ok
}

// dirListingNotSupportedError methods

func (e *dirListingNotSupportedError) Error() string {
	return e.Err.Error()
}

func (e *dirListingNotSupportedError) Unwrap() error {
	return e.Err
}

func (e *dirListingNotSupportedError) Is(target error) bool {
	_, ok := target.(*dirListingNotSupportedError)
	return ok
}

// InvalidByteInChunkLengthError methods

func (e *InvalidByteInChunkLengthError) Error() string {
	return e.Err.Error()
}

func (e *InvalidByteInChunkLengthError) Unwrap() error {
	return e.Err
}

func (e *InvalidByteInChunkLengthError) Is(target error) bool {
	_, ok := target.(*InvalidByteInChunkLengthError)
	return ok
}

// UnexpectedEOFError methods

func (e *UnexpectedEOFError) Error() string {
	return e.Err.Error()
}

func (e *UnexpectedEOFError) Unwrap() error {
	return e.Err
}

func (e *UnexpectedEOFError) Is(target error) bool {
	_, ok := target.(*UnexpectedEOFError)
	return ok
}

// HttpErrResp type and methods

type HttpErrResp struct {
	Code int
	Str  string
	Err  error
}

func (e *HttpErrResp) Error() string {
	if e.Err != nil {
		return e.Str + ": " + e.Err.Error()
	}
	return e.Str
}

func (e *HttpErrResp) Unwrap() error {
	return e.Err
}

// CacheThrottleError is returned when a cache responds with HTTP 429 because
// its fair scheduler shed the request. It carries the machine-parseable Reason
// (from the response body) and the RetryAfter hint (from the Retry-After
// header) so callers and external retriers can distinguish an unresponsive
// origin from a merely-slow one and honor the advertised backoff. It wraps the
// specific retryable Pelican error type, so errors.As(err, &error_codes.PelicanError{})
// and IsRetryable both work through the chain.
type CacheThrottleError struct {
	Reason     string
	RetryAfter time.Duration
	// Endpoint is the cache host that shed the request.
	Endpoint string
	// Err is the wrapped, specific retryable PelicanError.
	Err error
	// detail is the server-provided human-readable message.
	detail string
}

func (e *CacheThrottleError) Error() string {
	var sb strings.Builder
	sb.WriteString("request throttled by cache")
	if e.Endpoint != "" {
		sb.WriteString(" ")
		sb.WriteString(e.Endpoint)
	}
	if e.Reason != "" {
		sb.WriteString(" (")
		sb.WriteString(e.Reason)
		sb.WriteString(")")
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&sb, "; retry after %s", e.RetryAfter)
	}
	if e.detail != "" {
		// The detail is server-provided text: render it quoted so embedded
		// control characters cannot forge log records downstream.
		fmt.Fprintf(&sb, ": %q", e.detail)
	}
	if e.Err != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Err.Error())
	}
	return sb.String()
}

func (e *CacheThrottleError) Unwrap() error {
	return e.Err
}

// Is reports a match for ErrTooManyRequests so a throttle observed as a
// remote 429 satisfies the same errors.Is check as a shed performed by
// this process's own scheduler.
func (e *CacheThrottleError) Is(target error) bool {
	return target == ErrTooManyRequests
}

// newThrottleErrorFromResponse builds the structured throttle error for an
// HTTP 429 from any request flavor (GET, PUT, HEAD, COPY): the reason is
// parsed (and validated) from the already-read response body, the backoff
// hint from the Retry-After header. body may be empty when the response
// body was unavailable (e.g. HEAD).
func newThrottleErrorFromResponse(resp *http.Response, body, endpoint string) *CacheThrottleError {
	reason, detail := parseThrottleBody(body)
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	return newCacheThrottleError(reason, detail, endpoint, retryAfter)
}

// newThrottleErrorNoResponse builds the structured throttle error for a 429
// observed through a library that does not expose the response, so neither the
// body's reason nor the Retry-After header is available (the WebDAV client used
// for stat is the case in point). The result still classifies as retryable and
// still satisfies errors.Is(err, ErrTooManyRequests); it just carries no reason
// or backoff hint.
func newThrottleErrorNoResponse(endpoint, detail string) *CacheThrottleError {
	return newCacheThrottleError("", detail, endpoint, 0)
}

// newCacheThrottleError builds a CacheThrottleError from a cache's 429
// response: the reason parsed from the JSON body's "error" field, the
// Retry-After header, the endpoint host, and the body detail (truncated
// here; quoted at display time since it is server-controlled text).
func newCacheThrottleError(reason, detail, endpoint string, retryAfter time.Duration) *CacheThrottleError {
	// Not every 429 carries a reason -- a HEAD response has no body, and the
	// WebDAV client hides the response entirely -- so omit the parenthetical
	// rather than rendering an empty one.
	base := fmt.Errorf("cache %s throttled the request", endpoint)
	if reason != "" {
		base = fmt.Errorf("cache %s throttled the request (%s)", endpoint, reason)
	}
	return &CacheThrottleError{
		Reason:     reason,
		RetryAfter: retryAfter,
		Endpoint:   endpoint,
		Err:        throttleErrorForReason(reason, base),
		detail:     truncateErrorDetail(detail),
	}
}

// SlowTransferError methods

func (e *SlowTransferError) Error() (errMsg string) {
	errMsg = "cancelled transfer, too slow; detected speed=" +
		ByteCountSI(e.BytesPerSecond) +
		"/s, total transferred=" +
		ByteCountSI(e.BytesTransferred) +
		", total transfer time=" +
		e.Duration.Round(time.Millisecond).String()
	if e.CacheAge == 0 {
		errMsg += ", cache miss"
	} else if e.CacheAge > 0 {
		errMsg += ", cache hit"
	}
	return
}

func (e *SlowTransferError) Is(target error) bool {
	_, ok := target.(*SlowTransferError)
	return ok
}

// TransferAttemptError methods

func (tae *TransferAttemptError) Error() (errMsg string) {
	errMsg = "failed download from "
	if tae.isUpload {
		errMsg = "failed upload to "
	}
	if tae.serviceHost == "" {
		errMsg += "unknown host"
	} else {
		errMsg += tae.serviceHost
	}
	if tae.isProxyErr {
		if tae.proxyHost == "" {
			errMsg += " due to unknown proxy"
		} else {
			errMsg += " due to proxy " + tae.proxyHost
		}
	} else if tae.proxyHost != "" {
		errMsg += "+proxy=" + tae.proxyHost
	}
	if tae.err != nil {
		errMsg += ": " + tae.err.Error()
	}
	return
}

func (tae *TransferAttemptError) Unwrap() error {
	return tae.err
}

func (tae *TransferAttemptError) Is(target error) bool {
	other, ok := target.(*TransferAttemptError)
	if !ok {
		return false
	}
	return tae.isUpload == other.isUpload && tae.serviceHost == other.serviceHost && tae.isProxyErr == other.isProxyErr && tae.proxyHost == other.proxyHost
}

// newTransferAttemptError creates a new TransferAttemptError
func newTransferAttemptError(service string, proxy string, isProxyErr bool, isUpload bool, err error) (tae *TransferAttemptError) {
	tae = &TransferAttemptError{
		serviceHost: service,
		proxyHost:   proxy,
		isProxyErr:  isProxyErr,
		isUpload:    isUpload,
		err:         err,
	}
	return
}

// wrapHttpErrRespInner wraps the inner error of an HttpErrResp while
// preserving the human-readable response body captured in HttpErrResp.Str.
//
// Before this fix, this function returned only the inner PelicanError,
// discarding HttpErrResp.Str (which contains the origin's response body).
// Now the PelicanError is re-wrapped so its inner error carries the full
// message (e.g. "request failed (HTTP status 404): No such file").
func wrapHttpErrRespInner(httpErr *HttpErrResp) error {
	innerErr := httpErr.Unwrap()
	// Check if inner error is already a PelicanError (wrapped in downloadHTTP)
	var pe *error_codes.PelicanError
	if errors.As(innerErr, &pe) {
		// Preserve the origin's response body (httpErr.Str) by re-wrapping
		// the PelicanError around an error that includes the body text.
		// This ensures the message survives all the way to the cache API
		// error handler instead of being reduced to just the status code.
		// Use %w to keep the original inner error (e.g. *StatusCodeError)
		// reachable via errors.As.
		return pe.Wrap(fmt.Errorf("%s: %w", httpErr.Str, pe.Unwrap()))
	}
	if sce, ok := innerErr.(*StatusCodeError); ok {
		// Unwrapped StatusCodeError (shouldn't happen if downloadHTTP wraps correctly, but handle for safety)
		return wrapStatusCodeError(sce)
	}
	// HttpErrResp with non-StatusCodeError inner error - wrap based on HTTP status code
	return wrapErrorByStatusCode(httpErr.Code, innerErr)
}

// wrapConnectionSetupErrorInner wraps the inner error of a ConnectionSetupError
func wrapConnectionSetupErrorInner(cse *ConnectionSetupError, originalErr error) error {
	innerErr := cse.Unwrap()
	if sce, ok := innerErr.(*StatusCodeError); ok {
		return wrapStatusCodeError(sce)
	}
	if isTLSCertificateValidationError(innerErr) {
		// TLS certificate validation error - wrap as SpecificationError (configuration issue, not retryable)
		return error_codes.NewSpecificationError(originalErr)
	}
	if ue, ok := innerErr.(*url.Error); ok {
		httpErr := ue.Unwrap()
		if httpErr.Error() == "net/http: timeout awaiting response headers" {
			return error_codes.NewTransfer_HeaderTimeoutError(&HeaderTimeoutError{})
		}
	}
	// Wrap ConnectionSetupError (it's still a connection setup error)
	return error_codes.NewContact_ConnectionSetupError(cse)
}

// wrapDownloadError wraps an error from downloadHTTP with the appropriate PelicanError type.
// It returns the wrapped error and a boolean indicating if this is a proxy error.
// The proxyStr may be modified if the error is a proxy connection error.
func wrapDownloadError(err error, transferEndpointURL string, tokenContents string, fedTokenContents string) (wrappedErr error, isProxyErr bool, modifiedProxyStr string) {
	// Handle proxy connection errors
	var ope *net.OpError
	if errors.As(err, &ope) && ope.Op == "proxyconnect" {
		if ope.Addr != nil {
			modifiedProxyStr = "(" + ope.Addr.String() + ")"
		}
		proxyErr := &ConnectionSetupError{URL: transferEndpointURL, Err: err}
		return error_codes.NewContact_ConnectionSetupError(proxyErr), true, modifiedProxyStr
	}

	// Handle permission denied errors
	var pde *PermissionDeniedError
	if errors.As(err, &pde) {
		// Enrich with token validity information.  If the origin already
		// provided a reason (preserved in pde.message from downloadHTTP),
		// append the token diagnosis; otherwise build a standalone message.
		var parts []string
		if tokenContents != "" {
			expired, expiration, tokenErr := tokenIsExpired(tokenContents)
			if tokenErr != nil {
				parts = append(parts, "token could not be parsed")
			} else if expired {
				parts = append(parts, "token expired at "+expiration.Format(time.RFC3339))
				pde.expired = true
			} else {
				parts = append(parts, "token appears valid but was rejected by the server")
			}
		}
		if fedTokenContents != "" {
			expired, expiration, tokenErr := tokenIsExpired(fedTokenContents)
			if tokenErr != nil {
				parts = append(parts, "federation token could not be parsed")
			} else if expired {
				parts = append(parts, "federation token expired at "+expiration.Format(time.RFC3339))
				if !pde.expired {
					pde.expired = true
				}
			} else {
				parts = append(parts, "federation token appears valid but was rejected by the server")
			}
		}
		var tokenDetail string
		if len(parts) == 0 {
			// No token was sent (e.g., public namespace accessed via a cache that doesn't know about it yet).
			// Mark as retryable so the client can attempt at a different cache that isn't stale.
			tokenDetail = "no token was provided"
			pde.noToken = true
		} else {
			tokenDetail = strings.Join(parts, "; ")
		}
		if pde.message != "" {
			pde.message = pde.message + " (" + tokenDetail + ")"
		} else {
			pde.message = "Permission denied: " + tokenDetail
		}
		return error_codes.NewAuthorizationError(pde), false, ""
	}

	// Handle connection reset errors
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return error_codes.NewContact_ConnectionResetError(&NetworkResetError{}), false, ""
	}

	// Handle allocate memory errors
	var allocErr *allocateMemoryError
	if errors.As(err, &allocErr) {
		return error_codes.NewTransferError(allocErr), false, ""
	}

	// Handle invalid chunk length errors
	var invalidChunkErr *InvalidByteInChunkLengthError
	if errors.As(err, &invalidChunkErr) {
		return error_codes.NewTransferError(invalidChunkErr), false, ""
	}

	// Handle HttpErrResp (returned from downloadHTTP)
	var httpErr *HttpErrResp
	if errors.As(err, &httpErr) {
		return wrapHttpErrRespInner(httpErr), false, ""
	}

	// Handle ConnectionSetupError
	var cse *ConnectionSetupError
	if errors.As(err, &cse) {
		return wrapConnectionSetupErrorInner(cse, err), false, ""
	}

	// Handle connection setup errors (timeout, DNS, TLS handshake, dial)
	if isContextDeadlineError(err) || isDNSError(err) || (isTLSError(err) && !isTLSCertificateValidationError(err)) || isDialError(err) {
		cse := &ConnectionSetupError{URL: transferEndpointURL, Err: err}
		return error_codes.NewContact_ConnectionSetupError(cse), false, ""
	}

	// Catch-all: check if error is already a PelicanError
	var pe *error_codes.PelicanError
	if errors.As(err, &pe) {
		return err, false, ""
	}
	// Unknown error type - wrap as generic TransferError
	return error_codes.NewTransferError(err), false, ""
}
