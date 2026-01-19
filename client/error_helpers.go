/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// wrapHttpErrRespInner wraps the inner error of an HttpErrResp
func wrapHttpErrRespInner(httpErr *HttpErrResp) error {
	innerErr := httpErr.Unwrap()
	// Check if inner error is already a PelicanError (wrapped in downloadHTTP)
	var pe *error_codes.PelicanError
	if errors.As(innerErr, &pe) {
		return innerErr
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
func wrapDownloadError(err error, transferEndpointURL string, tokenContents string) (wrappedErr error, isProxyErr bool, modifiedProxyStr string) {
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
		// If the token is expired we can retry because we will just get a new token
		// otherwise something is wrong with the token
		expired, expiration, tokenErr := tokenIsExpired(tokenContents)
		if tokenErr != nil {
			pde.message = "Permission denied: token could not be parsed"
			pde.expired = false
		} else if expired {
			pde.message = "Permission denied: token expired at " + expiration.Format(time.RFC3339)
			pde.expired = true
		} else {
			pde.message = "Permission denied: token appears valid but was rejected by the server"
			pde.expired = false
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
