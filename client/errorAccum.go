/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/pelican_url"
)

// PermissionDeniedError is returned when a 403 status code is received.
// The message is generated based on the token's validity.
type PermissionDeniedError struct {
	message string
	expired bool
}

func (e *PermissionDeniedError) Error() string {
	if e.message == "" {
		return "permission denied"
	}
	return e.message
}

type (
	TimestampedError struct {
		err       error
		timestamp time.Time
	}

	// A container object for multiple sub-errors representing transfer failures.
	TransferErrors struct {
		start  time.Time
		errors []error
	}
)

func (te *TimestampedError) Error() string {
	return te.err.Error()
}

func (te *TimestampedError) Unwrap() error {
	return te.err
}

// Create a new transfer error object
func NewTransferErrors() *TransferErrors {
	return &TransferErrors{
		start:  time.Now(),
		errors: make([]error, 0),
	}
}

func (te *TransferErrors) AddError(err error) {
	te.AddPastError(err, time.Now())
}

func (te *TransferErrors) AddPastError(err error, timestamp time.Time) {
	if te.errors == nil {
		te.errors = make([]error, 0)
	}
	if err != nil {
		te.errors = append(te.errors, &TimestampedError{err: err, timestamp: timestamp})
	}
}

// This resets the TransferErrors object for testing purposes
func (te *TransferErrors) resetErrors() {
	te.errors = make([]error, 0)
}

func (te *TransferErrors) Unwrap() []error {
	return te.errors
}

func (te *TransferErrors) Error() string {
	if te.errors == nil {
		return "transfer error unknown"
	}
	if len(te.errors) == 1 {
		return "transfer error: " + te.errors[0].Error()
	}
	errors := make([]string, len(te.errors))
	for idx, err := range te.errors {
		errors[idx] = err.Error()
	}
	return "transfer errors: [" + strings.Join(errors, ", ") + "]"
}

// Return a more refined, user-friendly error string
func (te *TransferErrors) UserError() string {
	first := true
	lastError := te.start
	var errorsFormatted []string
	for idx, err := range te.errors {
		theError := err.(*TimestampedError)
		var errFmt string
		if len(te.errors) > 1 {
			errFmt = fmt.Sprintf("Attempt #%v: %s", idx+1, theError.err.Error())
		} else {
			errFmt = theError.err.Error()
		}
		timeElapsed := theError.timestamp.Sub(lastError)
		timeFormat := timeElapsed.Truncate(100 * time.Millisecond).String()
		errFmt += " (" + timeFormat
		if first {
			errFmt += " since start)"
		} else {
			timeSinceStart := theError.timestamp.Sub(te.start)
			timeSinceStartFormat := timeSinceStart.Truncate(100 * time.Millisecond).String()
			errFmt += " elapsed, " + timeSinceStartFormat + " since start)"
		}
		lastError = theError.timestamp
		errorsFormatted = append(errorsFormatted, errFmt)
		first = false
	}
	var toReturn string
	first = true
	for idx := len(errorsFormatted) - 1; idx >= 0; idx-- {
		if !first {
			toReturn += "; "
		}
		toReturn += errorsFormatted[idx]
		first = false
	}
	return toReturn
}

// IsRetryable will return true if the error is retryable
func IsRetryable(err error) bool {
	// Special case: PermissionDeniedError has dynamic retryability based on token expiration
	// Check this before the general PelicanError check since it's always wrapped but needs special handling
	// If the token is expired, we can retry because we'll get a new token
	var pde *PermissionDeniedError
	if errors.As(err, &pde) {
		return pde.expired
	}

	// Check if it contains a TLS AlertError, which should always be retryable
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}

	// Check if it's a wrapped PelicanError - use its metadata
	var pe *error_codes.PelicanError
	if errors.As(err, &pe) {
		return pe.IsRetryable()
	}

	// Fall back to legacy checks for unwrapped errors
	if errors.Is(err, pelican_url.MetadataTimeoutErr) {
		return true
	}

	var hep *HttpErrResp
	if errors.As(err, &hep) {
		switch int(hep.Code) {
		case http.StatusInternalServerError:
		case http.StatusBadGateway:
		case http.StatusServiceUnavailable:
		case http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

// Returns true if all errors are retryable.
// If no errors are present, then returns true
func (te *TransferErrors) AllErrorsRetryable() bool {
	if te.errors == nil {
		return true
	}
	for _, err := range te.errors {
		if !IsRetryable(err) {
			return false
		}
	}
	return true
}

func ShouldRetry(err error) bool {
	var te *TransferErrors
	if errors.As(err, &te) {
		return te.AllErrorsRetryable()
	}
	return IsRetryable(err)
}
