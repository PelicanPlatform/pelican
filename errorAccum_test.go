/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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

package pelican

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrorAccum tests simple adding and removing from the accumulator
func TestErrorAccum(t *testing.T) {
	bunchOfErrors = make([]TimestampedError, 0)
	defer func() {
		bunchOfErrors = make([]TimestampedError, 0)
	}()
	// Case 1: cache with http
	err := errors.New("error1")
	err2 := errors.New("error2")
	AddError(err)
	AddError(err2)

	errStr := GetErrors()
	assert.Regexp(t, `Attempt\ \#2:\ error2\ \(0s\ elapsed,\ [0-9]+m?s\ since\ start\);\ Attempt\ \#1:\ error1\ \([0-9]+m?s\ since\ start\)`, errStr)

}

// TestErrorsRetryableFalse tests that errors are not retryable
func TestErrorsRetryableFalse(t *testing.T) {
	bunchOfErrors = make([]TimestampedError, 0)
	defer func() {
		bunchOfErrors = make([]TimestampedError, 0)
	}()
	// Case 2: cache with http
	AddError(&SlowTransferError{})
	AddError(&SlowTransferError{})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

	AddError(&ConnectionSetupError{})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

	// Now add a non-retryable error
	AddError(errors.New("Non retryable error"))
	assert.False(t, ErrorsRetryable(), "ErrorsRetryable should be false")

}

// TestErrorsRetryableTrue tests that errors are retryable
func TestErrorsRetryableTrue(t *testing.T) {
	bunchOfErrors = make([]TimestampedError, 0)
	defer func() {
		bunchOfErrors = make([]TimestampedError, 0)
	}()
	// Try with a retryable error nested error
	AddError(&url.Error{Err: &SlowTransferError{}})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

	AddError(&ConnectionSetupError{})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

}
