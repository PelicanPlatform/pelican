package stashcp

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

//  TestErrorAccum tests simple adding and removing from the accumulator
func TestErrorAccum(t *testing.T) {
	bunchOfErrors = make([]error, 0)
	defer func() {
		bunchOfErrors = make([]error, 0)
	}()
	// Case 1: cache with http
	err := errors.New("error1")
	err2 := errors.New("error2")
	AddError(err)
	AddError(err2)

	errStr := GetErrors()
	assert.Equal(t, "error1;error2;", errStr)

}

// TestErrorsRetryableFalse tests that errors are not retryable
func TestErrorsRetryableFalse(t *testing.T) {
	bunchOfErrors = make([]error, 0)
	defer func() {
		bunchOfErrors = make([]error, 0)
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
	bunchOfErrors = make([]error, 0)
	defer func() {
		bunchOfErrors = make([]error, 0)
	}()
	// Try with a retryable error nested error
	AddError(&url.Error{Err: &SlowTransferError{}})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

	AddError(&ConnectionSetupError{})
	assert.True(t, ErrorsRetryable(), "ErrorsRetryable should be true")

}
