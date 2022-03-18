package stashcp

import (
	"errors"
	"sync"
)

var (
	bunchOfErrors []error
	mu            sync.Mutex
)

// AddError will add an accumulated error to the error stack
func AddError(err error) bool {
	mu.Lock()
	defer mu.Unlock()
	bunchOfErrors = append(bunchOfErrors, err)
	return true
}

func GetErrors() string {
	mu.Lock()
	defer mu.Unlock()
	var toReturn string
	for _, theError := range bunchOfErrors {
		toReturn += theError.Error() + ";"
	}
	return toReturn
}

// IsRetryable will return true if the error is retryable
func IsRetryable(err error) bool {
	if errors.Is(err, &SlowTransferError{}) ||
		errors.Is(err, &ConnectionSetupError{}) {
		return true
	}
	return false
}

// ErrorsRetryable returns if the errors in the stack are retryable later
func ErrorsRetryable() bool {
	mu.Lock()
	defer mu.Unlock()
	// Loop through the errors and see if all of them are retryable
	for _, theError := range bunchOfErrors {
		if !IsRetryable(theError) {
			return false
		}
	}
	return true
}
