package stashcp

import (
	"errors"
	"sync"
	"time"
)

type TimestampedError struct {
	err error
	timestamp time.Time
}

var (
	bunchOfErrors []TimestampedError
	mu            sync.Mutex
	// We will generate an error string including the time since startup
	startup       time.Time = time.Now()
)

// AddError will add an accumulated error to the error stack
func AddError(err error) bool {
	mu.Lock()
	defer mu.Unlock()
	bunchOfErrors = append(bunchOfErrors, TimestampedError{err, time.Now()})
	return true
}

func GetErrors() string {
	mu.Lock()
	defer mu.Unlock()
	first := true
	lastError := startup
	var errorsFormatted []string
	for _, theError := range bunchOfErrors {
		errFmt := theError.err.Error()
		timeElapsed := theError.timestamp.Sub(lastError)
		timeFormat := timeElapsed.Truncate(100*time.Millisecond).String()
		errFmt += " (" + timeFormat
		if first {
			errFmt += " since start)"
		} else {
			timeSinceStart := theError.timestamp.Sub(startup)
			timeSinceStartFormat := timeSinceStart.Truncate(100*time.Millisecond).String()
			errFmt += " elapsed, " + timeSinceStartFormat + " since start)"
		}
		lastError = theError.timestamp
		errorsFormatted = append(errorsFormatted, errFmt)
		first = false
	}
	var toReturn string
	first = true
	for idx := len(errorsFormatted)-1; idx >= 0; idx-- {
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
		if !IsRetryable(theError.err) {
			return false
		}
	}
	return true
}
