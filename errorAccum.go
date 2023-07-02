package pelican

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	grab "github.com/cavaliercoder/grab"
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

func ClearErrors() {
	mu.Lock()
	defer mu.Unlock()

	bunchOfErrors = make([]TimestampedError, 0)
}

func GetErrors() string {
	mu.Lock()
	defer mu.Unlock()
	first := true
	lastError := startup
	var errorsFormatted []string
	for idx, theError := range bunchOfErrors {
		errFmt := fmt.Sprintf("Attempt #%v: %s", idx + 1, theError.err.Error())
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
	if errors.Is(err, &SlowTransferError{}) {
		return true
	}
	var cse *ConnectionSetupError
	if errors.As(err, &cse) {
		if sce, ok := cse.Unwrap().(grab.StatusCodeError); ok {
			switch int(sce) {
			case http.StatusInternalServerError:
			case http.StatusBadGateway:
			case http.StatusServiceUnavailable:
			case http.StatusGatewayTimeout:
				return true
			default:
				return false
			}
		}
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
