package main

import "sync"

var (
	bunchOfErrors []error
	mu sync.Mutex
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
