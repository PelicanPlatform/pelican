package main

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

//  TestErrorAccum tests simple adding and removing from the accumulator
func TestErrorAccum(t *testing.T) {
	// Case 1: cache with http
	err := errors.New("error1")
	err2 := errors.New("error2")
	AddError(err)
	AddError(err2)

	errStr := GetErrors()
	assert.Equal(t, "error1;error2;", errStr)

}
