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

// Package error_codes classifies client failures into the taxonomy documented
// in docs/error_codes.yaml, and lets callers ask which classification an error
// carries with the standard errors.Is.
//
// # The model
//
// Every classification has a dotted name, such as "Specification" or
// "Specification.FileNotFound". The dots are the taxonomy: a name is the child
// of whatever precedes its last dot. That is the only place the hierarchy
// exists. A child error does not wrap its parent, and no PelicanError ever
// wraps a sentinel; the relationship is spelled out in the name string alone.
//
// There are two kinds of value:
//
//   - An error to return, built by a New*Error constructor. It carries a
//     classification and a cause, and is wrapped and unwrapped like any other
//     Go error.
//   - A sentinel, one per classification (ErrSpecification,
//     ErrSpecification_FileNotFound, ...). It carries the classification and
//     nothing else, and is only ever the target argument of errors.Is.
//
// # Matching
//
// errors.Is(err, sentinel) walks err's Unwrap chain exactly as it does for any
// error, including the Unwrap() []error branches an accumulator produces. At
// each PelicanError it visits, it asks the Is method below whether that
// error's name is the sentinel's name or a descendant of it:
//
//	errors.Is(NewSpecification_FileNotFoundError(cause), ErrSpecification)             // true
//	errors.Is(NewSpecification_FileNotFoundError(cause), ErrSpecification_FileNotFound) // true
//	errors.Is(NewSpecificationError(cause), ErrSpecification_FileNotFound)             // false
//
// So a sentinel for a parent asks "anything in this family?" and a sentinel for
// a leaf asks "this one exactly?". A caller that needs one specific answer
// matches a leaf; a caller that needs a whole category matches the parent.
// Nothing here changes how far errors.Is walks, only what counts as a match at
// each step.
package error_codes

import (
	"errors"
	"strings"
)

// ErrPelican matches any classified Pelican error, whatever its type. It is the
// sentinel to use when the question is "did anything classify this at all",
// which is what the CLI exit paths ask before choosing an exit code.
var ErrPelican = &PelicanError{}

// Is reports whether e's classification is target's classification or one of
// its descendants, so that errors.Is can compare an error against the
// sentinels. A target that is not a *PelicanError is not a Pelican sentinel and
// never matches.
func (e *PelicanError) Is(target error) bool {
	t, ok := target.(*PelicanError)
	if !ok {
		return false
	}
	if t == ErrPelican {
		return true
	}
	if t.errorType == "" || e.errorType == "" {
		return false
	}
	return e.errorType == t.errorType || strings.HasPrefix(e.errorType, t.errorType+".")
}

// ExitCodeFor returns the documented client exit code for the classification in
// err's chain, and whether one was found. The code is a property of the
// classification rather than of the particular error, so it comes from the
// matched sentinel and needs nothing from the instance.
//
// When a chain carries more than one classification -- a refused upload, where
// a TransferErrors accumulator wraps an Authorization error -- the narrowest
// sentinel that matches anywhere in the chain wins, not the outermost one.
func ExitCodeFor(err error) (int, bool) {
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return sentinel.exitCode, true
		}
	}
	return 0, false
}

// Message returns the classified error's own message, and whether err carried a
// classification at all.
//
// The point of preferring this over err.Error() is that it drops the wrapping
// context accumulated on the way up -- "failed download: request failed:" --
// which is useful in a log and noise in a message shown to a user.
func Message(err error) (string, bool) {
	var pe *PelicanError
	if !errors.As(err, &pe) {
		return "", false
	}
	return pe.Error(), true
}
