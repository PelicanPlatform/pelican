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

package error_codes

import (
	"errors"
	"strings"
)

// ErrPelican matches any classified Pelican error, whatever its type. It is the
// sentinel to use when the question is "did anything classify this at all",
// which is what the CLI exit paths ask before choosing an exit code.
var ErrPelican = &PelicanError{}

func (e *PelicanError) Is(target error) bool {
	if exact, ok := target.(exactMatch); ok {
		return e.errorType == exact.errorType
	}
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

// exactMatch is a sentinel wrapper that opts out of hierarchical matching. It
// is comparable, as errors.Is requires of a target.
type exactMatch struct{ *PelicanError }

// Exactly narrows a sentinel so that errors.Is matches that classification
// alone and none of its descendants:
//
//	errors.Is(err, error_codes.ErrSpecification)             // any Specification.*
//	errors.Is(err, Exactly(error_codes.ErrSpecification))    // the bare code only
//
// Needed where a parent code carries a meaning its children do not share. A
// bare Specification says the object is not there, while its
// FileNotCreated and FileAlreadyExists descendants are write-path answers
// that must not be read as "absent".
func Exactly(sentinel *PelicanError) error {
	return exactMatch{sentinel}
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
