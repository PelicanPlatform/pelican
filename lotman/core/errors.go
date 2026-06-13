/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package core

import (
	"errors"
	"fmt"
)

// Sentinel errors. Callers may test with errors.Is.
var (
	// ErrNilDB is returned when New is given a nil database handle.
	ErrNilDB = errors.New("lotman/core: nil database handle")
	// ErrLotNotFound is returned when a referenced lot does not exist.
	ErrLotNotFound = errors.New("lotman/core: lot not found")
	// ErrLotExists is returned when creating a lot whose name is already taken.
	ErrLotExists = errors.New("lotman/core: lot already exists")
	// ErrInvalidLot is returned when a lot specification violates an invariant
	// (missing parent, invalid MPA sentinel combination, partial-zero timestamps).
	ErrInvalidLot = errors.New("lotman/core: invalid lot specification")
	// ErrNotAuthorized is returned when the caller is not an owner/parent
	// permitted to perform the requested mutation.
	ErrNotAuthorized = errors.New("lotman/core: caller not authorized for lot")
	// ErrReclaimed is returned when a mutation targets an already-reclaimed lot.
	ErrReclaimed = errors.New("lotman/core: lot is reclaimed")
)

// wrap annotates an error with context, preserving the chain for errors.Is/As.
// Returns nil if err is nil.
func wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("lotman/core: %s: %w", msg, err)
}

// wrapf is the formatted variant of wrap.
func wrapf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("lotman/core: "+format+": %w", append(args, err)...)
}
