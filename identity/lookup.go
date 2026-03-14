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

package identity

import (
	"context"
	"fmt"
)

// UserInfo contains resolved POSIX identity information for a user.
type UserInfo struct {
	UID       uint32
	GID       uint32
	Username  string
	Groupname string
	HomeDir   string
	Shell     string
}

// LookupStrategy defines the interface for user/group lookup implementations.
// Implementations need not be safe for concurrent use; the CachedLookup
// wrapper serialises access.
type LookupStrategy interface {
	// LookupUser looks up a user by username and returns user info.
	LookupUser(ctx context.Context, username string) (*UserInfo, error)

	// LookupGroup looks up a group by name and returns the GID.
	LookupGroup(ctx context.Context, groupname string) (uint32, error)

	// LookupSecondaryGroups returns the GIDs of the secondary (supplementary)
	// groups the user belongs to.  The primary GID should NOT be included.
	// Implementations that cannot determine secondary groups should return
	// (nil, nil).
	LookupSecondaryGroups(ctx context.Context, username string) ([]uint32, error)

	// Name returns a human-readable name for this strategy.
	Name() string
}

// Lookup is the high-level interface consumed by the rest of Pelican
// (e.g. multiuserFileSystem).  Implementations must be safe for
// concurrent use.
type Lookup interface {
	// UidForUser returns the UID for the given username.
	UidForUser(username string) (uint32, error)

	// GidForGroup returns the GID for the given group name.
	GidForGroup(groupname string) (uint32, error)

	// SecondaryGidsForUser returns the secondary GIDs for the given
	// username, filtered to exclude any GID below the configured
	// minimum threshold.  The primary GID is not included.
	SecondaryGidsForUser(username string) ([]uint32, error)
}

// ErrUserNotFound is returned when a user cannot be resolved.
type ErrUserNotFound struct {
	Username string
}

func (e *ErrUserNotFound) Error() string {
	return fmt.Sprintf("user not found: %s", e.Username)
}

// ErrGroupNotFound is returned when a group cannot be resolved.
type ErrGroupNotFound struct {
	Groupname string
}

func (e *ErrGroupNotFound) Error() string {
	return fmt.Sprintf("group not found: %s", e.Groupname)
}

// ErrStrategyNotAvailable is returned when a strategy cannot be used
// on the current system.
var ErrStrategyNotAvailable = fmt.Errorf("strategy not available")

// DefaultMinID is the minimum UID/GID that the Lookup layer will
// return.  Any resolved ID below this threshold is rejected to
// prevent accidental operations as root or other system accounts.
const DefaultMinID uint32 = 1000

// ErrBelowMinID is returned when a resolved UID or GID is below
// the configured minimum threshold.
type ErrBelowMinID struct {
	Name  string // username or groupname
	ID    uint32
	MinID uint32
}

func (e *ErrBelowMinID) Error() string {
	return fmt.Sprintf("resolved ID %d for %q is below minimum threshold %d", e.ID, e.Name, e.MinID)
}
