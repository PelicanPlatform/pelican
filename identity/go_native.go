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
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

// GoNativeLookup resolves users and groups using the Go standard library
// (os/user).  With CGO enabled this calls getpwnam/getgrnam via libc;
// without CGO it falls back to parsing /etc/passwd and /etc/group.
type GoNativeLookup struct{}

// NewGoNativeLookup creates a new GoNativeLookup.
func NewGoNativeLookup() *GoNativeLookup {
	return &GoNativeLookup{}
}

// LookupUser implements LookupStrategy.
func (g *GoNativeLookup) LookupUser(_ context.Context, username string) (*UserInfo, error) {
	u, err := user.Lookup(username)
	if err != nil {
		var unknownUserErr user.UnknownUserError
		if errors.As(err, &unknownUserErr) {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("failed to lookup user %q: %w", username, err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UID %q for user %q: %w", u.Uid, username, err)
	}

	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GID %q for user %q: %w", u.Gid, username, err)
	}

	var groupname string
	if grp, grpErr := user.LookupGroupId(u.Gid); grpErr == nil {
		groupname = grp.Name
	} else {
		groupname = u.Gid
	}

	return &UserInfo{
		UID:       uint32(uid),
		GID:       uint32(gid),
		Username:  u.Username,
		Groupname: groupname,
		HomeDir:   u.HomeDir,
	}, nil
}

// LookupSecondaryGroups implements LookupStrategy.
func (g *GoNativeLookup) LookupSecondaryGroups(_ context.Context, username string) ([]uint32, error) {
	u, err := user.Lookup(username)
	if err != nil {
		var unknownUserErr user.UnknownUserError
		if errors.As(err, &unknownUserErr) {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("failed to lookup user %q: %w", username, err)
	}

	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("failed to get group IDs for user %q: %w", username, err)
	}

	primaryGID, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse primary GID %q for user %q: %w", u.Gid, username, err)
	}

	var gids []uint32
	for _, gidStr := range groupIDs {
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			continue
		}
		if uint32(gid) == uint32(primaryGID) {
			continue
		}
		gids = append(gids, uint32(gid))
	}
	return gids, nil
}

// LookupGroup implements LookupStrategy.
func (g *GoNativeLookup) LookupGroup(_ context.Context, groupname string) (uint32, error) {
	grp, err := user.LookupGroup(groupname)
	if err != nil {
		var unknownGroupErr user.UnknownGroupError
		if errors.As(err, &unknownGroupErr) {
			return 0, &ErrGroupNotFound{Groupname: groupname}
		}
		return 0, fmt.Errorf("failed to lookup group %q: %w", groupname, err)
	}

	gid, err := strconv.ParseUint(grp.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse GID %q for group %q: %w", grp.Gid, groupname, err)
	}

	return uint32(gid), nil
}

// Name implements LookupStrategy.
func (g *GoNativeLookup) Name() string {
	return "go-os-user"
}

// tryGoFallback creates a GoNativeLookup (always succeeds).
func tryGoFallback() (LookupStrategy, error) {
	return NewGoNativeLookup(), nil
}
