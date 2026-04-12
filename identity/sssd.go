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
	"strings"

	"github.com/bbockelm/gosssd"
)

// SSSDLookup resolves users and groups by communicating directly with the
// SSSD NSS responder over its Unix socket.  This avoids CGO/libc NSS.
//
// Because gosssd.Client is not goroutine-safe, SSSDLookup creates a fresh
// connection for each lookup.  The CachedLookup wrapper keeps the number
// of socket round-trips low.
type SSSDLookup struct {
	socketPath string
}

// SSSDOption configures a SSSDLookup.
type SSSDOption func(*SSSDLookup)

// WithSSSDSocketPath overrides the default SSSD NSS socket path.
func WithSSSDSocketPath(path string) SSSDOption {
	return func(s *SSSDLookup) {
		s.socketPath = path
	}
}

// NewSSSDLookup creates a new SSSDLookup.  By default it uses the
// standard socket path (/var/lib/sss/pipes/nss).
func NewSSSDLookup(opts ...SSSDOption) *SSSDLookup {
	s := &SSSDLookup{}
	for _, o := range opts {
		o(s)
	}
	return s
}

// connect returns a connected gosssd.Client.  Caller must close it.
func (s *SSSDLookup) connect(ctx context.Context) (*gosssd.Client, error) {
	var clientOpts []gosssd.ClientOption
	if s.socketPath != "" {
		clientOpts = append(clientOpts, gosssd.WithSocketPath(s.socketPath))
	}
	client := gosssd.NewClient(clientOpts...)
	if err := client.ConnectContext(ctx); err != nil {
		return nil, fmt.Errorf("SSSD connect: %w", err)
	}
	return client, nil
}

// LookupUser implements LookupStrategy.
func (s *SSSDLookup) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	u, err := client.GetUserByName(username)
	if err != nil {
		// gosssd returns "request failed with status: 1" for NOTFOUND
		if strings.Contains(err.Error(), "status: 1") {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("SSSD lookup user %q: %w", username, err)
	}

	var groupname string
	if grp, grpErr := client.GetGroupByGID(u.GID); grpErr == nil {
		groupname = grp.Name
	} else {
		groupname = fmt.Sprintf("%d", u.GID)
	}

	return &UserInfo{
		UID:       u.UID,
		GID:       u.GID,
		Username:  u.Name,
		Groupname: groupname,
		HomeDir:   u.HomeDir,
		Shell:     u.Shell,
	}, nil
}

// LookupSecondaryGroups implements LookupStrategy.
func (s *SSSDLookup) LookupSecondaryGroups(ctx context.Context, username string) ([]uint32, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	gids, err := client.GetGroupsForUser(username)
	if err != nil {
		// gosssd returns "request failed with status: 1" for NOTFOUND
		if strings.Contains(err.Error(), "status: 1") {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("SSSD lookup secondary groups for %q: %w", username, err)
	}
	return gids, nil
}

// LookupGroup implements LookupStrategy.
func (s *SSSDLookup) LookupGroup(ctx context.Context, groupname string) (uint32, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	grp, err := client.GetGroupByName(groupname)
	if err != nil {
		// gosssd returns "request failed with status: 1" for NOTFOUND
		if strings.Contains(err.Error(), "status: 1") {
			return 0, &ErrGroupNotFound{Groupname: groupname}
		}
		return 0, fmt.Errorf("SSSD lookup group %q: %w", groupname, err)
	}
	return grp.GID, nil
}

// Name implements LookupStrategy.
func (s *SSSDLookup) Name() string {
	return "sssd-gosssd"
}

// trySSSD attempts to create an SSSD lookup strategy.
func trySSSD(ctx context.Context) (LookupStrategy, error) { //nolint:unused // called from nss_linux.go
	s := NewSSSDLookup()
	// Verify connectivity
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	client.Close()
	return s, nil
}
