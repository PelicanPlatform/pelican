//go:build linux

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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const defaultVarlinkTimeout = 10 * time.Second

// SystemdUserDBLookupStrategy uses systemd-userdbd via the varlink protocol.
type SystemdUserDBLookupStrategy struct {
	socketPath string
}

// NewSystemdUserDBLookup creates a new systemd-userdbd lookup strategy.
func NewSystemdUserDBLookup() (*SystemdUserDBLookupStrategy, error) {
	socketPath := "/run/systemd/userdb/io.systemd.UserDatabase"

	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("systemd-userdbd socket not available: %w", err)
	}

	return &SystemdUserDBLookupStrategy{socketPath: socketPath}, nil
}

// ensureTimeout returns a context that has a deadline.  If the
// parent context already carries a deadline the original is returned
// unchanged; otherwise a defaultVarlinkTimeout is applied.
func (s *SystemdUserDBLookupStrategy) ensureTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultVarlinkTimeout)
}

// dial connects to the varlink socket with full context cancellation
// support.  A goroutine watches ctx.Done() and closes the connection
// so that any blocking read or write returns immediately.  The
// returned cleanup function MUST be called (via defer) to stop the
// goroutine and close the connection.
func (s *SystemdUserDBLookupStrategy) dial(ctx context.Context) (net.Conn, func(), error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", s.socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to systemd-userdbd: %w", err)
	}

	// Propagate deadline to the connection so blocking I/O is bounded.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Watch for cancellation in a goroutine.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	cleanup := func() {
		close(done)
		_ = conn.Close()
	}
	return conn, cleanup, nil
}

// wrapErr checks whether the context has been cancelled or expired
// and, if so, returns the context error instead of the raw I/O
// error which is typically "use of closed network connection".
func (s *SystemdUserDBLookupStrategy) wrapErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("varlink call cancelled: %w", ctxErr)
	}
	return err
}

// varlinkRequest represents a varlink method call.
type varlinkRequest struct {
	Method     string                 `json:"method"`
	Parameters map[string]interface{} `json:"parameters"`
	More       bool                   `json:"more,omitempty"`
}

// varlinkResponse represents a varlink method response.
type varlinkResponse struct {
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Continues  bool                   `json:"continues,omitempty"`
}

// LookupUser implements LookupStrategy.
func (s *SystemdUserDBLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	conn, cleanup, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	request := varlinkRequest{
		Method: "io.systemd.UserDatabase.GetUserRecord",
		Parameters: map[string]interface{}{
			"userName": username,
		},
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, s.wrapErr(ctx, fmt.Errorf("failed to send varlink request: %w", err))
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, s.wrapErr(ctx, fmt.Errorf("failed to read varlink response: %w", err))
		}
		return nil, fmt.Errorf("empty varlink response")
	}

	var response varlinkResponse
	if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse varlink response: %w", err)
	}

	if response.Error != "" {
		if response.Error == "io.systemd.UserDatabase.NoRecordFound" {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("varlink error: %s", response.Error)
	}

	record, ok := response.Parameters["record"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid user record in response")
	}

	uid, _ := record["uid"].(float64)
	gid, _ := record["gid"].(float64)
	homeDir, _ := record["homeDirectory"].(string)
	shell, _ := record["shell"].(string)

	groupname := fmt.Sprintf("%d", uint32(gid))

	return &UserInfo{
		UID:       uint32(uid),
		GID:       uint32(gid),
		Username:  username,
		Groupname: groupname,
		HomeDir:   homeDir,
		Shell:     shell,
	}, nil
}

// LookupSecondaryGroups implements LookupStrategy using the
// io.systemd.UserDatabase.GetMemberships varlink method.
// It enumerates all group memberships for the user, looks up each
// group's GID via GetGroupRecord, and filters out the primary GID.
func (s *SystemdUserDBLookupStrategy) LookupSecondaryGroups(ctx context.Context, username string) ([]uint32, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// First, get the primary GID so we can exclude it.
	userInfo, err := s.LookupUser(ctx, username)
	if err != nil {
		return nil, err
	}
	primaryGID := userInfo.GID

	// Open a connection for the GetMemberships call.
	conn, cleanup, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	request := varlinkRequest{
		Method: "io.systemd.UserDatabase.GetMemberships",
		Parameters: map[string]interface{}{
			"userName": username,
			"service":  "",
		},
		More: true,
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, s.wrapErr(ctx, fmt.Errorf("failed to send varlink GetMemberships request: %w", err))
	}

	// Read streaming responses.  The varlink "more" flag indicates
	// additional responses will follow.
	var groupNames []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var response varlinkResponse
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
			return nil, s.wrapErr(ctx, fmt.Errorf("failed to parse varlink GetMemberships response: %w", err))
		}

		if response.Error != "" {
			if response.Error == "io.systemd.UserDatabase.NoRecordFound" {
				break
			}
			return nil, fmt.Errorf("varlink GetMemberships error: %s", response.Error)
		}

		if gn, ok := response.Parameters["groupName"].(string); ok && gn != "" {
			groupNames = append(groupNames, gn)
		}

		if !response.Continues {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, s.wrapErr(ctx, fmt.Errorf("failed reading varlink GetMemberships stream: %w", err))
	}

	// Resolve each group name to a GID, skipping the primary.
	var gids []uint32
	for _, gn := range groupNames {
		gid, err := s.LookupGroup(ctx, gn)
		if err != nil {
			continue // skip groups we can't resolve
		}
		if gid == primaryGID {
			continue
		}
		gids = append(gids, gid)
	}
	return gids, nil
}

// LookupGroup implements LookupStrategy.
func (s *SystemdUserDBLookupStrategy) LookupGroup(ctx context.Context, groupname string) (uint32, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	conn, cleanup, err := s.dial(ctx)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	request := varlinkRequest{
		Method: "io.systemd.UserDatabase.GetGroupRecord",
		Parameters: map[string]interface{}{
			"groupName": groupname,
		},
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return 0, s.wrapErr(ctx, fmt.Errorf("failed to send varlink request: %w", err))
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return 0, s.wrapErr(ctx, fmt.Errorf("failed to read varlink response: %w", err))
		}
		return 0, fmt.Errorf("empty varlink response")
	}

	var response varlinkResponse
	if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
		return 0, fmt.Errorf("failed to parse varlink response: %w", err)
	}

	if response.Error != "" {
		if response.Error == "io.systemd.UserDatabase.NoRecordFound" {
			return 0, &ErrGroupNotFound{Groupname: groupname}
		}
		return 0, fmt.Errorf("varlink error: %s", response.Error)
	}

	record, ok := response.Parameters["record"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid group record in response")
	}

	gid, _ := record["gid"].(float64)
	return uint32(gid), nil
}

// Name implements LookupStrategy.
func (s *SystemdUserDBLookupStrategy) Name() string {
	return "systemd-userdbd-varlink"
}

// trySystemdUserDB attempts to create a systemd-userdbd lookup strategy.
func trySystemdUserDB() (LookupStrategy, error) {
	return NewSystemdUserDBLookup()
}
