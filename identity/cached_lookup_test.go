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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStrategy is a test double that implements LookupStrategy,
// counts calls, and can return errors.
type mockStrategy struct {
	userCalls  atomic.Int64
	groupCalls atomic.Int64
	userMap    map[string]*UserInfo
	gidMap     map[string]uint32
}

func newMockStrategy() *mockStrategy {
	return &mockStrategy{
		userMap: map[string]*UserInfo{
			"alice": {UID: 1000, GID: 1000, Username: "alice", Groupname: "users"},
			"bob":   {UID: 1001, GID: 1000, Username: "bob", Groupname: "users"},
		},
		gidMap: map[string]uint32{
			"users":  1000,
			"admins": 2000,
		},
	}
}

func (m *mockStrategy) LookupUser(_ context.Context, username string) (*UserInfo, error) {
	m.userCalls.Add(1)
	if info, ok := m.userMap[username]; ok {
		return info, nil
	}
	return nil, &ErrUserNotFound{Username: username}
}

func (m *mockStrategy) LookupGroup(_ context.Context, groupname string) (uint32, error) {
	m.groupCalls.Add(1)
	if gid, ok := m.gidMap[groupname]; ok {
		return gid, nil
	}
	return 0, &ErrGroupNotFound{Groupname: groupname}
}

func (m *mockStrategy) LookupSecondaryGroups(_ context.Context, _ string) ([]uint32, error) {
	return nil, nil
}

func (m *mockStrategy) Name() string {
	return "mock"
}

func TestCachedLookup_PositiveCache(t *testing.T) {
	mock := newMockStrategy()
	cached := NewCachedLookup(mock)

	// First call should hit the inner lookup
	uid, err := cached.UidForUser("alice")
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), uid)
	assert.Equal(t, int64(1), mock.userCalls.Load())

	// Second call should be cached
	uid, err = cached.UidForUser("alice")
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), uid)
	assert.Equal(t, int64(1), mock.userCalls.Load(), "expected cached result, but inner was called again")

	// Different user should trigger another lookup
	uid, err = cached.UidForUser("bob")
	require.NoError(t, err)
	assert.Equal(t, uint32(1001), uid)
	assert.Equal(t, int64(2), mock.userCalls.Load())
}

func TestCachedLookup_NegativeCache(t *testing.T) {
	mock := newMockStrategy()
	cached := NewCachedLookupWithTTL(mock, 5*time.Minute, 100*time.Millisecond)

	// First call: miss
	_, err := cached.UidForUser("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(1), mock.userCalls.Load())

	// Second call (within negative TTL): should be cached
	_, err = cached.UidForUser("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(1), mock.userCalls.Load(), "expected negative cache hit")
}

func TestCachedLookup_GidCache(t *testing.T) {
	mock := newMockStrategy()
	cached := NewCachedLookup(mock)

	// Positive lookup
	gid, err := cached.GidForGroup("users")
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), gid)
	assert.Equal(t, int64(1), mock.groupCalls.Load())

	// Cached
	gid, err = cached.GidForGroup("users")
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), gid)
	assert.Equal(t, int64(1), mock.groupCalls.Load())

	// Negative lookup
	_, err = cached.GidForGroup("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(2), mock.groupCalls.Load())
}

// Compile-time interface check
var _ Lookup = (*CachedLookup)(nil)

func TestCachedLookup_MinID_RejectsRoot(t *testing.T) {
	// Strategy that resolves "root" to UID 0 / GID 0
	mock := &mockStrategy{
		userMap: map[string]*UserInfo{
			"root": {UID: 0, GID: 0, Username: "root", Groupname: "root"},
		},
		gidMap: map[string]uint32{
			"root": 0,
		},
	}
	cached := NewCachedLookup(mock) // default minID = 1000

	_, err := cached.UidForUser("root")
	require.Error(t, err)
	var belowMin *ErrBelowMinID
	require.ErrorAs(t, err, &belowMin)
	assert.Equal(t, uint32(0), belowMin.ID)
	assert.Equal(t, uint32(1000), belowMin.MinID)
	assert.Equal(t, "root", belowMin.Name)

	_, err = cached.GidForGroup("root")
	require.Error(t, err)
	require.ErrorAs(t, err, &belowMin)
	assert.Equal(t, uint32(0), belowMin.ID)
}

func TestCachedLookup_MinID_RejectsSystemAccounts(t *testing.T) {
	// Typical system accounts have UIDs in the 1-999 range
	mock := &mockStrategy{
		userMap: map[string]*UserInfo{
			"daemon":  {UID: 1, GID: 1, Username: "daemon"},
			"nobody":  {UID: 65534, GID: 65534, Username: "nobody"},
			"sshd":    {UID: 74, GID: 74, Username: "sshd"},
			"regular": {UID: 1000, GID: 1000, Username: "regular"},
		},
		gidMap: map[string]uint32{
			"daemon":  1,
			"nogroup": 65534,
		},
	}
	cached := NewCachedLookup(mock)

	// System accounts below 1000 should be rejected
	for _, name := range []string{"daemon", "sshd"} {
		_, err := cached.UidForUser(name)
		require.Error(t, err, "expected UID for %q to be rejected", name)
		var belowMin *ErrBelowMinID
		assert.ErrorAs(t, err, &belowMin)
	}

	// GIDs below 1000 should be rejected
	_, err := cached.GidForGroup("daemon")
	require.Error(t, err)
	var belowMin *ErrBelowMinID
	assert.ErrorAs(t, err, &belowMin)

	// UID 1000 is exactly at the threshold — should be allowed
	uid, err := cached.UidForUser("regular")
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), uid)

	// UID 65534 (nobody) is above 1000 — should be allowed
	uid, err = cached.UidForUser("nobody")
	require.NoError(t, err)
	assert.Equal(t, uint32(65534), uid)
}

func TestCachedLookup_MinID_CustomThreshold(t *testing.T) {
	mock := &mockStrategy{
		userMap: map[string]*UserInfo{
			"svc": {UID: 500, GID: 500, Username: "svc"},
		},
		gidMap: map[string]uint32{
			"svcgrp": 500,
		},
	}

	// With a lower threshold, UID 500 should be accepted
	cached := NewCachedLookup(mock, WithMinID(500))
	uid, err := cached.UidForUser("svc")
	require.NoError(t, err)
	assert.Equal(t, uint32(500), uid)

	gid, err := cached.GidForGroup("svcgrp")
	require.NoError(t, err)
	assert.Equal(t, uint32(500), gid)

	// With a higher threshold, UID 500 should be rejected
	cached2 := NewCachedLookup(mock, WithMinID(501))
	_, err = cached2.UidForUser("svc")
	require.Error(t, err)
	var belowMin *ErrBelowMinID
	assert.ErrorAs(t, err, &belowMin)

	_, err = cached2.GidForGroup("svcgrp")
	require.Error(t, err)
	assert.ErrorAs(t, err, &belowMin)
}

func TestCachedLookup_MinID_ZeroDisablesGuard(t *testing.T) {
	mock := &mockStrategy{
		userMap: map[string]*UserInfo{
			"root": {UID: 0, GID: 0, Username: "root", Groupname: "root"},
		},
		gidMap: map[string]uint32{
			"root": 0,
		},
	}

	// WithMinID(0) disables the guard entirely
	cached := NewCachedLookup(mock, WithMinID(0))
	uid, err := cached.UidForUser("root")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), uid)

	gid, err := cached.GidForGroup("root")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), gid)
}

func TestCachedLookup_NegativeCache_GidForGroup(t *testing.T) {
	mock := newMockStrategy()
	cached := NewCachedLookupWithTTL(mock, 5*time.Minute, 100*time.Millisecond)

	// First call: miss
	_, err := cached.GidForGroup("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(1), mock.groupCalls.Load())

	// Second call (within negative TTL): should be cached
	_, err = cached.GidForGroup("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(1), mock.groupCalls.Load(), "expected negative cache hit for group")
}

// mockStrategyWithSecondary extends mockStrategy with secondary group support.
type mockStrategyWithSecondary struct {
	mockStrategy
	secondaryCalls atomic.Int64
	secondaryMap   map[string][]uint32
}

func (m *mockStrategyWithSecondary) LookupSecondaryGroups(_ context.Context, username string) ([]uint32, error) {
	m.secondaryCalls.Add(1)
	if gids, ok := m.secondaryMap[username]; ok {
		return gids, nil
	}
	return nil, &ErrUserNotFound{Username: username}
}

func TestCachedLookup_SecondaryCache(t *testing.T) {
	mock := &mockStrategyWithSecondary{
		mockStrategy: *newMockStrategy(),
		secondaryMap: map[string][]uint32{
			"alice": {2000, 3000},
		},
	}
	cached := NewCachedLookup(mock)

	// Positive hit
	gids, err := cached.SecondaryGidsForUser("alice")
	require.NoError(t, err)
	assert.Equal(t, []uint32{2000, 3000}, gids)
	assert.Equal(t, int64(1), mock.secondaryCalls.Load())

	// Cached
	gids, err = cached.SecondaryGidsForUser("alice")
	require.NoError(t, err)
	assert.Equal(t, []uint32{2000, 3000}, gids)
	assert.Equal(t, int64(1), mock.secondaryCalls.Load(), "expected cached secondary result")

	// Negative hit
	_, err = cached.SecondaryGidsForUser("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(2), mock.secondaryCalls.Load())

	// Negative cached
	_, err = cached.SecondaryGidsForUser("nonexistent")
	require.Error(t, err)
	assert.Equal(t, int64(2), mock.secondaryCalls.Load(), "expected negative cache hit for secondary")
}
