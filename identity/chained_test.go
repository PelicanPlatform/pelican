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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failStrategy always returns an error for every lookup.
type failStrategy struct {
	name string
}

func (f *failStrategy) LookupUser(_ context.Context, username string) (*UserInfo, error) {
	return nil, &ErrUserNotFound{Username: username}
}

func (f *failStrategy) LookupGroup(_ context.Context, groupname string) (uint32, error) {
	return 0, &ErrGroupNotFound{Groupname: groupname}
}

func (f *failStrategy) LookupSecondaryGroups(_ context.Context, _ string) ([]uint32, error) {
	return nil, nil
}

func (f *failStrategy) Name() string {
	return f.name
}

// fixedStrategy returns a fixed user / GID for any lookup.
type fixedStrategy struct {
	name string
	info *UserInfo
	gid  uint32
}

func (s *fixedStrategy) LookupUser(_ context.Context, _ string) (*UserInfo, error) {
	return s.info, nil
}

func (s *fixedStrategy) LookupGroup(_ context.Context, _ string) (uint32, error) {
	return s.gid, nil
}

func (s *fixedStrategy) LookupSecondaryGroups(_ context.Context, _ string) ([]uint32, error) {
	return nil, nil
}

func (s *fixedStrategy) Name() string {
	return s.name
}

func TestChainedLookupStrategy_FallsThrough(t *testing.T) {
	ctx := context.Background()

	chain := &ChainedLookupStrategy{
		strategies: []LookupStrategy{
			&failStrategy{name: "fail1"},
			&fixedStrategy{
				name: "fixed",
				info: &UserInfo{UID: 42, GID: 42, Username: "testuser"},
				gid:  42,
			},
		},
	}

	info, err := chain.LookupUser(ctx, "testuser")
	require.NoError(t, err)
	assert.Equal(t, uint32(42), info.UID)

	gid, err := chain.LookupGroup(ctx, "testgroup")
	require.NoError(t, err)
	assert.Equal(t, uint32(42), gid)
}

func TestChainedLookupStrategy_AllFail(t *testing.T) {
	ctx := context.Background()

	chain := &ChainedLookupStrategy{
		strategies: []LookupStrategy{
			&failStrategy{name: "fail1"},
			&failStrategy{name: "fail2"},
		},
	}

	_, err := chain.LookupUser(ctx, "nobody")
	require.Error(t, err)
	var notFound *ErrUserNotFound
	assert.True(t, errors.As(err, &notFound))

	_, err = chain.LookupGroup(ctx, "nogroup")
	require.Error(t, err)
	var gNotFound *ErrGroupNotFound
	assert.True(t, errors.As(err, &gNotFound))
}

func TestChainedLookupStrategy_FirstWins(t *testing.T) {
	ctx := context.Background()

	chain := &ChainedLookupStrategy{
		strategies: []LookupStrategy{
			&fixedStrategy{
				name: "first",
				info: &UserInfo{UID: 1, GID: 1, Username: "first"},
				gid:  1,
			},
			&fixedStrategy{
				name: "second",
				info: &UserInfo{UID: 2, GID: 2, Username: "second"},
				gid:  2,
			},
		},
	}

	info, err := chain.LookupUser(ctx, "any")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), info.UID, "first strategy should win")
}

func TestChainedLookupStrategy_Name(t *testing.T) {
	chain := &ChainedLookupStrategy{
		strategies: []LookupStrategy{
			&failStrategy{name: "a"},
			&failStrategy{name: "b"},
		},
	}
	assert.Equal(t, "chained:a,b", chain.Name())

	empty := &ChainedLookupStrategy{}
	assert.Equal(t, "chained-empty", empty.Name())
}
