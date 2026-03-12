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
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoNativeLookup_LookupUser(t *testing.T) {
	lookup := NewGoNativeLookup()
	ctx := context.Background()

	t.Run("RootUser", func(t *testing.T) {
		info, err := lookup.LookupUser(ctx, "root")
		require.NoError(t, err)
		assert.Equal(t, uint32(0), info.UID)
		assert.Equal(t, "root", info.Username)
	})

	t.Run("CurrentUser", func(t *testing.T) {
		current, err := user.Current()
		require.NoError(t, err)

		info, err := lookup.LookupUser(ctx, current.Username)
		require.NoError(t, err)

		expectedUid, err := strconv.ParseUint(current.Uid, 10, 32)
		require.NoError(t, err)
		assert.Equal(t, uint32(expectedUid), info.UID)
	})

	t.Run("NonexistentUser", func(t *testing.T) {
		_, err := lookup.LookupUser(ctx, "nonexistent_user_abc123xyz")
		require.Error(t, err)
		var notFound *ErrUserNotFound
		assert.True(t, errors.As(err, &notFound))
	})
}

func TestGoNativeLookup_LookupGroup(t *testing.T) {
	lookup := NewGoNativeLookup()
	ctx := context.Background()

	t.Run("RootGroup", func(t *testing.T) {
		gid, err := lookup.LookupGroup(ctx, "root")
		require.NoError(t, err)
		assert.Equal(t, uint32(0), gid)
	})

	t.Run("NonexistentGroup", func(t *testing.T) {
		_, err := lookup.LookupGroup(ctx, "nonexistent_group_abc123xyz")
		require.Error(t, err)
		var notFound *ErrGroupNotFound
		assert.True(t, errors.As(err, &notFound))
	})
}

func TestGoNativeLookup_ImplementsStrategy(t *testing.T) {
	var _ LookupStrategy = (*GoNativeLookup)(nil)
}

func TestGoNativeLookup_Name(t *testing.T) {
	lookup := NewGoNativeLookup()
	assert.Equal(t, "go-os-user", lookup.Name())
}
