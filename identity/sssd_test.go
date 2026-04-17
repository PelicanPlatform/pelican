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
	"os"
	"testing"

	"github.com/bbockelm/gosssd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSSDLookup_ImplementsStrategy(t *testing.T) {
	var _ LookupStrategy = (*SSSDLookup)(nil)
}

func TestSSSDLookup_NoSocket(t *testing.T) {
	// Use a non-existent socket path so Connect fails
	lookup := NewSSSDLookup(WithSSSDSocketPath("/tmp/nonexistent-sssd-socket"))
	ctx := context.Background()

	_, err := lookup.LookupUser(ctx, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSSD connect")

	_, err = lookup.LookupGroup(ctx, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSSD connect")
}

func TestSSSDLookup_WithSocketPath(t *testing.T) {
	customPath := "/tmp/custom-sssd-socket"
	lookup := NewSSSDLookup(WithSSSDSocketPath(customPath))
	assert.Equal(t, customPath, lookup.socketPath)
}

// TestSSSDLookup_Integration runs only when the SSSD NSS socket is present.
func TestSSSDLookup_Integration(t *testing.T) {
	info, err := os.Stat(gosssd.DefaultNSSSocketPath)
	if err != nil || info.Mode().Type()&os.ModeSocket == 0 {
		t.Skip("SSSD NSS socket not available")
	}

	lookup := NewSSSDLookup()
	ctx := context.Background()

	t.Run("RootUser", func(t *testing.T) {
		info, err := lookup.LookupUser(ctx, "root")
		require.NoError(t, err)
		assert.Equal(t, uint32(0), info.UID)
	})

	t.Run("RootGroup", func(t *testing.T) {
		gid, err := lookup.LookupGroup(ctx, "root")
		require.NoError(t, err)
		assert.Equal(t, uint32(0), gid)
	})

	t.Run("NonexistentUser", func(t *testing.T) {
		_, err := lookup.LookupUser(ctx, "nonexistent_user_abc123xyz")
		assert.Error(t, err)
	})

	t.Run("NonexistentGroup", func(t *testing.T) {
		_, err := lookup.LookupGroup(ctx, "nonexistent_group_abc123xyz")
		assert.Error(t, err)
	})
}
