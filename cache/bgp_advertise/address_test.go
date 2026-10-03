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

package bgp_advertise

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseManageMode(t *testing.T) {
	cases := map[string]ManageMode{
		"":     ManageAuto,
		"auto": ManageAuto,
		"AUTO": ManageAuto,
		" on ": ManageOn,
		"On":   ManageOn,
		"off":  ManageOff,
		"OFF":  ManageOff,
	}
	for in, want := range cases {
		got, err := ParseManageMode(in)
		require.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}

	_, err := ParseManageMode("sometimes")
	assert.Error(t, err)
}

func TestDecideAddress(t *testing.T) {
	cases := []struct {
		mode       ManageMode
		present    bool
		wantAdd    bool
		wantRemove bool
	}{
		{ManageOff, false, false, false},
		{ManageOff, true, false, false},
		{ManageOn, false, true, true},
		{ManageOn, true, true, true}, // always ensure present and always remove
		{ManageAuto, false, true, true},
		{ManageAuto, true, false, false}, // pre-existing: leave it alone
	}
	for _, c := range cases {
		add, remove := decideAddress(c.mode, c.present)
		assert.Equal(t, c.wantAdd, add, "mode=%s present=%v add", c.mode, c.present)
		assert.Equal(t, c.wantRemove, remove, "mode=%s present=%v remove", c.mode, c.present)
	}
}

func TestNormalizeAddrSpec(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":     "192.0.2.1/32",
		"192.0.2.0/24":  "192.0.2.0/24",
		"2001:db8::1":   "2001:db8::1/128",
		"2001:db8::/64": "2001:db8::/64",
		" 192.0.2.5 ":   "192.0.2.5/32",
	}
	for in, want := range cases {
		got, err := normalizeAddrSpec(in)
		require.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}

	for _, bad := range []string{"", "not-an-ip", "192.0.2.0/99", "::/300"} {
		_, err := normalizeAddrSpec(bad)
		assert.Error(t, err, "input %q should be invalid", bad)
	}
}

// TestNewAddressManager_NoopWhenDisabled verifies that a disabled / empty
// configuration yields a manager whose Apply/Cleanup are safe no-ops on every
// platform (no netlink, no privileges required).
func TestNewAddressManager_NoopWhenDisabled(t *testing.T) {
	t.Run("mode-off", func(t *testing.T) {
		m, err := NewAddressManager(AddressConfig{Addresses: []string{"192.0.2.1"}, Mode: ManageOff})
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.NoError(t, m.Apply())
		assert.NoError(t, m.Cleanup())
	})

	t.Run("no-addresses", func(t *testing.T) {
		m, err := NewAddressManager(AddressConfig{Mode: ManageAuto})
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.NoError(t, m.Apply())
		assert.NoError(t, m.Cleanup())
	})
}
