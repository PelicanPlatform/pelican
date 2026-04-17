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

package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestSSRFTransport(disabled bool, allowed, blocked []string) *SSRFTransport {
	return &SSRFTransport{
		disabled:          disabled,
		skipDefaultBlocks: false,
		allowed:           parseCIDRList(allowed, "test-allowed"),
		blocked:           parseCIDRList(blocked, "test-blocked"),
	}
}

func TestSSRFTransport_IsBlocked(t *testing.T) {
	t.Run("DisabledAllowsEverything", func(t *testing.T) {
		st := newTestSSRFTransport(true, nil, nil)
		assert.False(t, st.isBlocked(net.ParseIP("127.0.0.1")))
		assert.False(t, st.isBlocked(net.ParseIP("10.0.0.1")))
		assert.False(t, st.isBlocked(net.ParseIP("8.8.8.8")))
	})

	t.Run("BlocksLoopback", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("127.0.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("127.0.0.2")))
		assert.True(t, st.isBlocked(net.ParseIP("::1")))
	})

	t.Run("BlocksRFC1918", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("10.0.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("10.255.255.255")))
		assert.True(t, st.isBlocked(net.ParseIP("172.16.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("172.31.255.255")))
		assert.True(t, st.isBlocked(net.ParseIP("192.168.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("192.168.255.255")))
	})

	t.Run("BlocksLinkLocal", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("169.254.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("fe80::1")))
	})

	t.Run("BlocksCGN", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("100.64.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("100.127.255.255")))
	})

	t.Run("BlocksDocumentation", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("192.0.2.1")))
		assert.True(t, st.isBlocked(net.ParseIP("198.51.100.1")))
		assert.True(t, st.isBlocked(net.ParseIP("203.0.113.1")))
		assert.True(t, st.isBlocked(net.ParseIP("2001:db8::1")))
	})

	t.Run("BlocksMulticast", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("224.0.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("ff02::1")))
	})

	t.Run("BlocksIPv6UniqueLocal", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("fd00::1")))
	})

	t.Run("AllowsPublicAddresses", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.False(t, st.isBlocked(net.ParseIP("8.8.8.8")))
		assert.False(t, st.isBlocked(net.ParseIP("1.1.1.1")))
		assert.False(t, st.isBlocked(net.ParseIP("93.184.216.34")))
		assert.False(t, st.isBlocked(net.ParseIP("2607:f8b0:4004:800::200e")))
	})

	t.Run("AllowListOverridesBlock", func(t *testing.T) {
		st := newTestSSRFTransport(false, []string{"10.0.0.0/24"}, nil)
		// 10.0.0.1 is normally blocked (RFC 1918) but allowed by override
		assert.False(t, st.isBlocked(net.ParseIP("10.0.0.1")))
		// 10.0.1.1 is still blocked (not in allowed range)
		assert.True(t, st.isBlocked(net.ParseIP("10.0.1.1")))
	})

	t.Run("BlockListAddsNewBlocks", func(t *testing.T) {
		// Block a normally-public range
		st := newTestSSRFTransport(false, nil, []string{"93.184.216.0/24"})
		assert.True(t, st.isBlocked(net.ParseIP("93.184.216.34")))
		// Other public IPs still allowed
		assert.False(t, st.isBlocked(net.ParseIP("8.8.8.8")))
	})

	t.Run("AllowTakesPriorityOverAdditionalBlock", func(t *testing.T) {
		// If the same range is in both allowed and blocked, allowed wins
		st := newTestSSRFTransport(false, []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"})
		assert.False(t, st.isBlocked(net.ParseIP("10.0.0.1")))
	})

	t.Run("BlocksBenchmarking", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		assert.True(t, st.isBlocked(net.ParseIP("198.18.0.1")))
		assert.True(t, st.isBlocked(net.ParseIP("198.19.255.255")))
	})

	t.Run("BlocksIPv4Mapped", func(t *testing.T) {
		st := newTestSSRFTransport(false, nil, nil)
		// ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address for loopback
		assert.True(t, st.isBlocked(net.ParseIP("::ffff:127.0.0.1")))
		// ::ffff:10.0.0.1 is an IPv4-mapped IPv6 address for private
		assert.True(t, st.isBlocked(net.ParseIP("::ffff:10.0.0.1")))
	})
}

func TestParseCIDRList(t *testing.T) {
	t.Run("ValidCIDRs", func(t *testing.T) {
		result := parseCIDRList([]string{"10.0.0.0/8", "192.168.0.0/16"}, "test")
		assert.Len(t, result, 2)
	})

	t.Run("InvalidCIDRsSkipped", func(t *testing.T) {
		result := parseCIDRList([]string{"not-a-cidr", "10.0.0.0/8"}, "test")
		assert.Len(t, result, 1)
	})

	t.Run("EmptyList", func(t *testing.T) {
		result := parseCIDRList(nil, "test")
		assert.Nil(t, result)
	})
}
