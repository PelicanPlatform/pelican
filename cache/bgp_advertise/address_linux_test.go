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

package bgp_advertise

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// loopback is used as a harmless device for address add/remove tests; the
// TEST-NET-1 (192.0.2.0/24, RFC 5737) range is reserved for documentation/tests.
const (
	testDevice = "lo"
	testAddrV4 = "192.0.2.123"
)

// requireNetAdmin skips the test unless the process can modify interface
// addresses (CAP_NET_ADMIN).  It probes by attempting to add and immediately
// remove a test address on the loopback device; a permission error -> skip.
func requireNetAdmin(t *testing.T) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(testDevice)
	if err != nil {
		t.Skipf("loopback device %q not available: %v", testDevice, err)
	}
	probe, err := netlink.ParseAddr("192.0.2.250/32")
	require.NoError(t, err)
	if err := netlink.AddrAdd(link, probe); err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("insufficient privileges (CAP_NET_ADMIN) to manage addresses: %v", err)
		}
		// Some environments disallow address changes entirely; treat as skip.
		t.Skipf("cannot manage addresses on %q in this environment: %v", testDevice, err)
	}
	_ = netlink.AddrDel(link, probe)
	return link
}

// addrOnLink reports whether ip is currently configured on the link.
func addrOnLink(t *testing.T, link netlink.Link, ip string) bool {
	t.Helper()
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	require.NoError(t, err)
	target := net.ParseIP(ip)
	for _, a := range addrs {
		if a.IPNet != nil && a.IPNet.IP.Equal(target) {
			return true
		}
	}
	return false
}

// TestAddressManager_AutoAddsAndRemoves verifies the default "auto" mode adds an
// absent address and removes it on cleanup.
func TestAddressManager_AutoAddsAndRemoves(t *testing.T) {
	link := requireNetAdmin(t)
	t.Cleanup(func() {
		if a, err := netlink.ParseAddr(testAddrV4 + "/32"); err == nil {
			_ = netlink.AddrDel(link, a) // best-effort safety net
		}
	})

	require.False(t, addrOnLink(t, link, testAddrV4), "test address should not be present before the test")

	m, err := NewAddressManager(AddressConfig{
		Addresses: []string{testAddrV4},
		Device:    testDevice,
		Mode:      ManageAuto,
	})
	require.NoError(t, err)

	require.NoError(t, m.Apply())
	assert.True(t, addrOnLink(t, link, testAddrV4), "auto mode should add the absent address")

	require.NoError(t, m.Cleanup())
	assert.False(t, addrOnLink(t, link, testAddrV4), "auto mode should remove the address it added")
}

// TestAddressManager_AutoLeavesPreexisting verifies that in "auto" mode an
// address already present at startup is neither (re)added nor removed.
func TestAddressManager_AutoLeavesPreexisting(t *testing.T) {
	link := requireNetAdmin(t)

	addr, err := netlink.ParseAddr(testAddrV4 + "/32")
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(link, addr))
	t.Cleanup(func() { _ = netlink.AddrDel(link, addr) })

	m, err := NewAddressManager(AddressConfig{
		Addresses: []string{testAddrV4},
		Device:    testDevice,
		Mode:      ManageAuto,
	})
	require.NoError(t, err)
	require.NoError(t, m.Apply())
	require.NoError(t, m.Cleanup())

	assert.True(t, addrOnLink(t, link, testAddrV4),
		"auto mode must not remove an address that pre-existed at startup")
}

// TestAddressManager_OnAlwaysRemoves verifies that "on" mode removes the address
// on cleanup even though it pre-existed at startup.
func TestAddressManager_OnAlwaysRemoves(t *testing.T) {
	link := requireNetAdmin(t)

	addr, err := netlink.ParseAddr(testAddrV4 + "/32")
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(link, addr))
	t.Cleanup(func() { _ = netlink.AddrDel(link, addr) })

	m, err := NewAddressManager(AddressConfig{
		Addresses: []string{testAddrV4},
		Device:    testDevice,
		Mode:      ManageOn,
	})
	require.NoError(t, err)
	require.NoError(t, m.Apply())
	require.NoError(t, m.Cleanup())

	assert.False(t, addrOnLink(t, link, testAddrV4),
		"on mode should always remove the address on cleanup")
}

// TestDetectEgressDevice checks that the device routing to the loopback address
// is the loopback interface -- a deterministic, network-independent assertion.
func TestDetectEgressDevice(t *testing.T) {
	if _, err := netlink.LinkByName(testDevice); err != nil {
		t.Skipf("loopback device not available: %v", err)
	}
	dev, err := detectEgressDevice(net.ParseIP("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, testDevice, dev)
}

// TestNewAddressManager_AutoDetectsDevice verifies the device is auto-detected
// from the route-hint IP when none is configured.
func TestNewAddressManager_AutoDetectsDevice(t *testing.T) {
	if _, err := netlink.LinkByName(testDevice); err != nil {
		t.Skipf("loopback device not available: %v", err)
	}
	m, err := NewAddressManager(AddressConfig{
		Addresses:   []string{testAddrV4},
		RouteHintIP: net.ParseIP("127.0.0.1"),
		Mode:        ManageAuto,
	})
	require.NoError(t, err)
	assert.Equal(t, testDevice, m.Device())
}
