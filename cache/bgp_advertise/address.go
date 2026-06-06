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
	"net"
	"strings"

	"github.com/pkg/errors"
)

// ManageMode controls whether Pelican adds/removes the anycast IP addresses on a
// local network device.
type ManageMode string

const (
	// ManageAuto adds an address only if it is not already present at startup,
	// and removes (on shutdown) only the addresses Pelican itself added.
	ManageAuto ManageMode = "auto"
	// ManageOn always adds the addresses at startup and always removes them on shutdown.
	ManageOn ManageMode = "on"
	// ManageOff never touches the local addresses.
	ManageOff ManageMode = "off"
)

// ParseManageMode parses the Cache.Anycast.AddressManagement value.  An empty
// string defaults to ManageAuto.
func ParseManageMode(s string) (ManageMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ManageAuto, nil
	case "on":
		return ManageOn, nil
	case "off":
		return ManageOff, nil
	default:
		return "", errors.Errorf("invalid address management mode %q (want one of: on, off, auto)", s)
	}
}

// AddressConfig configures binding of the anycast service addresses onto a local
// network device.
type AddressConfig struct {
	// Addresses are the anycast IPs to bind (bare IP, or IP with prefix length).
	Addresses []string
	// Device is the network interface to manage; auto-detected from RouteHintIP when empty.
	Device string
	// RouteHintIP is a destination (typically the director's IP) used to determine
	// the egress device when Device is empty.
	RouteHintIP net.IP
	// Mode selects on/off/auto behavior.
	Mode ManageMode
}

// decideAddress reports, for a single address, whether it should be added now and
// whether it should be removed on cleanup, given the management mode and whether
// the address is already present on the device at startup.
//
//	off  -> never add, never remove
//	on   -> always ensure present, always remove on cleanup
//	auto -> add (and later remove) only if it was absent at startup; an address
//	        that was already present is left untouched on both ends
func decideAddress(mode ManageMode, alreadyPresent bool) (add bool, removeOnCleanup bool) {
	switch mode {
	case ManageOff:
		return false, false
	case ManageOn:
		return true, true
	default: // ManageAuto
		if alreadyPresent {
			return false, false
		}
		return true, true
	}
}

// normalizeAddrSpec turns a bare IP into a host-route CIDR (/32 for IPv4, /128
// for IPv6) and validates an IP/prefix spec, returning the canonical CIDR string.
func normalizeAddrSpec(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty anycast address")
	}
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return "", errors.Wrapf(err, "invalid anycast address %q", s)
		}
		return s, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", errors.Errorf("invalid anycast IP %q", s)
	}
	if ip.To4() != nil {
		return s + "/32", nil
	}
	return s + "/128", nil
}
