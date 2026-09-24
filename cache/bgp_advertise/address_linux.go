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
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// AddressManager manages the presence of the anycast service addresses on a
// local network device using netlink (Linux only).
type AddressManager struct {
	device string
	mode   ManageMode
	specs  []string // normalized CIDRs to manage
	added  []string // CIDRs to remove on Cleanup
}

// NewAddressManager validates the configuration and resolves the device.  It
// performs no changes to the system (call Apply for that).  When management is a
// no-op (mode off or no addresses), it returns a manager whose Apply/Cleanup do
// nothing.
func NewAddressManager(cfg AddressConfig) (*AddressManager, error) {
	if cfg.Mode == ManageOff || len(cfg.Addresses) == 0 {
		return &AddressManager{mode: ManageOff}, nil
	}

	specs := make([]string, 0, len(cfg.Addresses))
	for _, a := range cfg.Addresses {
		spec, err := normalizeAddrSpec(a)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}

	device := cfg.Device
	if device == "" {
		detected, err := detectEgressDevice(cfg.RouteHintIP)
		if err != nil {
			return nil, errors.Wrap(err, "could not determine the network device for anycast addresses; "+
				"set Cache.Anycast.Device explicitly")
		}
		device = detected
		log.WithField("device", device).Debug("Auto-detected network device for anycast addresses")
	}

	return &AddressManager{device: device, mode: cfg.Mode, specs: specs}, nil
}

// Device returns the resolved network device name.
func (m *AddressManager) Device() string { return m.device }

// detectEgressDevice asks the kernel which interface would be used to reach dst
// (typically the director) and returns its name.
func detectEgressDevice(dst net.IP) (string, error) {
	if dst == nil {
		return "", errors.New("no route-hint IP available to detect the egress device")
	}
	routes, err := netlink.RouteGet(dst)
	if err != nil {
		return "", errors.Wrapf(err, "kernel route lookup for %s failed", dst)
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", errors.Errorf("no route to %s", dst)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", errors.Wrapf(err, "could not resolve interface index %d", routes[0].LinkIndex)
	}
	return link.Attrs().Name, nil
}

// addrPresent reports whether addr is already configured on link.
func addrPresent(link netlink.Link, addr *netlink.Addr) (bool, error) {
	family := netlink.FAMILY_V4
	if addr.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	existing, err := netlink.AddrList(link, family)
	if err != nil {
		return false, errors.Wrap(err, "failed to list device addresses")
	}
	for _, e := range existing {
		if e.IPNet != nil && e.IPNet.IP.Equal(addr.IPNet.IP) {
			return true, nil
		}
	}
	return false, nil
}

// Apply adds the configured anycast addresses to the device according to the
// management mode, recording which addresses must be removed on Cleanup.
func (m *AddressManager) Apply() error {
	if m.mode == ManageOff || len(m.specs) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(m.device)
	if err != nil {
		return errors.Wrapf(err, "anycast network device %q not found", m.device)
	}

	for _, spec := range m.specs {
		addr, err := netlink.ParseAddr(spec)
		if err != nil {
			return errors.Wrapf(err, "invalid anycast address %q", spec)
		}
		present, err := addrPresent(link, addr)
		if err != nil {
			return err
		}
		add, removeOnCleanup := decideAddress(m.mode, present)
		if add && !present {
			// AddrReplace is idempotent and avoids EEXIST if a concurrent actor
			// added the address between the presence check and now.
			if err := netlink.AddrReplace(link, addr); err != nil {
				return errors.Wrapf(err, "failed to add anycast address %s to %s", spec, m.device)
			}
			log.WithField("address", spec).WithField("device", m.device).Info("Added anycast address to device")
		}
		if removeOnCleanup {
			m.added = append(m.added, spec)
		}
	}
	return nil
}

// Cleanup removes the anycast addresses that Apply recorded for removal.  It is
// safe to call when nothing was added.
func (m *AddressManager) Cleanup() error {
	if len(m.added) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(m.device)
	if err != nil {
		return errors.Wrapf(err, "anycast network device %q not found during cleanup", m.device)
	}
	var firstErr error
	for _, spec := range m.added {
		addr, err := netlink.ParseAddr(spec)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := netlink.AddrDel(link, addr); err != nil {
			log.WithError(err).WithField("address", spec).Warn("Failed to remove anycast address from device")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		log.WithField("address", spec).WithField("device", m.device).Info("Removed anycast address from device")
	}
	m.added = nil
	return firstErr
}
