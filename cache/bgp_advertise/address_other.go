//go:build !linux

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

import "github.com/pkg/errors"

// AddressManager is a no-op on non-Linux platforms, where local address
// management via netlink is unavailable.
type AddressManager struct{}

// NewAddressManager returns a no-op manager when address management is disabled
// or no addresses are configured.  If management is actually requested, it
// returns an error explaining that the feature requires Linux.
func NewAddressManager(cfg AddressConfig) (*AddressManager, error) {
	if cfg.Mode == ManageOff || len(cfg.Addresses) == 0 {
		return &AddressManager{}, nil
	}
	return nil, errors.New("anycast local address management is only supported on Linux; " +
		"set Cache.Anycast.AddressManagement=off and manage the addresses out of band")
}

// Device returns the empty string on non-Linux platforms.
func (m *AddressManager) Device() string { return "" }

// Apply is a no-op on non-Linux platforms.
func (m *AddressManager) Apply() error { return nil }

// Cleanup is a no-op on non-Linux platforms.
func (m *AddressManager) Cleanup() error { return nil }
