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
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

var (
	ssrfTransport     *SSRFTransport
	onceSSRFTransport sync.Once
)

// SSRFTransport is an http.Transport wrapper that prevents server-side request
// forgery (SSRF) by blocking connections to non-publicly-routable IP addresses.
//
// It wraps the standard Pelican transport with a custom dialer that resolves
// the target hostname and checks the resulting IP against a set of blocked and
// allowed CIDR ranges before establishing the connection.
//
// By default, all RFC 1918 private ranges, loopback, link-local, and other
// non-public ranges are blocked.  Administrators can override the policy via:
//
//   - Server.SSRFProtection.Disabled (bool): master switch; when true the dialer
//     passes through to the underlying transport without filtering.
//   - Server.SSRFProtection.SkipDefaultBlocks (bool): when true the built-in
//     list of non-public CIDR ranges is NOT included in the block list.
//   - Server.SSRFProtection.AllowedCIDRs ([]string): CIDRs that should be reachable
//     even though they fall inside a normally-blocked range.
//   - Server.SSRFProtection.BlockedCIDRs ([]string): additional CIDRs to block beyond
//     the built-in non-public ranges.
type SSRFTransport struct {
	// The underlying dialer to use once SSRF checks pass.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// allowed overrides: connections to IPs in these nets are permitted
	// even if they would otherwise be blocked.
	allowed []*net.IPNet

	// additional blocked ranges beyond the built-in non-public set.
	blocked []*net.IPNet

	// Whether SSRF protection is disabled.
	disabled bool

	// Whether the built-in default block list is skipped.
	skipDefaultBlocks bool
}

// builtinBlockedCIDRs lists all non-publicly-routable address ranges.
var builtinBlockedCIDRs = []string{
	// IPv4
	"0.0.0.0/8",          // "This" network (RFC 1122)
	"10.0.0.0/8",         // Private (RFC 1918)
	"100.64.0.0/10",      // Shared address space / CGN (RFC 6598)
	"127.0.0.0/8",        // Loopback (RFC 1122)
	"169.254.0.0/16",     // Link-local (RFC 3927)
	"172.16.0.0/12",      // Private (RFC 1918)
	"192.0.0.0/24",       // IETF protocol assignments (RFC 6890)
	"192.0.2.0/24",       // TEST-NET-1 (RFC 5737)
	"192.88.99.0/24",     // 6to4 relay anycast (RFC 3068)
	"192.168.0.0/16",     // Private (RFC 1918)
	"198.18.0.0/15",      // Benchmarking (RFC 2544)
	"198.51.100.0/24",    // TEST-NET-2 (RFC 5737)
	"203.0.113.0/24",     // TEST-NET-3 (RFC 5737)
	"224.0.0.0/4",        // Multicast (RFC 5771)
	"240.0.0.0/4",        // Reserved (RFC 1112)
	"255.255.255.255/32", // Broadcast

	// IPv6
	"::1/128",       // Loopback
	"::/128",        // Unspecified
	"64:ff9b::/96",  // IPv4/IPv6 translation (RFC 6052)
	"100::/64",      // Discard (RFC 6666)
	"2001:db8::/32", // Documentation (RFC 3849)
	"fc00::/7",      // Unique local (RFC 4193)
	"fe80::/10",     // Link-local (RFC 4291)
	"ff00::/8",      // Multicast (RFC 4291)
}

// mustParseCIDR is a helper that panics on invalid CIDR strings.
// Used only for the compile-time builtinBlockedCIDRs list.
func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid built-in CIDR %q: %v", s, err))
	}
	return ipNet
}

// parseCIDRList parses a slice of CIDR strings, logging warnings for invalid entries.
// We warn instead of fail because I don't want a typo to cause an origin to fail to restart
// after a web-based configuration change.
func parseCIDRList(cidrs []string, label string) []*net.IPNet {
	var result []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warningf("Ignoring invalid CIDR in %s: %q: %v", label, cidr, err)
			continue
		}
		result = append(result, ipNet)
	}
	return result
}

// isBlocked returns true if the given IP should be blocked by SSRF protection.
func (t *SSRFTransport) isBlocked(ip net.IP) bool {
	if t.disabled {
		return false
	}

	// Check allow-list first: if an IP is explicitly allowed, it is never blocked.
	for _, allowNet := range t.allowed {
		if allowNet.Contains(ip) {
			return false
		}
	}

	// Check admin-configured additional blocked ranges.
	for _, blockNet := range t.blocked {
		if blockNet.Contains(ip) {
			return true
		}
	}

	// Check all built-in non-public ranges (unless skipped).
	if !t.skipDefaultBlocks {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return true
		}
		// The Go stdlib helpers don't cover all our ranges (e.g. CGN, benchmarking,
		// documentation nets), so also check the full built-in list.
		for _, cidr := range builtinBlockedCIDRs {
			blockNet := mustParseCIDR(cidr)
			if blockNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// ssrfDialContext resolves the hostname, checks each resulting IP against the
// SSRF policy, and then dials using only a verified-safe address.
func (t *SSRFTransport) ssrfDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.disabled {
		return t.dialContext(ctx, network, addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("SSRF dialer: invalid address %q: %w", addr, err)
	}

	// Resolve the hostname to IP addresses.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("SSRF dialer: DNS resolution failed for %q: %w", host, err)
	}

	// Check every resolved IP; block if any resolves to a non-public address.
	// This prevents DNS rebinding attacks where a hostname has both public and
	// private addresses.
	for _, ipAddr := range ips {
		if t.isBlocked(ipAddr.IP) {
			return nil, fmt.Errorf("SSRF dialer: blocked connection to %s (%s): "+
				"address is not publicly routable", host, ipAddr.IP.String())
		}
	}

	// All IPs are safe; dial the original address so the OS can choose the
	// best route (and respect Happy Eyeballs, etc.).
	return t.dialContext(ctx, network, net.JoinHostPort(host, port))
}

// GetSSRFTransport returns a singleton *SSRFTransport configured from the
// Server.SSRF* parameters.  The returned transport shares TLS configuration
// and connection pooling settings with the default Pelican transport but uses
// a SSRF-safe dialer.
//
// The transport is initialised once; subsequent calls return the same instance.
func GetSSRFTransport() *SSRFTransport {
	onceSSRFTransport.Do(func() {
		setupSSRFTransport()
	})
	return ssrfTransport
}

func setupSSRFTransport() {
	// Ensure the base transport is initialised.
	onceTransport.Do(func() {
		setupTransport()
	})

	disabled := param.Server_SSRFProtection_Disabled.GetBool()
	skipDefaultBlocks := param.Server_SSRFProtection_SkipDefaultBlocks.GetBool()
	allowed := parseCIDRList(param.Server_SSRFProtection_AllowedCIDRs.GetStringSlice(), "Server.SSRFProtection.AllowedCIDRs")
	blocked := parseCIDRList(param.Server_SSRFProtection_BlockedCIDRs.GetStringSlice(), "Server.SSRFProtection.BlockedCIDRs")

	st := &SSRFTransport{
		dialContext:       globalDialContext,
		allowed:           allowed,
		blocked:           blocked,
		disabled:          disabled,
		skipDefaultBlocks: skipDefaultBlocks,
	}

	ssrfTransport = st

	if !disabled {
		log.Infof("SSRF-resistant transport enabled (allowed overrides: %d, additional blocks: %d)",
			len(allowed), len(blocked))
	} else {
		log.Info("SSRF-resistant transport disabled by configuration")
	}
}

// GetSSRFHttpTransport returns an *http.Transport that uses the SSRF-safe dialer.
// It clones the default Pelican transport and replaces the DialContext.
func GetSSRFHttpTransport() *http.Transport {
	ssrf := GetSSRFTransport()
	tr := GetTransport().Clone()
	tr.DialContext = ssrf.ssrfDialContext
	return tr
}

// ResetSSRFTransportForTest resets the SSRF transport singleton so it can be
// re-initialised with different config values in tests.
func ResetSSRFTransportForTest() {
	onceSSRFTransport = sync.Once{}
	ssrfTransport = nil
}
