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

package test_utils

import (
	"context"
	"net"
	"testing"

	"github.com/pelicanplatform/pelican/config"
)

// UnresolvableHost is a name under the reserved .invalid TLD (RFC 6761),
// which can never resolve.
const UnresolvableHost = "noserverexists.invalid"

// FailLookupsOf makes connections through the global transport
// (config.GetTransport and the clients built on it) to host fail the way a
// lookup of a nonexistent name does -- "dial tcp: lookup <host>: no such
// host" -- without asking a resolver.  A real lookup depends on the network
// and can take longer than a test is prepared to wait.  Connections to any
// other host are dialed normally.  The real dialer is restored when the test
// ends.
func FailLookupsOf(t *testing.T, host string) {
	t.Helper()
	// Create the transport first: its first use installs the default dialer,
	// which would otherwise replace the one set here.
	config.GetTransport()
	dial := (&net.Dialer{}).DialContext
	config.SetTransportDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, _, err := net.SplitHostPort(addr); err == nil && h == host {
			return nil, &net.OpError{Op: "dial", Net: network,
				Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
		}
		return dial(ctx, network, addr)
	})
	t.Cleanup(func() { config.SetTransportDialer(dial) })
}
