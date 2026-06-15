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
	"context"
	"crypto/tls"
	"net"
	"net/url"

	"github.com/pkg/errors"
)

// VerifyCertSAN dials a TLS connection to probeURL and verifies that the
// certificate presented by the server lists expectedSAN as a Subject Alternative
// Name (honoring wildcard SANs).
//
// IMPORTANT: probeURL must be the cache's OWN external URL, not the anycast
// hostname.  Probing the anycast hostname could route to a completely different
// cache, so it cannot tell us whether *this* host is serving the right
// certificate.  The probe deliberately does not verify the certificate's trust
// chain -- it only cares whether the served certificate covers the anycast name.
func VerifyCertSAN(ctx context.Context, probeURL, expectedSAN string) error {
	if probeURL == "" {
		return errors.New("no probe URL configured")
	}
	if expectedSAN == "" {
		return errors.New("no expected SAN configured")
	}

	u, err := url.Parse(probeURL)
	if err != nil {
		return errors.Wrapf(err, "could not parse probe URL %q", probeURL)
	}
	host := u.Hostname()
	if host == "" {
		return errors.Errorf("probe URL %q has no host", probeURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	dialer := &tls.Dialer{
		Config: &tls.Config{
			// We inspect the SAN ourselves; we do not require the cert to chain
			// to a trusted CA for the purpose of this check.
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.Wrapf(err, "failed to TLS-dial probe URL %q", addr)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("probe connection is not a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return errors.Errorf("no certificate presented by %q", addr)
	}
	leaf := certs[0]
	// VerifyHostname matches against the certificate's DNS SANs (including
	// wildcards) and returns nil when expectedSAN is covered.
	if err := leaf.VerifyHostname(expectedSAN); err != nil {
		return errors.Wrapf(err, "certificate served by %q does not cover anycast hostname %q (DNS SANs: %v)",
			addr, expectedSAN, leaf.DNSNames)
	}
	return nil
}
