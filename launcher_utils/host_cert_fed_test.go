//go:build !windows

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

package launcher_utils_test

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry/registry_client"
	"github.com/pelicanplatform/pelican/server_structs"
)

// TestOriginObtainsFederationCertificate is an end-to-end check that an origin,
// running in a federation whose registry acts as a CA (the default), swaps its
// temporary self-signed TLS certificate for a real, federation-issued one — with
// no operator configuration. It exercises the full path: registry CA bootstrap,
// federation-metadata ca_endpoint discovery, the CSR-bound JWT request signed by
// the origin's registered key, issuance, install, and trust-chain verification.
func TestOriginObtainsFederationCertificate(t *testing.T) {
	// Brings up origin + registry in-process. Registry.DisableCA defaults false,
	// so the registry bootstraps the federation CA; RequireOriginApproval defaults
	// false, so the origin's Pending registration may obtain a certificate.
	fed := fed_test_utils.NewFedTest(t, "")

	// The federation must advertise a CA endpoint for the origin to auto-detect.
	fedInfo, err := config.GetFederation(fed.Ctx)
	require.NoError(t, err)
	require.NotEmpty(t, fedInfo.CAEndpoint, "registry should advertise a CA endpoint by default")

	// Drive one manager cycle deterministically (the background manager also runs,
	// but on a 10-minute timer; EnsureHostCertificate is idempotent).
	require.NoError(t, launcher_utils.EnsureHostCertificate(fed.Ctx, server_structs.OriginType))

	// The installed leaf certificate must now be federation-issued (not the
	// self-signed "Pelican CA" temporary cert) and carry exactly one SAN — the
	// origin's registry slug.
	leaf, intermediates := loadInstalledChain(t)
	assert.Contains(t, strings.Join(leaf.Issuer.Organization, ","), "Pelican Federation",
		"origin should be running a federation-issued certificate")
	assert.NotContains(t, strings.Join(leaf.Issuer.Organization, ","), "Pelican CA",
		"the temporary self-signed certificate should have been replaced")
	// The cert carries the service slug (SignHostCertificate stamps it first),
	// possibly followed by the origin's registration hostname.
	require.NotEmpty(t, leaf.DNSNames)
	slug := leaf.DNSNames[0]
	assert.NotEmpty(t, slug)
	assert.Empty(t, leaf.IPAddresses, "no IP SANs should be issued")
	require.Len(t, intermediates, 1, "installed chain should include the intermediate")

	// The leaf must verify against the federation root the registry publishes,
	// keyed on the slug.
	caBase, err := url.JoinPath(fedInfo.CAEndpoint, "api", "v1.0", "registry")
	require.NoError(t, err)
	rootPEM, err := registry_client.FetchCABundle(fed.Ctx, caBase)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(rootPEM)))
	interPool := x509.NewCertPool()
	interPool.AddCert(intermediates[0])
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: interPool, DNSName: slug,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "installed certificate must verify against the federation root")
}

// loadInstalledChain reads the leaf + intermediates from the origin's configured
// TLS certificate chain file.
func loadInstalledChain(t *testing.T) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	data, err := os.ReadFile(param.Server_TLSCertificateChain.GetString())
	require.NoError(t, err)
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, cert)
	}
	require.NotEmpty(t, certs)
	return certs[0], certs[1:]
}
