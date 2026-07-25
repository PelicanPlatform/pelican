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

package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry/registry_client"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// ecdsaRegistrationKey returns a fresh ECDSA private key (as a jwk.Key, so it
// can sign JWTs) and the single-key public JWKS string stored as a
// registration's Pubkey.
func ecdsaRegistrationKey(t *testing.T) (jwk.Key, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwkKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(jwkKey))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))
	pubKey, err := jwk.PublicKeyOf(jwkKey)
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	jwksBytes, err := json.Marshal(set)
	require.NoError(t, err)
	return jwkKey, string(jwksBytes)
}

// newCSR builds a CSR with a fresh host keypair and returns both the PEM and the
// parsed request (so tests can compute its thumbprint).
func newCSR(t *testing.T) (csrPEM string, csr *x509.CertificateRequest) {
	t.Helper()
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, hostKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), parsed
}

// mintHostCertToken builds and signs a request token. The knobs let tests
// produce good and deliberately-malformed tokens.
type tokenOpts struct {
	signWith    jwk.Key
	audience    string
	scope       token_scopes.TokenScope
	csrHash     string        // if empty, omit the binding claim
	ttl         time.Duration // if zero, omit exp
	omitCSRHash bool
}

func mintHostCertToken(t *testing.T, o tokenOpts) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer("test").
		IssuedAt(time.Now()).
		Audience([]string{o.audience}).
		Claim("scope", string(o.scope))
	if o.ttl > 0 {
		b = b.Expiration(time.Now().Add(o.ttl))
	}
	if !o.omitCSRHash {
		b = b.Claim(server_structs.HostCertCSRHashClaim, o.csrHash)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, o.signWith))
	require.NoError(t, err)
	return string(signed)
}

func TestAuthorizedNamesForPrefix(t *testing.T) {
	slug := "18f1jk5"
	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"origin hostname", "/origins/example.org", []string{slug, "example.org"}},
		{"cache hostname", "/caches/cache.example.org", []string{slug, "cache.example.org"}},
		{"hostname with port is stripped", "/origins/example.org:8444", []string{slug, "example.org"}},
		{"IP-literal prefix contributes no DNS SAN", "/origins/192.0.2.10", []string{slug}},
		{"IPv6-literal prefix contributes no DNS SAN", "/origins/[2001:db8::1]:8444", []string{slug}},
		{"non-service prefix yields only the slug", "/foo/bar", []string{slug}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, authorizedNamesForPrefix(tc.prefix, slug))
		})
	}
}

func TestIssueHostCertificate(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})
	server_utils.ResetTestState()

	svr := registryMockup(ctx, t, "host-cert")
	defer func() {
		assert.NoError(t, database.ShutdownDB())
		svr.CloseClientConnections()
		svr.Close()
	}()

	require.NoError(t, database.ServerDatabase.AutoMigrate(&CertificateAuthority{}))
	caKeyOverride = bytes.Repeat([]byte{0x2a}, 32)
	t.Cleanup(func() { caKeyOverride = nil })
	require.NoError(t, EnsureFederationCA(database.ServerDatabase))

	// Seed an APPROVED origin registration whose key we control.
	regKey, regJWKS := ecdsaRegistrationKey(t)
	prefix := "/origins/example.org"
	require.NoError(t, AddRegistration(&server_structs.Registration{
		Prefix: prefix,
		Pubkey: regJWKS,
		AdminMetadata: server_structs.AdminMetadata{
			SiteName: "test-origin",
			Status:   server_structs.RegApproved,
		},
	}))

	slug, err := serviceSlugForPrefix(prefix)
	require.NoError(t, err)
	require.NotEmpty(t, slug)

	sha := func(csr *x509.CertificateRequest) string {
		sum := sha256.Sum256(csr.Raw)
		return hex.EncodeToString(sum[:])
	}
	goodTokenOpts := func(csr *x509.CertificateRequest) tokenOpts {
		return tokenOpts{
			signWith: regKey, audience: server_structs.HostCertAudience,
			scope: token_scopes.Registry_RequestHostCert, csrHash: sha(csr), ttl: 2 * time.Minute,
		}
	}

	t.Run("happy path issues a slug-bound cert", func(t *testing.T) {
		csrPEM, csr := newCSR(t)
		chainPEM, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, goodTokenOpts(csr)),
		})
		require.NoError(t, err)

		leaf, intermediates := parseChain(t, chainPEM)
		require.Len(t, intermediates, 1)
		// Cert carries the slug plus the hostname embedded in the registration
		// prefix (/origins/example.org -> example.org), so both IP+slug and
		// DNS-hostname clients validate.
		assert.Contains(t, leaf.DNSNames, slug)
		assert.Contains(t, leaf.DNSNames, "example.org")
		assert.Empty(t, leaf.IPAddresses)

		rootPEM, err := GetCABundlePEM(database.ServerDatabase)
		require.NoError(t, err)
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM([]byte(rootPEM)))
		interPool := x509.NewCertPool()
		interPool.AddCert(intermediates[0])
		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: interPool, DNSName: slug,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err)
	})

	t.Run("token signed by wrong key is rejected", func(t *testing.T) {
		wrongKey, _ := ecdsaRegistrationKey(t)
		csrPEM, csr := newCSR(t)
		o := goodTokenOpts(csr)
		o.signWith = wrongKey
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
	})

	t.Run("token bound to a different CSR is rejected", func(t *testing.T) {
		_, otherCSR := newCSR(t) // token commits to this...
		csrPEM, _ := newCSR(t)   // ...but we present this one
		o := goodTokenOpts(otherCSR)
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
		assert.Contains(t, err.Error(), "not bound")
	})

	t.Run("wrong scope is rejected", func(t *testing.T) {
		csrPEM, csr := newCSR(t)
		o := goodTokenOpts(csr)
		o.scope = token_scopes.Registry_EditRegistration
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		csrPEM, csr := newCSR(t)
		o := goodTokenOpts(csr)
		o.audience = "some-other-service"
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		csrPEM, csr := newCSR(t)
		o := goodTokenOpts(csr)
		o.ttl = -1 * time.Minute // already expired
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
	})

	t.Run("token without expiry is rejected", func(t *testing.T) {
		csrPEM, csr := newCSR(t)
		o := goodTokenOpts(csr)
		o.ttl = 0 // omit exp
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: prefix, CSR: csrPEM, Token: mintHostCertToken(t, o),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
		assert.Contains(t, err.Error(), "expiry")
	})

	t.Run("pending service is refused when the federation requires approval", func(t *testing.T) {
		require.NoError(t, param.Registry_RequireOriginApproval.Set(true))
		t.Cleanup(func() { _ = param.Registry_RequireOriginApproval.Set(false) })

		_, pendingJWKS := ecdsaRegistrationKey(t)
		pendingPrefix := "/origins/pending.example.org"
		require.NoError(t, AddRegistration(&server_structs.Registration{
			Prefix: pendingPrefix,
			Pubkey: pendingJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: "pending-origin",
				Status:   server_structs.RegPending,
			},
		}))
		csrPEM, csr := newCSR(t)
		_, err := issueHostCertificateImpl(&server_structs.IssueHostCertRequest{
			Prefix: pendingPrefix, CSR: csrPEM, Token: mintHostCertToken(t, goodTokenOpts(csr)),
		})
		require.Error(t, err)
		assert.ErrorAs(t, err, &permissionDeniedError{})
		assert.Contains(t, err.Error(), "approved")
	})

	t.Run("pending service is allowed when approval is not required", func(t *testing.T) {
		// RequireOriginApproval defaults to false in the mock registry.
		_, pendingJWKS := ecdsaRegistrationKey(t)
		openPrefix := "/origins/open.example.org"
		require.NoError(t, AddRegistration(&server_structs.Registration{
			Prefix: openPrefix,
			Pubkey: pendingJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: "open-origin",
				Status:   server_structs.RegPending,
			},
		}))
		reg, err := requireApprovedService(openPrefix)
		require.NoError(t, err)
		assert.Equal(t, openPrefix, reg.Prefix)
	})

	t.Run("client obtains a usable cert over HTTP", func(t *testing.T) {
		registryEndpoint := svr.URL + "/api/v1.0/registry"

		chainPEM, hostKeyPEM, err := registry_client.RequestHostCertificate(ctx, registryEndpoint, prefix, regKey)
		require.NoError(t, err)

		leaf, intermediates := parseChain(t, chainPEM)
		require.Len(t, intermediates, 1)
		assert.Contains(t, leaf.DNSNames, slug)
		assert.Contains(t, leaf.DNSNames, "example.org")

		// The returned host private key must match the certificate's public key.
		block, _ := pem.Decode([]byte(hostKeyPEM))
		require.NotNil(t, block)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		hostKey, ok := parsed.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, hostKey.PublicKey.Equal(leaf.PublicKey), "leaf must certify the returned host key")

		// The CA bundle endpoint returns the federation root.
		rootPEM, err := registry_client.FetchCABundle(ctx, registryEndpoint)
		require.NoError(t, err)
		assert.Contains(t, rootPEM, "BEGIN CERTIFICATE")
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM([]byte(rootPEM)))
		interPool := x509.NewCertPool()
		interPool.AddCert(intermediates[0])
		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: interPool, DNSName: slug,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err, "client-obtained cert must verify against the fetched root")
	})
}
