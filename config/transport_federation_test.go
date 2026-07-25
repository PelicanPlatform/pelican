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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCA generates a self-signed CA and returns its PEM encoding, the parsed
// certificate, and the private key (needed to sign a leaf for verification).
func newTestCA(t *testing.T, commonName string) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), cert, key
}

// newLeafSignedBy issues a server leaf certificate signed by the supplied CA.
func newLeafSignedBy(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "origin.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

// TestAddFederationCA verifies that a fetched root PEM is merged into the pool
// used by the transports, that the operation is idempotent, and that bad input
// is handled gracefully.
func TestAddFederationCA(t *testing.T) {
	// Reset the dedup cache so the test is independent of any prior additions.
	federationCAMu.Lock()
	federationCASeen = map[[32]byte]struct{}{}
	federationCAMu.Unlock()

	rootPEM, caCert, caKey := newTestCA(t, "pelican-federation-test-root")

	// First add: should report a new certificate merged.
	added, err := AddFederationCA(rootPEM)
	require.NoError(t, err)
	assert.True(t, added, "expected the federation root to be newly added")

	// Every transport variant must now reference a non-nil RootCAs pool that
	// trusts a leaf signed by this root.
	leaf := newLeafSignedBy(t, caCert, caKey)
	pool := GetTransport().TLSClientConfig.RootCAs
	require.NotNil(t, pool, "transport should have a RootCAs pool after adding a federation CA")

	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, verifyErr, "leaf signed by the federation root should validate against the transport pool")

	// The basic and no-proxy transports must share the same trust.
	require.NotNil(t, GetBasicTransport().TLSClientConfig.RootCAs)
	_, verifyErr = leaf.Verify(x509.VerifyOptions{Roots: GetBasicTransport().TLSClientConfig.RootCAs})
	assert.NoError(t, verifyErr, "basic transport should also trust the federation root")

	require.NotNil(t, GetTransportNoProxy().TLSClientConfig.RootCAs)
	_, verifyErr = leaf.Verify(x509.VerifyOptions{Roots: GetTransportNoProxy().TLSClientConfig.RootCAs})
	assert.NoError(t, verifyErr, "no-proxy transport should also trust the federation root")

	// Second add of the same PEM: idempotent no-op.
	added, err = AddFederationCA(rootPEM)
	require.NoError(t, err)
	assert.False(t, added, "re-adding the same federation root should be a no-op")

	// Empty / whitespace input: no error, nothing added.
	added, err = AddFederationCA("   \n")
	require.NoError(t, err)
	assert.False(t, added)

	// Non-certificate input: reported as an error, never panics.
	_, err = AddFederationCA("not a pem at all")
	assert.Error(t, err)
}
