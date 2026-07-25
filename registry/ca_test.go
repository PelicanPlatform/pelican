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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newCATestDB returns an in-memory SQLite handle with the certificate_authorities
// table created, isolated per test. It installs a fixed CA encryption key via
// caKeyOverride so tests exercise the encrypt-at-rest path without the master-key
// / issuer-key machinery.
func newCATestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_pragma=foreign_keys(1)"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&CertificateAuthority{}))

	caKeyOverride = bytes.Repeat([]byte{0x2a}, 32)
	t.Cleanup(func() {
		caKeyOverride = nil
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// makeCSR builds a self-signed CSR requesting the given SANs.
func makeCSR(t *testing.T, cn string, dnsNames []string, ips []net.IP) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	return csr
}

func TestEnsureFederationCA(t *testing.T) {
	db := newCATestDB(t)

	require.NoError(t, EnsureFederationCA(db))

	root, err := loadCA(db, caRoleRoot)
	require.NoError(t, err)
	intermediate, err := loadCA(db, caRoleIntermediate)
	require.NoError(t, err)

	// Root is a self-signed CA with pathlen 1.
	assert.True(t, root.cert.IsCA)
	assert.Equal(t, root.cert.Subject.String(), root.cert.Issuer.String(), "root must be self-signed")
	assert.Equal(t, 1, root.cert.MaxPathLen)

	// Intermediate is a CA signed by the root with pathlen 0.
	assert.True(t, intermediate.cert.IsCA)
	assert.Equal(t, root.cert.Subject.String(), intermediate.cert.Issuer.String(), "intermediate must be issued by root")
	assert.True(t, intermediate.cert.MaxPathLenZero)
	require.NoError(t, intermediate.cert.CheckSignatureFrom(root.cert), "intermediate signature must chain to root")

	// Idempotent: a second call must not replace the material.
	require.NoError(t, EnsureFederationCA(db))
	root2, err := loadCA(db, caRoleRoot)
	require.NoError(t, err)
	assert.Equal(t, root.cert.SerialNumber, root2.cert.SerialNumber, "root must be stable across calls")
	intermediate2, err := loadCA(db, caRoleIntermediate)
	require.NoError(t, err)
	assert.Equal(t, intermediate.cert.SerialNumber, intermediate2.cert.SerialNumber, "intermediate must be stable across calls")

	// Exactly one row per role.
	var count int64
	require.NoError(t, db.Model(&CertificateAuthority{}).Count(&count).Error)
	assert.EqualValues(t, 2, count)
}

func TestSignHostCertificate_ChainVerifies(t *testing.T) {
	db := newCATestDB(t)
	require.NoError(t, EnsureFederationCA(db))

	// Services authenticate by their unique slug, not a hostname or IP.
	slug := "18f1jk5"
	csr := makeCSR(t, slug, []string{slug}, nil)

	chainPEM, err := SignHostCertificate(db, HostCertRequest{
		CSR:             csr,
		AuthorizedNames: []string{slug},
	})
	require.NoError(t, err)

	// The chain should contain leaf + intermediate.
	leaf, intermediates := parseChain(t, chainPEM)
	require.Len(t, intermediates, 1, "chain must include the intermediate")
	assert.False(t, leaf.IsCA)
	assert.Contains(t, leaf.DNSNames, slug)
	assert.Empty(t, leaf.IPAddresses, "no IP SANs should ever be issued")

	// Full chain must verify up to the root as trust anchor, matching the slug.
	rootPEM, err := GetCABundlePEM(db)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(rootPEM)))
	interPool := x509.NewCertPool()
	interPool.AddCert(intermediates[0])

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: interPool,
		DNSName:       slug,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "leaf must verify against the root via the intermediate, keyed on the slug")
}

func TestSignHostCertificate_StampsOnlyAuthorizedNames(t *testing.T) {
	db := newCATestDB(t)
	require.NoError(t, EnsureFederationCA(db))

	slug := "18f1jk5"
	evilSlug := "victim0"
	evilIP := net.ParseIP("10.0.0.1")

	// The CSR tries to claim an unauthorized slug and an IP SAN; the issued
	// cert must contain ONLY the authorized slug regardless of what the CSR
	// requested.
	csr := makeCSR(t, "whatever", []string{evilSlug}, []net.IP{evilIP})

	chainPEM, err := SignHostCertificate(db, HostCertRequest{
		CSR:             csr,
		AuthorizedNames: []string{slug},
	})
	require.NoError(t, err)

	leaf, _ := parseChain(t, chainPEM)
	assert.Equal(t, []string{slug}, leaf.DNSNames, "cert SANs must equal exactly the authorized names")
	assert.NotContains(t, leaf.DNSNames, evilSlug, "CSR-requested name must be ignored")
	assert.Empty(t, leaf.IPAddresses, "IP SANs must never be issued")
}

func TestSignHostCertificate_NoAuthorizedNamesRejected(t *testing.T) {
	db := newCATestDB(t)
	require.NoError(t, EnsureFederationCA(db))

	csr := makeCSR(t, "victim0", []string{"victim0"}, nil)
	_, err := SignHostCertificate(db, HostCertRequest{
		CSR:             csr,
		AuthorizedNames: nil, // caller supplied no identity to grant
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorized SANs")
}

func TestSignHostCertificate_RequiresCA(t *testing.T) {
	db := newCATestDB(t) // no EnsureFederationCA call
	csr := makeCSR(t, "18f1jk5", []string{"18f1jk5"}, nil)
	_, err := SignHostCertificate(db, HostCertRequest{
		CSR:             csr,
		AuthorizedNames: []string{"18f1jk5"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// parseChain splits a PEM chain into its leaf (first cert) and the remaining
// intermediates.
func parseChain(t *testing.T, chainPEM string) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	var certs []*x509.Certificate
	rest := []byte(chainPEM)
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

func TestCA_KeysEncryptedAtRest(t *testing.T) {
	db := newCATestDB(t)
	require.NoError(t, EnsureFederationCA(db))

	// The raw stored bytes must be ciphertext, never the plaintext PEM.
	var rows []CertificateAuthority
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 2)
	for _, row := range rows {
		assert.NotContains(t, string(row.EncryptedKey), "PRIVATE KEY",
			"stored CA key for role %q must not be plaintext PEM", row.Role)
		assert.NotEmpty(t, row.EncryptedKey)
	}

	// With the wrong CA key, the stored material must fail to decrypt (proving
	// the key actually gates access, not just that bytes differ).
	caKeyOverride = bytes.Repeat([]byte{0x99}, 32)
	_, err := loadCA(db, caRoleRoot)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

func TestSealOpenCAKey_Roundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	plaintext := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")

	blob, err := sealCAKey(key, plaintext)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "PRIVATE KEY")

	got, err := openCAKey(key, plaintext[:0]) // too short -> error
	require.Error(t, err)
	assert.Nil(t, got)

	got, err = openCAKey(key, blob)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// A different key must not open it.
	_, err = openCAKey(bytes.Repeat([]byte{0x22}, 32), blob)
	require.Error(t, err)
}

// Guard against accidentally shortening the CA validity windows below the host
// cert lifetime.
func TestCAValidityWindows(t *testing.T) {
	assert.Greater(t, rootCAValidity, intermediateCAValidity)
	assert.Greater(t, intermediateCAValidity, defaultHostCertValidity)
	assert.Positive(t, time.Duration(defaultHostCertValidity))
}
