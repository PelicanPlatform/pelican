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

package launcher_utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// writeSelfSignedCert writes a self-signed certificate (so Issuer == Subject)
// with the given organization and expiry, and returns its path.
func writeSelfSignedCert(t *testing.T, org string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{org}, CommonName: "host"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
	return path
}

func TestHostCertNeedsIssue(t *testing.T) {
	orig := param.Server_TLSCertificateChain.GetString()
	t.Cleanup(func() { _ = param.Server_TLSCertificateChain.Set(orig) })

	far := time.Now().Add(365 * 24 * time.Hour)

	t.Run("self-signed temporary cert is replaced", func(t *testing.T) {
		require.NoError(t, param.Server_TLSCertificateChain.Set(writeSelfSignedCert(t, selfSignedIssuerOrg, far)))
		need, reason := hostCertNeedsIssue()
		assert.True(t, need)
		assert.Contains(t, reason, "temporary")
	})

	t.Run("valid federation cert is left alone", func(t *testing.T) {
		require.NoError(t, param.Server_TLSCertificateChain.Set(writeSelfSignedCert(t, federationIssuerOrg, far)))
		need, _ := hostCertNeedsIssue()
		assert.False(t, need)
	})

	t.Run("federation cert near expiry is renewed", func(t *testing.T) {
		soon := time.Now().Add(1 * time.Hour) // within hostCertRenewBefore
		require.NoError(t, param.Server_TLSCertificateChain.Set(writeSelfSignedCert(t, federationIssuerOrg, soon)))
		need, reason := hostCertNeedsIssue()
		assert.True(t, need)
		assert.Contains(t, reason, "expiry")
	})

	t.Run("operator-provided cert is never touched", func(t *testing.T) {
		require.NoError(t, param.Server_TLSCertificateChain.Set(writeSelfSignedCert(t, "Acme Corporation", far)))
		need, _ := hostCertNeedsIssue()
		assert.False(t, need)
	})

	t.Run("missing cert requires issuance", func(t *testing.T) {
		require.NoError(t, param.Server_TLSCertificateChain.Set(filepath.Join(t.TempDir(), "absent.pem")))
		need, _ := hostCertNeedsIssue()
		assert.True(t, need)
	})
}

func TestInstallHostCertificate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	rootPath := filepath.Join(dir, "ca.pem")

	origKey := param.Server_TLSKey.GetString()
	origChain := param.Server_TLSCertificateChain.GetString()
	origRoot := param.Server_TLSCACertificateFile.GetString()
	t.Cleanup(func() {
		_ = param.Server_TLSKey.Set(origKey)
		_ = param.Server_TLSCertificateChain.Set(origChain)
		_ = param.Server_TLSCACertificateFile.Set(origRoot)
	})
	require.NoError(t, param.Server_TLSKey.Set(keyPath))
	require.NoError(t, param.Server_TLSCertificateChain.Set(chainPath))
	require.NoError(t, param.Server_TLSCACertificateFile.Set(rootPath))

	require.NoError(t, installHostCertificate("CHAIN-PEM", "KEY-PEM", "ROOT-PEM"))

	chain, err := os.ReadFile(chainPath)
	require.NoError(t, err)
	assert.Equal(t, "CHAIN-PEM", string(chain))
	key, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, "KEY-PEM", string(key))
	root, err := os.ReadFile(rootPath)
	require.NoError(t, err)
	assert.Equal(t, "ROOT-PEM", string(root))

	// The private key must be written with restrictive permissions.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0400), info.Mode().Perm())
	}
}
