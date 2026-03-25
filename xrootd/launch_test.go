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

package xrootd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// writeCertWithEKUs generates a self-signed PEM certificate with the given
// extended key usages, writes it to a temp file inside dir, and returns its path.
func writeCertWithEKUs(t *testing.T, dir string, ekus []x509.ExtKeyUsage) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	f, err := os.CreateTemp(dir, "cert-*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, f.Close())
	return f.Name()
}

// TestMakeUnprivilegedXrootdLauncher_DisableClientX509 verifies that
// makeUnprivilegedXrootdLauncher correctly sets the XRD_CURLDISABLEX509
// environment variable, and that it returns a fatal error when
// Cache.DisableClientX509 is false and the configured cert is missing the
// clientAuth EKU.
func TestMakeUnprivilegedXrootdLauncher_DisableClientX509(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	tests := []struct {
		name              string
		disableClientX509 bool
		// certEKUs is the EKU set written into the temp cert.  When nil and
		// disableClientX509 is false, no cert path is configured.
		certEKUs    []x509.ExtKeyUsage
		wantEnvVar  bool   // expect XRD_CURLDISABLEX509=1 in ExtraEnv
		wantErr     bool   // expect makeUnprivilegedXrootdLauncher to return an error
		errContains string // substring the error message should contain
	}{
		{
			name:              "param true (default): sets XRD_CURLDISABLEX509=1, no error",
			disableClientX509: true,
			wantEnvVar:        true,
			wantErr:           false,
		},
		{
			name:              "param false, cert has clientAuth and serverAuth: no env var, no error",
			disableClientX509: false,
			certEKUs:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEnvVar:        false,
			wantErr:           false,
		},
		{
			name:              "param false, cert has only serverAuth (typical Let's Encrypt): fatal error",
			disableClientX509: false,
			certEKUs:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantEnvVar:        false,
			wantErr:           true,
			errContains:       "clientAuth Extended Key Usage",
		},
		{
			name:              "param false, no cert configured: no env var, no error",
			disableClientX509: false,
			certEKUs:          nil,
			wantEnvVar:        false,
			wantErr:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			t.Cleanup(func() {
				// Reset global FD state written by makeUnprivilegedXrootdLauncher.
				g_cache_fds = [2]int{-1, -1}
				server_utils.ResetTestState()
			})

			runDir := t.TempDir()
			require.NoError(t, param.Cache_RunLocation.Set(runDir))
			require.NoError(t, param.Server_DropPrivileges.Set(false))
			require.NoError(t, param.Cache_DisableClientX509.Set(tc.disableClientX509))

			if !tc.disableClientX509 && tc.certEKUs != nil {
				certPath := writeCertWithEKUs(t, runDir, tc.certEKUs)
				require.NoError(t, param.Server_TLSCertificateChain.Set(certPath))
			}

			launcher, err := makeUnprivilegedXrootdLauncher("xrootd", runDir, "/fake/xrootd.cfg", true)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() {
				syscall.Close(launcher.fds[0])
				syscall.Close(launcher.fds[1])
			})

			if tc.wantEnvVar {
				assert.True(t, slices.Contains(launcher.ExtraEnv, "XRD_CURLDISABLEX509=1"),
					"expected XRD_CURLDISABLEX509=1 in ExtraEnv; got: %v", launcher.ExtraEnv)
			} else {
				assert.False(t, slices.Contains(launcher.ExtraEnv, "XRD_CURLDISABLEX509=1"),
					"expected XRD_CURLDISABLEX509=1 to be absent; got: %v", launcher.ExtraEnv)
			}
		})
	}
}
