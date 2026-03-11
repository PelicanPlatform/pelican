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

package utils

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

// makeSelfSignedCert creates a minimal self-signed PEM certificate with the
// supplied extended key usages.
func makeSelfSignedCert(t *testing.T, ekus []x509.ExtKeyUsage) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckClientAuthEKU(t *testing.T) {
	tests := []struct {
		name        string
		buildPEM    func(t *testing.T) []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "cert with clientAuth and serverAuth EKUs",
			buildPEM: func(t *testing.T) []byte {
				return makeSelfSignedCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
			},
			wantErr: false,
		},
		{
			name: "cert with only serverAuth EKU (typical Let's Encrypt cert)",
			buildPEM: func(t *testing.T) []byte {
				return makeSelfSignedCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			},
			wantErr:     true,
			errContains: "clientAuth Extended Key Usage",
		},
		{
			name: "cert with no EKU",
			buildPEM: func(t *testing.T) []byte {
				return makeSelfSignedCert(t, nil)
			},
			wantErr:     true,
			errContains: "clientAuth Extended Key Usage",
		},
		{
			name:     "empty PEM input",
			buildPEM: func(t *testing.T) []byte { return []byte{} },
			wantErr:  false,
		},
		{
			name:     "invalid/garbage PEM input",
			buildPEM: func(t *testing.T) []byte { return []byte("not a pem block") },
			wantErr:  false,
		},
		{
			name: "non-CERTIFICATE PEM block (private key)",
			buildPEM: func(t *testing.T) []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("dummy")})
			},
			wantErr: false,
		},
		{
			// Leaf cert lacks clientAuth; intermediate cert has it.
			// Only the leaf is inspected, so an error should still be returned.
			name: "chain where only intermediate has clientAuth EKU",
			buildPEM: func(t *testing.T) []byte {
				leafPEM := makeSelfSignedCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				intermediatePEM := makeSelfSignedCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
				return append(leafPEM, intermediatePEM...)
			},
			wantErr:     true,
			errContains: "clientAuth Extended Key Usage",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pemBytes := tc.buildPEM(t)
			err := CheckClientAuthEKU("/fake/cert.pem", pemBytes)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
