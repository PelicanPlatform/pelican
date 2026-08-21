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

package configtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// InitServerTLSForTest redirects all TLS key and certificate parameters
// to paths inside dir, isolating tests from host configuration.
// Call before any function that generates or reads TLS credentials.
func InitServerTLSForTest(t testing.TB, dir string) {
	t.Helper()
	require.NoError(t, param.Server_TLSCACertificateFile.Set(filepath.Join(dir, "ca.crt")))
	require.NoError(t, param.Server_TLSCAKey.Set(filepath.Join(dir, "ca.key")))
	require.NoError(t, param.Server_TLSCertificateChain.Set(filepath.Join(dir, "tls.crt")))
	require.NoError(t, param.Server_TLSKey.Set(filepath.Join(dir, "tls.key")))
}

// NewTLSServerForTest starts an HTTPS server with an ephemeral localhost
// leaf certificate signed by an already-provisioned test CA.
//
// The CA must already exist on disk: Server.TLSCACertificateFile and
// Server.TLSCAKey must be set, and both files must be present at those
// paths.
func NewTLSServerForTest(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()

	require.NotEmpty(t, param.Server_TLSCACertificateFile.GetString(),
		"NewTLSServerForTest requires Server.TLSCACertificateFile to be set")
	require.NotEmpty(t, param.Server_TLSCAKey.GetString(),
		"NewTLSServerForTest requires Server.TLSCAKey to be set")

	caCert := loadCACert(t, param.Server_TLSCACertificateFile.GetString())
	caPrivateKey := loadCAKey(t, param.Server_TLSCAKey.GetString())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate test TLS private key")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err, "Failed to generate test TLS serial number")

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, privateKey.Public(), caPrivateKey)
	require.NoError(t, err, "Failed to create test TLS certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err, "Failed to marshal test TLS private key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err, "Failed to assemble test TLS key pair")

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}
	server.StartTLS()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err, "Failed to parse test TLS listener address")
	server.URL = "https://" + net.JoinHostPort("localhost", port)
	t.Cleanup(server.Close)

	return server
}

// loadCACert reads the first PEM certificate block from path.
func loadCACert(t testing.TB, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read CA certificate file")
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "No PEM block found in CA certificate file")
	require.Equal(t, "CERTIFICATE", block.Type,
		"First PEM block in CA certificate file is not a CERTIFICATE")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse CA certificate")
	return cert
}

// loadCAKey reads a PKCS8-encoded ECDSA private key from path.
// This matches the format written by
// config.GenerateCACert / config.GeneratePrivateKey.
func loadCAKey(t testing.TB, path string) *ecdsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read CA key file")
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "No PEM block found in CA key file")
	require.Equal(t, "PRIVATE KEY", block.Type,
		"First PEM block in CA key file is not a PKCS8 PRIVATE KEY")
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err, "Failed to parse CA private key")
	key, ok := raw.(*ecdsa.PrivateKey)
	require.True(t, ok, "CA private key is not ECDSA")
	return key
}
