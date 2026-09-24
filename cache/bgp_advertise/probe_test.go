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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTLSServerWithSAN starts an httptest TLS server presenting a self-signed
// certificate that lists the given DNS names as SubjectAltNames.
func newTLSServerWithSAN(t *testing.T, dnsNames []string) *httptest.Server {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cache"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyCertSAN(t *testing.T) {
	ctx := context.Background()

	t.Run("matching-SAN", func(t *testing.T) {
		srv := newTLSServerWithSAN(t, []string{"cache.anycast.example.com"})
		err := VerifyCertSAN(ctx, srv.URL, "cache.anycast.example.com")
		assert.NoError(t, err)
	})

	t.Run("wildcard-SAN", func(t *testing.T) {
		srv := newTLSServerWithSAN(t, []string{"*.anycast.example.com"})
		err := VerifyCertSAN(ctx, srv.URL, "cache.anycast.example.com")
		assert.NoError(t, err)
	})

	t.Run("missing-SAN", func(t *testing.T) {
		srv := newTLSServerWithSAN(t, []string{"some-other-name.example.com"})
		err := VerifyCertSAN(ctx, srv.URL, "cache.anycast.example.com")
		assert.Error(t, err)
	})

	t.Run("empty-args", func(t *testing.T) {
		assert.Error(t, VerifyCertSAN(ctx, "", "x"))
		assert.Error(t, VerifyCertSAN(ctx, "https://localhost", ""))
	})

	t.Run("unreachable", func(t *testing.T) {
		// Port 1 is essentially never open.
		err := VerifyCertSAN(ctx, "https://127.0.0.1:1", "cache.anycast.example.com")
		assert.Error(t, err)
	})
}

func TestConfigValidate(t *testing.T) {
	base := Config{
		RouterID:    "10.0.0.1",
		LocalASN:    65000,
		PeerAddress: "10.0.0.2",
		PeerASN:     65001,
		NextHop:     "10.0.0.1",
		Routes:      []string{"192.0.2.0/24"},
	}
	require.NoError(t, base.Validate())

	t.Run("missing-router-id", func(t *testing.T) {
		c := base
		c.RouterID = ""
		assert.Error(t, c.Validate())
	})
	t.Run("missing-peer", func(t *testing.T) {
		c := base
		c.PeerAddress = ""
		assert.Error(t, c.Validate())
	})
	t.Run("no-routes", func(t *testing.T) {
		c := base
		c.Routes = nil
		assert.Error(t, c.Validate())
	})
	t.Run("bad-cidr", func(t *testing.T) {
		c := base
		c.Routes = []string{"not-a-cidr"}
		assert.Error(t, c.Validate())
	})
	t.Run("no-nexthop-or-local", func(t *testing.T) {
		c := base
		c.NextHop = ""
		c.LocalAddress = ""
		assert.Error(t, c.Validate())
	})
	t.Run("local-addr-substitutes-nexthop", func(t *testing.T) {
		c := base
		c.NextHop = ""
		c.LocalAddress = "10.0.0.1"
		assert.NoError(t, c.Validate())
		assert.Equal(t, "10.0.0.1", c.nextHop())
	})
}
