/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
)

var (
	// Our global transports that only will get reconfigured if needed
	transport *http.Transport

	// Transport that avoids any use of a HTTP(S) proxy
	transportNoProxy *http.Transport

	// Transport that avoids any broker-aware dialer
	basicTransport *http.Transport

	// The global HTTP client
	client *http.Client

	// The global non-broker-aware HTTP client
	basicClient *http.Client

	// The global HTTP client with no redirect
	clientNoRedirect *http.Client

	// The global HTTP client with no use of HTTP(S) proxies
	clientNoProxy *http.Client

	// Once to ensure we only set up the transport once
	onceTransport sync.Once

	// Static dialer for the transport
	dialerFunc atomic.Pointer[func(ctx context.Context, network, addr string) (net.Conn, error)]
)

// Returns the default transport object for Pelican.
//
// This transport will use the global dialer function set by SetTransportDialer,
// allowing it to be broker-aware.
func GetTransport() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return transport
}

// Returns the default client object for Pelican
//
// This uses the global dialer function set by SetTransportDialer, allowing it
// to be broker-aware
func GetClient() *http.Client {
	onceTransport.Do(func() {
		setupTransport()
	})
	return client
}

// Returns a basic transport object that does not use the broker-aware dialer.
func GetBasicTransport() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return basicTransport
}

// Returns a transport object that does not use any HTTP(S) proxy
func GetTransportNoProxy() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return transportNoProxy
}

// Returns the default client object configured to not follow redirects
//
// This allows special handling of redirect headers by the client
func GetClientNoRedirect() *http.Client {
	onceTransport.Do(func() {
		setupTransport()
	})
	return clientNoRedirect
}

// Returns the default client object configured to not use HTTP proxies
//
// This allows bypassing of proxies for the GET/PUT in the client methods
func GetClientNoProxy() *http.Client {
	onceTransport.Do(func() {
		setupTransport()
	})
	return clientNoProxy
}

// Returns the basic client object for Pelican
//
// This uses the golang default dialer and will not use the broker.
func GetBasicClient() *http.Client {
	onceTransport.Do(func() {
		setupTransport()
	})
	return basicClient
}

// Override the global transport's dialer function.
//
// Intended to allow the broker-aware dialer to be setup by other packages.
// Will panic if the dialerFunc is nil.
func SetTransportDialer(DialerContext func(ctx context.Context, network, addr string) (net.Conn, error)) {
	if DialerContext == nil {
		panic("dialerFunc cannot be nil")
	}
	dialerFunc.Store(&DialerContext)
}

// Implement the DialContext interface for the global transport.
//
// Uses the global dialer function
func globalDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialerCtx := dialerFunc.Load()
	return (*dialerCtx)(ctx, network, addr)
}

func setupTransport() {
	// Getting timeouts and other information from the parameter defaults
	maxIdleConns := param.Transport_MaxIdleConns.GetInt()
	idleConnTimeout := param.Transport_IdleConnTimeout.GetDuration()
	transportTLSHandshakeTimeout := param.Transport_TLSHandshakeTimeout.GetDuration()
	expectContinueTimeout := param.Transport_ExpectContinueTimeout.GetDuration()
	responseHeaderTimeout := param.Transport_ResponseHeaderTimeout.GetDuration()

	transportDialerTimeout := param.Transport_DialerTimeout.GetDuration()
	transportKeepAlive := param.Transport_DialerKeepAlive.GetDuration()

	defaultDialer := net.Dialer{
		Timeout:   transportDialerTimeout,
		KeepAlive: transportKeepAlive,
	}
	defaultDialerContext := defaultDialer.DialContext
	dialerFunc.Store(&defaultDialerContext)

	//Set up the transport
	transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           globalDialContext,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   transportTLSHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	if param.TLSSkipVerify.GetBool() {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if caCert, err := LoadCertificate(param.Server_TLSCACertificateFile.GetString()); err == nil {
		systemPool, err := x509.SystemCertPool()
		if err == nil {
			systemPool.AddCert(caCert)
			// Ensure that we don't override the InsecureSkipVerify if it's present
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{RootCAs: systemPool}
			} else {
				transport.TLSClientConfig.RootCAs = systemPool
			}
		}
	}
	client = &http.Client{Transport: transport}

	clientNoRedirect = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	basicTransport = transport.Clone()
	basicTransport.DialContext = defaultDialerContext
	basicClient = &http.Client{Transport: basicTransport}

	transportNoProxy = transport.Clone()
	transportNoProxy.Proxy = nil
	clientNoProxy = &http.Client{Transport: transportNoProxy}
}

var (
	// Guards mutation of the transports' RootCAs pools by AddFederationCA.
	federationCAMu sync.Mutex

	// SHA-256 fingerprints of certificates already merged into the transport
	// trust store, so repeated calls with the same root are cheap no-ops and
	// the reported "added" result is accurate.
	federationCASeen = map[[32]byte]struct{}{}
)

// AddFederationCA merges the PEM-encoded federation root certificate(s) into the
// RootCAs pool used by every Pelican HTTP transport (the ones returned by
// GetTransport/GetClient and their variants). This lets a client validate a TLS
// peer -- e.g. an origin reached directly by IP -- whose certificate was issued
// by the federation CA (the registry acting as a CA) rather than a public CA.
//
// It is idempotent and safe to call more than once: certificates already present
// are not re-added, and the returned bool reports whether any new certificate
// was actually merged. The federation roots are added on top of the existing
// trust (system roots plus any Server.TLSCACertificateFile), never replacing it.
//
// A fresh pool is built and swapped into the transports rather than mutating the
// live pool in place, so in-flight TLS handshakes keep reading a stable pool.
// Callers are expected to invoke this early (before heavy concurrent transfer
// activity); it is not intended to be raced against a large volume of
// simultaneous handshakes.
func AddFederationCA(rootPEM string) (added bool, err error) {
	// Ensure the transports exist before we touch their TLS config.
	onceTransport.Do(func() {
		setupTransport()
	})

	if strings.TrimSpace(rootPEM) == "" {
		return false, nil
	}

	// Parse every certificate block out of the supplied PEM.
	var certs []*x509.Certificate
	rest := []byte(rootPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return false, errors.Wrap(parseErr, "failed to parse federation CA certificate")
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return false, errors.New("no certificates found in federation CA bundle")
	}

	federationCAMu.Lock()
	defer federationCAMu.Unlock()

	// Figure out which certs are new (not already merged).
	var newCerts []*x509.Certificate
	for _, cert := range certs {
		fp := sha256.Sum256(cert.Raw)
		if _, ok := federationCASeen[fp]; ok {
			continue
		}
		newCerts = append(newCerts, cert)
	}
	if len(newCerts) == 0 {
		return false, nil
	}

	// Build a fresh pool starting from whatever the transport already trusts
	// (system roots, or system+Server CA file). Cloning avoids mutating a pool
	// that in-flight handshakes may be reading.
	var pool *x509.CertPool
	if transport != nil && transport.TLSClientConfig != nil && transport.TLSClientConfig.RootCAs != nil {
		pool = transport.TLSClientConfig.RootCAs.Clone()
	} else if sysPool, sysErr := x509.SystemCertPool(); sysErr == nil {
		pool = sysPool
	} else {
		pool = x509.NewCertPool()
	}

	for _, cert := range newCerts {
		pool.AddCert(cert)
	}

	applyRootCAPool(pool)

	for _, cert := range newCerts {
		federationCASeen[sha256.Sum256(cert.Raw)] = struct{}{}
	}
	return true, nil
}

// applyRootCAPool points every transport's TLS RootCAs at the supplied pool.
// The InsecureSkipVerify setting (if any) is preserved. Must be called with
// federationCAMu held.
func applyRootCAPool(pool *x509.CertPool) {
	for _, t := range []*http.Transport{transport, basicTransport, transportNoProxy} {
		if t == nil {
			continue
		}
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.RootCAs = pool
	}
}
