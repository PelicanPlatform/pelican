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
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/pelicanplatform/pelican/param"
)

var (
	// Our global transports that only will get reconfigured if needed
	transport *http.Transport

	// Transport that avoids any broker-aware dialer
	basicTransport *http.Transport

	// The global HTTP client
	client *http.Client

	// The global non-broker-aware HTTP client
	basicClient *http.Client

	// The global HTTP client with no redirect
	clientNoRedirect *http.Client

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

// Returns the default client object configured to not follow redirects
//
// This allows special handling of redirect headers by the client
func GetClientNoRedirect() *http.Client {
	onceTransport.Do(func() {
		setupTransport()
	})
	return clientNoRedirect
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
	//Getting timeouts and other information from defaults.yaml
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
	dialerFunc.CompareAndSwap(nil, &defaultDialerContext)

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
}
