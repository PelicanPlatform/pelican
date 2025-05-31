/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

	// Once to ensure we only set up the transport once
	onceTransport sync.Once

	// Static dialer for the transport
	dialerFunc atomic.Pointer[func(ctx context.Context, network, addr string) (net.Conn, error)]
)

// function to get/setup the transport (only once)
func GetTransport() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return transport
}

// Override the global transport's dialer function.
//
// Intended to allow the broker-aware dialer to be setup by other packages.
// Will panic if the dialerFunc is nil.
func SetTransportDialer(DialerConctext func(ctx context.Context, network, addr string) (net.Conn, error)) {
	if DialerConctext == nil {
		panic("dialerFunc cannot be nil")
	}
	dialerFunc.Store(&DialerConctext)
}

// Implement the DialContext interface for the global transport.
//
// Uses the global dialer function
func brokerDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (*dialerFunc.Load())(ctx, network, addr)
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
	dialerFunc.Store(&defaultDialerContext)

	//Set up the transport
	transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           brokerDialContext,
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
}
