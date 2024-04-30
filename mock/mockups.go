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

//
// Create mockups of various web services
//
// Allows unit tests to run without connecting to the various "real"
// external web services
//

package mock

import (
	"context"
	"crypto/tls"
	_ "embed"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	//go:embed resources/topology-namespace.json
	topologyMock string
)

func MockOSDFDiscovery(t *testing.T, transport *http.Transport) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"director_endpoint": "https://osdf-director.osg-htc.org",
			"namespace_registration_endpoint": "https://osdf-registry.osg-htc.org",
			"jwks_uri": "https://osg-htc.org/osdf/public_signing_key.jwks"
		  }`))
		assert.NoError(t, err)
	}))
	t.Cleanup(func() {
		server.Close()
	})

	origDialContext := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		if addr == "osg-htc.org:443" {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, server.Listener.Addr().Network(), server.Listener.Addr().String())
		}
		if origDialContext == nil {
			dialer := tls.Dialer{Config: transport.TLSClientConfig}
			return dialer.DialContext(ctx, network, addr)
		}
		return origDialContext(ctx, network, addr)
	}

	t.Cleanup(func() {
		transport.DialContext = origDialContext
	})
}

func MockTopology(t *testing.T, transport *http.Transport) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(topologyMock))
		assert.NoError(t, err)
	}))
	t.Cleanup(func() {
		server.Close()
	})

	origDialContext := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		if addr == "topology.opensciencegrid.org:443" {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, server.Listener.Addr().Network(), server.Listener.Addr().String())
		}
		if origDialContext == nil {
			dialer := tls.Dialer{Config: transport.TLSClientConfig}
			return dialer.DialContext(ctx, network, addr)
		}
		return origDialContext(ctx, network, addr)
	}

	t.Cleanup(func() {
		transport.DialContext = origDialContext
	})
}
