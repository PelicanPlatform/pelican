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

package test_utils

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// StubFederation is one TLS server playing every federation role a client
// transfer touches: the discovery document, the director, and the object
// server the director redirects to.  Every object under the namespace /test
// exists and holds the same contents.
//
// It is for exercising the client against a federation without starting one.
// MockFederationRoot covers discovery alone and turns certificate verification
// off to do it; this covers the director and the object server as well, and
// is verified the way a client verifies a production federation.
type StubFederation struct {
	// URL is the federation's discovery URL, which is also where its
	// director and object server answer.
	URL string
	// CAFile is the CA that signed the server's certificate.
	CAFile string
	// DirectorQueries counts the questions put to the director.
	DirectorQueries atomic.Int64

	server *httptest.Server
}

// StubFederationOptions configures a StubFederation.
type StubFederationOptions struct {
	// Contents is what every object holds.
	Contents string
	// RequireToken makes the director say the namespace wants a credential.
	RequireToken bool
	// OnFetch, if set, is called on each object fetch with the object's
	// federation path, before anything is written.  A non-zero return fails
	// the fetch with that status; zero lets it succeed.  Fetches run
	// concurrently, so it must be safe for concurrent use.
	OnFetch func(objectPath string) int
}

// NewStubFederation starts a stub federation for the duration of t.
func NewStubFederation(t *testing.T, opts StubFederationOptions) *StubFederation {
	t.Helper()
	sf := &StubFederation{}
	sf.server, sf.CAFile = startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server's own address, read off the request rather than off sf:
		// sf.URL is only assigned once the server is already serving, and a
		// network round trip is not an ordering the race detector can see.
		self := "https://" + r.Host
		switch {
		case r.URL.Path == "/.well-known/pelican-configuration":
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprintf(w, `{"director_endpoint": "%s"}`, self)
			assert.NoError(t, err)

		case r.Method == "PROPFIND":
			// A stat, answered by the object server: an object, not a
			// collection.
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, err := fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>%d</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
`, r.URL.Path, len(opts.Contents))
			assert.NoError(t, err)

		case strings.HasPrefix(r.URL.Path, "/download/"):
			if r.Method != http.MethodHead && opts.OnFetch != nil {
				if status := opts.OnFetch(strings.TrimPrefix(r.URL.Path, "/download")); status != 0 {
					w.WriteHeader(status)
					return
				}
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(opts.Contents)))
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, err := w.Write([]byte(opts.Contents))
				assert.NoError(t, err)
			}

		case strings.HasPrefix(r.URL.Path, "/test/"):
			// The director.  It redirects to this same server wearing the
			// object server's hat.
			sf.DirectorQueries.Add(1)
			w.Header().Set("Link", fmt.Sprintf(`<%s/download%s>; rel="duplicate"; pri=1; depth=1`, self, r.URL.Path))
			w.Header().Set("Location", self+"/download"+r.URL.Path)
			w.Header().Set("X-Pelican-Namespace", fmt.Sprintf("namespace=/test, require-token=%t", opts.RequireToken))
			w.WriteHeader(http.StatusTemporaryRedirect)

		default:
			t.Errorf("stub federation received an unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	sf.URL = sf.server.URL
	return sf
}

// InitClient initializes the client against the stub, discovering through it
// and trusting the CA that signed its certificate.  extra adds the test's own
// parameters.
func (sf *StubFederation) InitClient(t *testing.T, extra map[param.Param]any) {
	t.Helper()
	_, err := config.SetPreferredPrefix(config.PelicanPrefix)
	require.NoError(t, err)
	cfg := map[param.Param]any{
		param.Federation_DiscoveryUrl:     sf.URL,
		param.Server_TLSCACertificateFile: sf.CAFile,
	}
	for p, v := range extra {
		cfg[p] = v
	}
	InitClient(t, cfg)
}

// startTrustedTLSServer serves handler over TLS with a host certificate signed
// by a CA minted the way a Pelican server mints its own (config.GenerateCACert
// and config.GenerateCert), and returns the CA for the client to trust.
//
// It has to run before the client is initialized: the client builds its
// transport, and with it the set of CAs it trusts, at initialization.  The
// parameters set here only tell the generators where to write; initializing
// the client resets them, and the files are what persist.
func startTrustedTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "tlsca.pem")
	require.NoError(t, param.Server_TLSCACertificateFile.Set(caFile))
	require.NoError(t, param.Server_TLSCAKey.Set(filepath.Join(dir, "tlsca.key")))
	require.NoError(t, param.Server_TLSCertificateChain.Set(filepath.Join(dir, "tls.crt")))
	require.NoError(t, param.Server_TLSKey.Set(filepath.Join(dir, "tls.key")))
	// httptest listens on the loopback address, so that is the name the
	// certificate has to carry.
	require.NoError(t, param.Server_Hostname.Set("127.0.0.1"))
	require.NoError(t, config.GenerateCACert())
	require.NoError(t, config.GenerateCert())

	cert, err := tls.LoadX509KeyPair(param.Server_TLSCertificateChain.GetString(), param.Server_TLSKey.GetString())
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, caFile
}
