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

package fed_tests

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// webEngineAddrRe matches the address the web engine binds to, e.g.
// "Starting web engine at address my-host:55309".  The child is told to bind
// port 0 (any free port), and pelican rewrites Server.WebPort to the chosen
// value before logging this line — so reading it back avoids racily
// pre-selecting a port that another process could grab before the child binds.
var webEngineAddrRe = regexp.MustCompile(`web engine at address \S*?:(\d+)`)

// upstreamCacheHasObject probes a cache via HTTP HEAD with
// Cache-Control: only-if-cached (RFC 7234 §5.2.1.7): the cache returns 200 if
// it already holds the object and 504 if it does not, without ever contacting
// the origin.  This lets the test inspect cache contents through the public
// cache API rather than poking at on-disk storage.
//
// cacheDataBase is the cache's /api/v1.0/cache/data/<discovery> endpoint.
// It returns (true, nil) when the cache holds the object, (false, nil) when it
// does not, and a non-nil error on transport failures or an unexpected status.
// Returning an error (rather than failing the test) keeps it safe to call from
// inside a require.Eventually closure, which runs on a separate goroutine.
func upstreamCacheHasObject(ctx context.Context, httpClient *http.Client, cacheDataBase, objectPath, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cacheDataBase+objectPath, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Cache-Control", "only-if-cached")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusGatewayTimeout:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected only-if-cached status %d for %s", resp.StatusCode, objectPath)
	}
}

// TestPersistentCacheSiteLocalFetchesFromCache verifies the site-local-mode
// behaviour of the V2 (persistent) cache: a site-local cache must appear to the
// federation as a client and fetch objects from other caches rather than
// directly from origins (matching the V1 XRD_PELICANDIRECTORYQUERYMODE=cache
// behaviour).
//
// Topology:
//   - An in-process federation (director + origin + an advertised V2 cache).
//     This advertised cache is the "upstream" cache.
//   - A separate `pelican cache serve` child process running a V2 cache with
//     Cache.EnableSiteLocalMode=true.  It is NOT advertised to the director.
//
// The test downloads a public object through the site-local cache and then
// asserts (via Cache-Control: only-if-cached) that the *upstream* cache also
// ended up holding the object.  That can only happen if the site-local cache
// fetched the object through the upstream cache (client mode); if it had
// fetched directly from the origin (the pre-fix embedded-cache behaviour), the
// upstream cache would never have seen the object.
func TestPersistentCacheSiteLocalFetchesFromCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Build the pelican binary used for the site-local cache child process.
	cliPath := getPelicanBinary(t)

	// Enable the persistent cache for the in-process (upstream) cache.
	require.NoError(t, param.Cache_EnableV2.Set(true))

	// Start the federation: director + origin + advertised V2 cache.
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0, "Federation should have at least one export")

	// Capture the configuration the child process needs to inherit from the
	// running federation.  By reusing the federation's CA and host certificate
	// (the host certificate is for the hostname and is not port-specific) the
	// child cache is mutually trusted with the test process and the rest of the
	// federation.
	hostname := param.Server_Hostname.GetString()
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	caCert := param.Server_TLSCACertificateFile.GetString()
	caKey := param.Server_TLSCAKey.GetString()
	tlsCert := param.Server_TLSCertificateChain.GetString()
	tlsKey := param.Server_TLSKey.GetString()
	issuerKeysDir := param.IssuerKeysDirectory.GetString()

	// Directories for the site-local cache child process.  The child binds an
	// arbitrary free port (Server.WebPort: 0); its actual URL is discovered
	// from its output once it starts.
	childDir := t.TempDir()
	childStorage := filepath.Join(childDir, "storage")

	// Build a config file for the child cache.  It inherits federation
	// discovery and TLS material from the parent and overrides ports,
	// storage locations and the cache flags under test.
	childConfig := map[string]any{
		"Federation": map[string]any{
			"DiscoveryUrl": discoveryUrl,
		},
		"Logging": map[string]any{
			"Level": "debug",
		},
		"TLSSkipVerify":       false,
		"ConfigDir":           childDir,
		"RuntimeDir":          childDir,
		"IssuerKeysDirectory": issuerKeysDir,
		"Server": map[string]any{
			"Hostname": hostname,
			// Bind any free port; pelican rewrites WebPort/ExternalWebUrl to
			// the chosen value, which we read back from the child's output.
			"WebPort":              0,
			"ExternalWebUrl":       "https://" + hostname,
			"EnableUI":             false,
			"TLSCACertificateFile": caCert,
			"TLSCAKey":             caKey,
			"TLSCertificateChain":  tlsCert,
			"TLSKey":               tlsKey,
		},
		"Cache": map[string]any{
			"EnableV2":                 true,
			"EnableSiteLocalMode":      true,
			"StorageLocation":          childStorage,
			"DbLocation":               filepath.Join(childDir, "cache.sqlite"),
			"RunLocation":              filepath.Join(childDir, "run"),
			"Port":                     0,
			"EnableLotman":             false,
			"EnableEvictionMonitoring": false,
			"SelfTest":                 false,
		},
	}

	childConfigBytes, err := yaml.Marshal(childConfig)
	require.NoError(t, err)
	childConfigPath := filepath.Join(childDir, "site-local-cache.yaml")
	require.NoError(t, os.WriteFile(childConfigPath, childConfigBytes, 0644))

	// Launch the site-local cache child process.  It is tied to the federation
	// context so it is torn down when the test's context is cancelled.
	var childOutput bytes.Buffer
	var outputMu sync.Mutex
	cmd := exec.CommandContext(ft.Ctx, cliPath, "cache", "serve", "--config", childConfigPath)
	cmd.Env = os.Environ()
	cmd.Stdout = &lockedWriter{w: &childOutput, mu: &outputMu}
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start(), "failed to start site-local cache process")
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		outputMu.Lock()
		defer outputMu.Unlock()
		if t.Failed() {
			t.Logf("site-local cache process output:\n%s", childOutput.String())
		}
	})
	childOutputSnapshot := func() string {
		outputMu.Lock()
		defer outputMu.Unlock()
		return childOutput.String()
	}

	// Discover the port the child bound to by reading it back from its output,
	// then build its URL.  This avoids pre-selecting a port (which would race
	// with other processes between selection and the child's bind).
	var childCacheUrl string
	require.Eventually(t, func() bool {
		m := webEngineAddrRe.FindStringSubmatch(childOutputSnapshot())
		if m == nil {
			return false
		}
		childCacheUrl = fmt.Sprintf("https://%s:%s", hostname, m[1])
		return true
	}, 60*time.Second, 200*time.Millisecond, "site-local cache never reported its web port")

	// Wait for the site-local cache's object-serving handlers to be registered.
	// The /api/v1.0/cache/stats endpoint is registered by RegisterCacheHandlers,
	// so a 200 there means the cache (not just the bare web engine, which serves
	// /api/v1.0/health much earlier) is ready to serve objects.
	httpClient := &http.Client{Transport: config.GetTransport()}
	readyUrl := childCacheUrl + "/api/v1.0/cache/stats"
	require.Eventually(t, func() bool {
		req, reqErr := http.NewRequestWithContext(ft.Ctx, http.MethodGet, readyUrl, nil)
		if reqErr != nil {
			return false
		}
		resp, doErr := httpClient.Do(req)
		if doErr != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 90*time.Second, 500*time.Millisecond, "site-local cache did not become ready")

	// Mint a read token for the object (signed by the federation's issuer key,
	// which both caches validate via the issuer's published JWKS).
	readToken := mintReadToken(t)

	// The upstream cache's public object endpoint.  We probe it with
	// only-if-cached to inspect its contents without triggering an origin fetch.
	// The cache derives its default federation identity from
	// fedInfo.DiscoveryEndpoint (see persistent_cache.NewPersistentCache), so
	// the /cache/data/<discovery> path segment must carry the discovery
	// server's host:port -- which in this harness is a separate httptest.Server
	// distinct from the director's web URL.
	discoveryHost := hostnameFromDiscovery(t, discoveryUrl)
	webUrl := param.Server_ExternalWebUrl.GetString()
	upstreamCacheData := webUrl + "/api/v1.0/cache/data/" + url.PathEscape(discoveryHost)
	const objectPath = "/test/hello_world.txt"

	// Precondition: the upstream cache must not already hold the object.
	cached, err := upstreamCacheHasObject(ft.Ctx, httpClient, upstreamCacheData, objectPath, readToken)
	require.NoError(t, err)
	require.False(t, cached, "upstream cache should not hold the object before the download")

	// Download the public object through the site-local cache by forcing the
	// client to use it as the (only) cache.  Client.PreferredCaches takes a bare
	// cache host:port and the client fills in the object path, so the override
	// URL is just the site-local cache's host:port.
	objectURL := fmt.Sprintf("pelican://%s%s", discoveryHost, objectPath)
	childCacheParsed, err := url.Parse(childCacheUrl)
	require.NoError(t, err)

	downloadDir := t.TempDir()
	downloadFile := filepath.Join(downloadDir, "hello_world.txt")
	results, err := client.DoGet(ft.Ctx, objectURL, downloadFile, false,
		client.WithCaches(childCacheParsed), client.WithToken(readToken))
	require.NoError(t, err, "download through site-local cache failed")
	require.NotEmpty(t, results)

	content, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(content), "downloaded content should match origin")

	// The decisive assertion: the upstream cache must now hold the object,
	// proving the site-local cache fetched it through the upstream cache rather
	// than directly from the origin (the latter being the pre-fix embedded-cache
	// behaviour).  Caching upstream is asynchronous, so poll via only-if-cached.
	require.Eventually(t, func() bool {
		has, probeErr := upstreamCacheHasObject(ft.Ctx, httpClient, upstreamCacheData, objectPath, readToken)
		return probeErr == nil && has
	}, 30*time.Second, 500*time.Millisecond,
		"upstream cache never received the object; site-local cache appears to have fetched directly from the origin")
}

// mintReadToken creates a short-lived WLCG read token signed by the running
// federation's issuer key.  Unlike getTempTokenForTest it does NOT reset
// IssuerKeysDirectory, so the token is signed by the key the federation
// actually published (and which the child cache can therefore verify).
func mintReadToken(t testing.TB) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = 5 * time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	tokConf.AddScopes(readScope)

	tkn, err := tokConf.CreateToken()
	require.NoError(t, err)
	return tkn
}

// hostnameFromDiscovery extracts the host:port of the federation from its
// discovery URL so object URLs can be addressed against it.
func hostnameFromDiscovery(t testing.TB, discoveryUrl string) string {
	t.Helper()
	u, err := url.Parse(discoveryUrl)
	require.NoError(t, err)
	return u.Host
}

// lockedWriter serialises writes to an underlying buffer so the child
// process's stdout and stderr can share one buffer safely.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
