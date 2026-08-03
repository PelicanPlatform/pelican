//go:build server && !windows

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

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestStandaloneOriginServe brings up an origin with Origin.EnableStandaloneMode
// and no federation reachable at all -- no Federation.DiscoveryUrl, no director,
// no registry -- and verifies that it still serves objects under Pelican's
// managed authorization.
//
// The absence of any federation configuration is the point of the test: on a
// non-standalone origin, startup gets as far as federation discovery and then
// fails, so simply reaching a served object proves that every federation
// touchpoint was skipped rather than merely tolerated.
func TestStandaloneOriginServe(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	tmpPath := t.TempDir()
	storageDir := t.TempDir()

	// Certificate verification stays on: the origin generates its own CA during
	// startup and records it in Server.TLSCACertificateFile, which every client
	// built from config.GetTransport() in this process already trusts.  Turning
	// verification off would hide a discovery document that named a host the
	// certificate does not cover.
	require.NoError(t, param.MultiSet(map[string]any{
		param.ConfigBase.GetName():         tmpPath,
		param.RuntimeDir.GetName():         tmpPath,
		param.Origin_RunLocation.GetName(): filepath.Join(tmpPath, "xrd"),
		param.Logging_Level.GetName():      "Debug",
		param.Server_EnableUI.GetName():    false,
		param.Server_WebPort.GetName():     0,
		param.Origin_DbLocation.GetName():  filepath.Join(tmpPath, "origin.sqlite"),

		// The native POSIX backend, served in-process, with no federation behind it.
		param.Origin_StorageType.GetName():          "posixv2",
		param.Origin_StoragePrefix.GetName():        storageDir,
		param.Origin_FederationPrefix.GetName():     "/standalone",
		param.Origin_EnablePublicReads.GetName():    true,
		param.Origin_EnableWrites.GetName():         true,
		param.Origin_EnableStandaloneMode.GetName(): true,
	}))

	_, shutdownCancel, err := launchers.LaunchModules(ctx, server_structs.OriginType)
	require.NoError(t, err)
	defer shutdownCancel()

	require.True(t, config.IsStandaloneOrigin())
	webUrl := param.Server_ExternalWebUrl.GetString()
	httpc := http.Client{Transport: config.GetTransport()}

	t.Run("federation-endpoints-are-empty", func(t *testing.T) {
		fedInfo, err := config.GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, webUrl, fedInfo.DiscoveryEndpoint)
		assert.Empty(t, fedInfo.DirectorEndpoint)
		assert.Empty(t, fedInfo.RegistryEndpoint)
	})

	t.Run("public-read-serves-object-at-its-federation-prefix", func(t *testing.T) {
		const contents = "standalone origins still serve objects\n"
		require.NoError(t, os.WriteFile(filepath.Join(storageDir, "hello.txt"), []byte(contents), 0644))

		// No director shares this web server, so the object is served from the
		// URL the client already constructed -- no redirect, no relocated data
		// route. Use a non-following client so a redirect would fail the test
		// rather than be silently followed.
		noRedirect := http.Client{
			Transport: config.GetTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirect.Get(webUrl + "/standalone/hello.txt")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		assert.Equal(t, contents, string(body))

		// The namespace metadata rides on the object's own response: with no
		// director, this is the only place a client can learn the namespace and
		// whether it needs a token.
		assert.Contains(t, resp.Header.Get("X-Pelican-Namespace"), "namespace=/standalone")
		assert.Contains(t, resp.Header.Get("X-Pelican-Namespace"), "require-token=false")
	})

	t.Run("discovery-names-no-director", func(t *testing.T) {
		resp, err := httpc.Get(webUrl + "/.well-known/pelican-configuration")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var fed struct {
			DiscoveryEndpoint string `json:"discovery_endpoint"`
			DirectorEndpoint  string `json:"director_endpoint"`
			RegistryEndpoint  string `json:"namespace_registration_endpoint"`
			JwksUri           string `json:"jwks_uri"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&fed))
		assert.Equal(t, webUrl, fed.DiscoveryEndpoint)
		assert.Empty(t, fed.DirectorEndpoint,
			"naming no director is what tells a client to resolve objects against this origin directly")
		assert.Empty(t, fed.RegistryEndpoint, "nothing serves registry APIs here")
		assert.Equal(t, webUrl+"/.well-known/issuer.jwks", fed.JwksUri)
	})

	t.Run("write-requires-locally-issued-token", func(t *testing.T) {
		uploadUrl := webUrl + "/standalone/uploaded.txt"

		// Without a token the write is refused: standalone mode disconnects the
		// origin from the federation, it does not disable authorization.
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadUrl, strings.NewReader("nope"))
		require.NoError(t, err)
		resp, err := httpc.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// A token from this origin's own issuer (the only issuer there is) works.
		tokCfg := token.NewWLCGToken()
		tokCfg.Issuer = webUrl
		tokCfg.Subject = "test-user"
		tokCfg.Lifetime = 5 * time.Minute
		tokCfg.AddAudiences("https://wlcg.cern.ch/jwt/v1/any")
		tokCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"))
		tok, err := tokCfg.CreateToken()
		require.NoError(t, err)

		const contents = "written through the standalone origin\n"
		req, err = http.NewRequestWithContext(ctx, http.MethodPut, uploadUrl, strings.NewReader(contents))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = httpc.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Less(t, resp.StatusCode, 300, string(body))

		written, err := os.ReadFile(filepath.Join(storageDir, "uploaded.txt"))
		require.NoError(t, err)
		assert.Equal(t, contents, string(written))
	})

	t.Run("rejection-hints-at-the-token-it-wants", func(t *testing.T) {
		// A refused client still has to discover which issuer would mint a
		// usable token. With no director in the deployment, these headers on the
		// rejection are the only place that information can come from.
		// Reads on this export are public, so exercise the auth path with a write.
		objectUrl := webUrl + "/standalone/hinted.txt"

		// No token at all: 401, because retrying without new information would
		// just loop.
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, objectUrl, strings.NewReader("x"))
		require.NoError(t, err)
		resp, err := httpc.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("X-Pelican-Authorization"), "issuer=")

		// A token that does not authorize: 403, which is the status the client's
		// token-hint retry keys on.
		badTokCfg := token.NewWLCGToken()
		badTokCfg.Issuer = webUrl
		badTokCfg.Subject = "test-user"
		badTokCfg.Lifetime = 5 * time.Minute
		badTokCfg.AddAudiences("https://wlcg.cern.ch/jwt/v1/any")
		badTokCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/nonexistent"))
		badTok, err := badTokCfg.CreateToken()
		require.NoError(t, err)

		req, err = http.NewRequestWithContext(ctx, http.MethodPut, objectUrl, strings.NewReader("x"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+badTok)
		resp, err = httpc.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// Either way the hints describe where to authenticate.
		assert.Contains(t, resp.Header.Get("X-Pelican-Namespace"), "namespace=/standalone")
		assert.Contains(t, resp.Header.Get("X-Pelican-Authorization"), "issuer=")
		assert.Contains(t, resp.Header.Get("X-Pelican-Token-Generation"), "issuer=")
	})

	t.Run("web-api-reports-standalone", func(t *testing.T) {
		resp, err := httpc.Get(webUrl + "/api/v1.0/servers")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var payload struct {
			Servers          []string `json:"servers"`
			StandaloneOrigin bool     `json:"standaloneOrigin"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
		assert.Equal(t, []string{"origin"}, payload.Servers)
		assert.True(t, payload.StandaloneOrigin)
	})

	t.Run("local-metadata-carries-a-server-name", func(t *testing.T) {
		// The record is normally a side effect of advertising to a director;
		// without it the web UI's ServerName lookup 404s on every page load.
		metadata, err := database.GetServerLocalMetadata()
		require.NoError(t, err)
		assert.NotEmpty(t, metadata.Name)
		assert.Equal(t, "origin", metadata.Type)
	})

	t.Run("pelican-client-transfers-objects", func(t *testing.T) {
		// The client speaks only pelican://, and it normally resolves an object
		// by asking the federation's discovery endpoint for a director and then
		// asking that director who serves the object. This federation's discovery
		// document names no director, so the client addresses the object to the
		// discovery host itself and asks nobody first (client.resolveWithoutDirector),
		// learning anything it still needs from the origin's own reply. Everything
		// above drives the origin's handlers with a hand-built HTTP client; this
		// subtest is what proves the real client library takes the directorless
		// path and completes.
		require.NoError(t, config.InitClient())
		host := strings.TrimPrefix(webUrl, "https://")

		const contents = "fetched by the pelican client\n"
		require.NoError(t, os.WriteFile(filepath.Join(storageDir, "client.txt"), []byte(contents), 0644))

		downloadDir := t.TempDir()
		results, err := client.DoGet(ctx, "pelican://"+host+"/standalone/client.txt",
			filepath.Join(downloadDir, "client.txt"), false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		got, err := os.ReadFile(filepath.Join(downloadDir, "client.txt"))
		require.NoError(t, err)
		assert.Equal(t, contents, string(got))

		// An upload takes the same directorless resolution -- a metadata HEAD,
		// then the transfer against the URL the client already had -- but writes
		// are never public, so it also covers the authorized half of that path.
		const uploaded = "uploaded by the pelican client\n"
		srcPath := filepath.Join(t.TempDir(), "upload.txt")
		require.NoError(t, os.WriteFile(srcPath, []byte(uploaded), 0644))

		tokCfg := token.NewWLCGToken()
		tokCfg.Issuer = webUrl
		tokCfg.Subject = "test-user"
		tokCfg.Lifetime = 5 * time.Minute
		tokCfg.AddAudiences("https://wlcg.cern.ch/jwt/v1/any")
		tokCfg.AddResourceScopes(
			token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"),
			token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"),
		)
		tok, err := tokCfg.CreateToken()
		require.NoError(t, err)

		_, err = client.DoPut(ctx, srcPath, "pelican://"+host+"/standalone/client-upload.txt", false,
			client.WithToken(tok))
		require.NoError(t, err)
		written, err := os.ReadFile(filepath.Join(storageDir, "client-upload.txt"))
		require.NoError(t, err)
		assert.Equal(t, uploaded, string(written))

		// Stat and list resolve the namespace the same way and then issue HEAD
		// and PROPFIND against the origin's own WebDAV routes -- the collections
		// URL in the namespace metadata is this origin, since nothing else in
		// the deployment could serve a listing.
		info, err := client.DoStat(ctx, "pelican://"+host+"/standalone/client.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(len(contents)), info.Size)

		listed, err := client.DoList(ctx, "pelican://"+host+"/standalone")
		require.NoError(t, err)
		names := make([]string, 0, len(listed))
		for _, fi := range listed {
			names = append(names, path.Base(fi.Name))
		}
		assert.Contains(t, names, "client.txt")
		assert.Contains(t, names, "client-upload.txt")
	})

	// Disk usage for the remote-protocol backends used to be measured by
	// pointing the Pelican client at the origin's own namespace, which needed a
	// federation to route through and a transfer engine to build.  Nothing on a
	// serve path calls config.InitClient, so that walk could not run outside a
	// test harness that had called it -- and a standalone origin was refused
	// outright.  It reads the backend directly now.
	t.Run("disk-usage-walks-the-backend-without-a-client", func(t *testing.T) {
		require.NoError(t, param.Origin_EnableDiskUsageCalculation.Set(true))

		// Write into the backing store directly rather than relying on an
		// earlier subtest, and into a subdirectory so the walk has to recurse.
		nested := filepath.Join(storageDir, "usage", "deep")
		require.NoError(t, os.MkdirAll(nested, 0755))
		const measured = "counted by the disk usage walk\n"
		require.NoError(t, os.WriteFile(filepath.Join(nested, "sized.txt"), []byte(measured), 0644))

		// An origin process never initializes the client; earlier subtests here
		// did, so undo that.  If the walk ever goes back over the network this
		// fails the way it would in production rather than passing on the
		// harness's leftovers.
		config.ResetClientInitialized()
		t.Cleanup(func() { require.NoError(t, config.InitClient()) })
		require.False(t, config.IsClientInitialized())

		require.NoError(t, origin.CalculateDiskUsage(ctx, true))

		// The walk logs its failures and returns nil, so "no error" says
		// nothing on its own; assert it found what earlier subtests wrote.
		objects := testutil.ToFloat64(origin.PelicanOriginDiskUsageObjects.WithLabelValues("/standalone"))
		assert.GreaterOrEqual(t, objects, float64(1), "the crawl reported no objects, so it walked nothing")
		bytes := testutil.ToFloat64(origin.PelicanOriginDiskUsageBytes.WithLabelValues("/standalone"))
		assert.GreaterOrEqual(t, bytes, float64(len(measured)),
			"the crawl missed the nested file, so it did not recurse")
		errs := testutil.ToFloat64(origin.PelicanOriginDiskUsageCrawlErrors.WithLabelValues("/standalone"))
		assert.Zero(t, errs, "the crawl hit errors while walking")
	})
}
