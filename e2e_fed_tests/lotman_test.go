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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// mintLotReadToken creates a token authorized to read lots: it is issued by the
// federation discovery endpoint (which owns the auto-created lots) and signed by
// the running federation's issuer key, so it passes the lots API's
// owner-issuer + scope check. It must be minted before any helper that re-points
// IssuerKeysDirectory (e.g. getTempTokenForTest).
func mintLotReadToken(t testing.TB, ctx context.Context) string {
	t.Helper()
	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, fedInfo.DiscoveryEndpoint, "federation discovery endpoint should be set")

	cfg := token.NewWLCGToken()
	cfg.Lifetime = 10 * time.Minute
	cfg.Issuer = fedInfo.DiscoveryEndpoint
	cfg.Subject = "lot-reader"
	cfg.AddAudienceAny()
	cfg.AddScopes(token_scopes.Lot_Read)
	tok, err := cfg.CreateToken()
	require.NoError(t, err)
	return tok
}

// lotsBaseURL returns the cache server's lots API base URL.
func lotsBaseURL() string {
	return fmt.Sprintf("https://%s:%d/api/v1.0/lots",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
}

// getJSON performs an authorized GET and decodes the JSON body into out,
// returning the HTTP status code.
func getJSON(t testing.TB, ctx context.Context, url, token string, out any) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode == http.StatusOK && out != nil {
		require.NoError(t, json.Unmarshal(body, out), "decoding %s: %s", url, string(body))
	}
	return resp.StatusCode
}

// nonSentinelLots filters out the synthesized container/sentinel lots, leaving
// the namespace lots (e.g. the one covering /test).
func nonSentinelLots(names []string) []string {
	var out []string
	for _, n := range names {
		switch n {
		case "root", "default", "monitoring":
		default:
			out = append(out, n)
		}
	}
	return out
}

// TestPersistentCache_LotUsageTracked is the end-to-end lot scenario: with
// LotMan enabled on a V2 cache, objects cached under a namespace are attributed
// to that namespace's lot, and the per-lot usage is reported through the lots
// REST API. This exercises object->lot resolution, the usage reconciler, and
// the API together over a real federation.
//
// Eviction is intentionally not asserted here: object-cap trimming depends on
// the metadata-consistency scan that reconciles per-lot object counts, which has
// a hardcoded 5-minute initial delay (too slow for an e2e), and quota-driven
// eviction needs filling past the high watermark (gigabytes). The eviction path
// itself is covered deterministically by the integration test
// TestTrimObjectCapsEvicts (a real StorageManager) and the priority-ordering
// tests in local_cache.
func TestPersistentCache_LotUsageTracked(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_EnableLotman.Set(true))
	require.NoError(t, param.Lotman_EnableAPI.Set(true))
	// Enabling LotMan requires the cache sizing/watermark parameters to be set.
	require.NoError(t, param.Cache_HighWaterMark.Set("100g"))
	require.NoError(t, param.Cache_LowWatermark.Set("50g"))
	require.NoError(t, param.Cache_FilesBaseSize.Set("1g"))
	require.NoError(t, param.Cache_FilesNominalSize.Set("2g"))
	require.NoError(t, param.Cache_FilesMaxSize.Set("100g"))
	// Push per-lot usage into the lot database promptly so the assertion does
	// not have to wait the default minute.
	require.NoError(t, param.Cache_LotUsageReconcileInterval.Set(time.Second))

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Mint the lot-read token while the federation issuer key is still active
	// (getTempTokenForTest below re-points IssuerKeysDirectory).
	lotToken := mintLotReadToken(t, ft.Ctx)

	// Cache several objects under /test.
	localTmpDir := t.TempDir()
	storageToken := getTempTokenForTest(t)
	const numObjects = 4
	for i := 0; i < numObjects; i++ {
		content := strings.Repeat(fmt.Sprintf("lot-usage-object-%d-", i), 512) // a few KB
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("usage_%d.txt", i))
		require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

		objURL := fmt.Sprintf("pelican://%s:%d/test/usage_%d.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(ft.Ctx, localFile, objURL, false, client.WithToken(storageToken))
		require.NoError(t, err)

		downloadFile := filepath.Join(localTmpDir, fmt.Sprintf("dl_usage_%d.txt", i))
		_, err = client.DoGet(ft.Ctx, objURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)
	}

	// The lots API requires authentication; first confirm our token is accepted.
	var listResp struct {
		Lots []string `json:"lots"`
	}
	require.Eventually(t, func() bool {
		return getJSON(t, ft.Ctx, lotsBaseURL(), lotToken, &listResp) == http.StatusOK
	}, 30*time.Second, time.Second, "lots API should accept the lot-read token and list lots")

	nsLots := nonSentinelLots(listResp.Lots)
	require.NotEmpty(t, nsLots, "expected a namespace lot for /test; got lots %v", listResp.Lots)

	// Some namespace lot should report cached bytes (or object count) once the
	// reconciler has run.
	require.Eventually(t, func() bool {
		// Re-list each tick: renewal may mint successor lots over time.
		_ = getJSON(t, ft.Ctx, lotsBaseURL(), lotToken, &listResp)
		for _, name := range nonSentinelLots(listResp.Lots) {
			var usage struct {
				TotalGB    *struct{ Total float64 } `json:"totalGB"`
				NumObjects *struct{ Total int64 }   `json:"numObjects"`
			}
			url := fmt.Sprintf("%s/%s/usage", lotsBaseURL(), name)
			if getJSON(t, ft.Ctx, url, lotToken, &usage) != http.StatusOK {
				continue
			}
			if usage.NumObjects != nil && usage.NumObjects.Total > 0 {
				return true
			}
			if usage.TotalGB != nil && usage.TotalGB.Total > 0 {
				return true
			}
		}
		return false
	}, 60*time.Second, 2*time.Second, "a namespace lot should report non-zero cached usage via the API")

	// Sanity: the path-scoped lots endpoint authorizes and responds. (V2 lot
	// paths are federation-qualified, so a bare "/test" query resolves to the
	// catch-all default lot rather than the namespace lot; we assert only that
	// the endpoint + path-scoped auth work, not the specific lot returned.)
	code := getJSON(t, ft.Ctx, lotsBaseURL()+"/by-path?path=/test", lotToken, nil)
	assert.Equal(t, http.StatusOK, code, "by-path lookup should authorize and respond")
}
