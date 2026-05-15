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

package director

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// Run one object transfer to a cache from the director. Since director-based cache tests require a different
// workflow than the origin tests. We can't reuse server_utils.RunTests(), but we want to keep common
// pieces together.
//
// Returns the namespace-relative test file path (e.g. /pelican/monitoring/directorTest/2025-01-24/director-test-...txt)
// so the caller can evict it from the cache after the test cycle.
func runCacheTest(ctx context.Context, cacheUrl url.URL) (testFilePath string, err error) {
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	dayStr := now.Format("2006-01-02")
	dirMonPath := path.Join(server_utils.MonitoringBaseNs, server_utils.DirectorTestDir)
	testFilePath = path.Join(dirMonPath, dayStr, server_utils.DirectorTest.String()+"-"+nowStr+".txt")
	cacheUrl = *cacheUrl.JoinPath(testFilePath)
	client := config.GetClient()
	req, reqErr := http.NewRequestWithContext(ctx, "GET", cacheUrl.String(), nil)
	if reqErr != nil {
		urlErr, ok := reqErr.(*url.Error)
		if ok && urlErr.Err == context.Canceled {
			// Shouldn't return error if the error is due to context being cancelled
			return "", nil
		}
		return "", errors.Wrap(reqErr, "failed to create an HTTP request")
	}
	res, reqErr := client.Do(req)
	if reqErr != nil {
		return "", errors.Wrap(reqErr, "failed to send request to cache for the test file")
	}
	byteBody, reqErr := io.ReadAll(res.Body)
	if reqErr != nil {
		return "", errors.Wrap(reqErr, "failed to read response body. Response status code is "+res.Status)
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("cache responses with non-200 status code. Body is %s", string(byteBody))
	}
	strBody := string(byteBody)

	if strings.TrimSuffix(strBody, "\n") == server_utils.DirectorTestBody {
		return testFilePath, nil
	} else {
		return "", fmt.Errorf("cache response file does not match expectation. Expected:%s, Got:%s", server_utils.DirectorTestBody, strBody)
	}
}

// evictCacheTestFile asks the cache to evict a previously-created director test file.
// Rather than calling the xrdhttp-pelican evict API directly (which would require the
// cache's scitokens config to trust the federation issuer), this sends the eviction
// request to the cache's Pelican web API. The cache then calls its own xrdhttp-pelican
// evict API using a locally-minted token — matching the self-test authorization pattern.
//
// This avoids the privilege problem where the Pelican process cannot delete xrootd-owned
// files when Server.DropPrivileges is true: XRootD removes the file as its own user.
//
// Eviction failures are logged but not returned as errors, since a missed eviction is not
// critical — the cache-side LaunchDirectorTestFileCleanup serves as a backup.
func evictCacheTestFile(ctx context.Context, cacheWebUrl string, testFilePath string) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		log.Warningf("Failed to get federation info for evict token: %v", err)
		return
	}

	testTokenCfg := token.NewWLCGToken()
	testTokenCfg.Lifetime = time.Minute
	testTokenCfg.Issuer = fedInfo.DiscoveryEndpoint
	testTokenCfg.AddAudiences(cacheWebUrl)
	testTokenCfg.Subject = "director"
	testTokenCfg.AddScopes(token_scopes.Pelican_DirectorTestReport)

	tok, err := testTokenCfg.CreateToken()
	if err != nil {
		log.Warningf("Failed to create evict token for cache %s: %v", cacheWebUrl, err)
		return
	}

	evictUrl, err := url.Parse(cacheWebUrl)
	if err != nil {
		log.Warningf("Failed to parse cache web URL %s: %v", cacheWebUrl, err)
		return
	}
	evictUrl.Path = "/api/v1.0/cache/evictTestFile"

	reqBody, _ := json.Marshal(map[string]string{"path": testFilePath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, evictUrl.String(), bytes.NewReader(reqBody))
	if err != nil {
		log.Warningf("Failed to create evict request for cache %s: %v", cacheWebUrl, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	client := config.GetClient()
	resp, err := client.Do(req)
	if err != nil {
		log.Warningf("Failed to send evict request to cache %s: %v", cacheWebUrl, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Debugf("Successfully evicted test file %s from cache %s", testFilePath, cacheWebUrl)
	} else {
		body, _ := io.ReadAll(resp.Body)
		log.Warningf("Evict request to cache %s returned status %d: %s", cacheWebUrl, resp.StatusCode, string(body))
	}
}
