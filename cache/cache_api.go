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

package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// Check for the sentinel file
func CheckCacheSentinelLocation() error {
	if param.Cache_SentinelLocation.IsSet() {
		sentinelPath := param.Cache_SentinelLocation.GetString()
		dataLoc := param.Cache_NamespaceLocation.GetString()
		sentinelPath = path.Clean(sentinelPath)
		if path.Base(sentinelPath) != sentinelPath {
			return errors.Errorf("invalid Cache.SentinelLocation path. File must not contain a directory. Got %s", sentinelPath)
		}
		fullPath := filepath.Join(dataLoc, sentinelPath)
		_, err := os.Stat(fullPath)
		if err != nil {
			return errors.Wrapf(err, "failed to open Cache.SentinelLocation %s. Directory check failed", fullPath)
		}
	}
	return nil
}

// dateSubdirPattern matches YYYY-MM-DD directory names used by daily-nested director test files
var dateSubdirPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// cleanupDirectorTestFiles removes old director test files from the directorTest directory.
// It handles both legacy flat files (director-test-*.txt directly in directorTest/) and
// daily-nested subdirectories (directorTest/YYYY-MM-DD/director-test-*.txt).
//
// For daily subdirectories: removes all directories older than today entirely, and within
// today's directory keeps only the two most recent files (test file + .cinfo).
// For legacy flat files: removes all if they exist.
func cleanupDirectorTestFiles(dirTestPath string) error {
	dirInfo, err := os.Stat(dirTestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to clean up yet
		}
		return err
	}
	if !dirInfo.IsDir() {
		return errors.New("director test path is not a directory: " + dirTestPath)
	}

	entries, err := os.ReadDir(dirTestPath)
	if err != nil {
		return err
	}

	todayStr := time.Now().Format("2006-01-02")

	// Collect legacy flat files (director-test-* files sitting directly in directorTest/)
	var legacyFiles []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			// Handle date subdirectories
			if !dateSubdirPattern.MatchString(entry.Name()) {
				continue
			}
			subdirPath := filepath.Join(dirTestPath, entry.Name())
			if entry.Name() < todayStr {
				// Remove entire old day directories
				if err := os.RemoveAll(subdirPath); err != nil {
					log.WithError(err).Warnf("Failed to remove old director test directory: %s", subdirPath)
				}
			} else if entry.Name() == todayStr {
				// Clean today's directory, keeping only the latest 2 files
				if err := cleanupOldFilesInDir(subdirPath, 2); err != nil {
					log.WithError(err).Warnf("Failed to clean up today's director test directory: %s", subdirPath)
				}
			}
			// Future-dated directories are left alone (shouldn't happen, but be safe)
		} else {
			// Collect legacy flat files with the director-test prefix
			if strings.HasPrefix(entry.Name(), server_utils.DirectorTest.String()) {
				legacyFiles = append(legacyFiles, entry)
			}
		}
	}

	// Clean up legacy flat files
	if len(legacyFiles) > 0 {
		for i := 0; i < len(legacyFiles); i++ {
			filePath := filepath.Join(dirTestPath, legacyFiles[i].Name())
			if err := os.Remove(filePath); err != nil {
				log.WithError(err).Warnf("Failed to remove legacy director test file: %s", filePath)
			}
		}
	}

	return nil
}

// cleanupOldFilesInDir removes all but the keepCount most recent files in a directory.
// Files are sorted by name (which includes an RFC3339 timestamp), so the last entries
// are the most recent.
func cleanupOldFilesInDir(dirPath string, keepCount int) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	var matchingFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			matchingFiles = append(matchingFiles, entry)
		}
	}

	if len(matchingFiles) <= keepCount {
		return nil
	}

	for i := 0; i < len(matchingFiles)-keepCount; i++ {
		filePath := filepath.Join(dirPath, matchingFiles[i].Name())
		if err := os.Remove(filePath); err != nil {
			log.WithError(err).Warnf("Failed to remove old test file: %s", filePath)
		}
	}
	return nil
}

// HandleDirectorEvictRequest handles eviction requests from the director. When the director
// completes a successful cache health test, it asks the cache to evict the previous test file
// via this endpoint. The cache then calls its own xrdhttp-pelican evict API using a locally-
// minted token, matching the self-test authorization pattern (see xrootd/self_monitor.go).
//
// This avoids modifying the cache's scitokens configuration to trust the federation issuer,
// since the cache already trusts its own issuer for the /pelican/monitoring namespace.
func HandleDirectorEvictRequest(ctx *gin.Context) {
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.FederationIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorTestReport},
	})
	if !ok || err != nil {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Failed to verify the token: ", err),
		})
		return
	}

	var reqBody struct {
		Path string `json:"path"`
	}
	if err := ctx.ShouldBindJSON(&reqBody); err != nil || reqBody.Path == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Missing or invalid 'path' in request body",
		})
		return
	}

	// Validate the path is under the monitoring namespace to prevent arbitrary evictions
	if !strings.HasPrefix(reqBody.Path, server_utils.MonitoringBaseNs+"/") {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path must be under " + server_utils.MonitoringBaseNs,
		})
		return
	}

	if err := evictViaLocalPlugin(ctx.Request.Context(), reqBody.Path); err != nil {
		log.Warningf("Failed to evict director test file %s: %v", reqBody.Path, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Eviction failed: " + err.Error(),
		})
		return
	}

	log.Debugf("Successfully evicted director test file via local plugin: %s", reqBody.Path)
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Eviction successful",
	})
}

// evictViaLocalPlugin calls the cache's own xrdhttp-pelican evict API with a locally-minted
// token. This mirrors how the cache self-test (xrootd/self_monitor.go generateFileTestScitoken)
// accesses its own XRootD port using the server's own issuer, which is already trusted by the
// cache's scitokens configuration.
func evictViaLocalPlugin(ctx context.Context, testFilePath string) error {
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	if issuerUrl == "" {
		return errors.New("Server_ExternalWebUrl is empty; cannot mint evict token")
	}

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuerUrl
	tokenCfg.Subject = "cache"
	tokenCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"))
	tokenCfg.AddAudienceAny()

	tok, err := tokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create evict token")
	}

	cacheUrl := param.Cache_Url.GetString()
	if cacheUrl == "" {
		return errors.New("Cache.Url is empty; cannot call evict API")
	}

	evictUrl, err := url.Parse(cacheUrl)
	if err != nil {
		return errors.Wrap(err, "failed to parse Cache.Url")
	}
	evictUrl.Path = "/pelican/api/v1.0/evict"
	q := evictUrl.Query()
	q.Set("path", testFilePath)
	q.Set("authz", "Bearer "+tok)
	evictUrl.RawQuery = q.Encode()

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, evictUrl.String(), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create evict request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send evict request")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("evict API returned status %d: %s", resp.StatusCode, string(body))
}

// Periodically scan the directorTest directory to clean up test files.
// Handles both legacy flat files and daily-nested subdirectories (YYYY-MM-DD/).
//
// This serves as a backup cleanup mechanism. The primary cleanup is performed by the
// director, which asks the cache to evict old test files via the cache web API endpoint
// POST /api/v1.0/cache/evictTestFile (see HandleDirectorEvictRequest). This local cleanup
// catches files that the director failed to evict (e.g., due to network issues or director restarts).
//
// Note: when Server.DropPrivileges is true, this function is a no-op because the Pelican
// process cannot delete files owned by the xrootd user. In that case, the director-side
// evict API is the only cleanup path.
func LaunchDirectorTestFileCleanup(ctx context.Context) {
	// Skip if drop privileges is enabled, because Director test files are owned by the xrootd user.
	// The unprivileged pelican user does not have permission to remove them.
	if param.Server_DropPrivileges.GetBool() {
		return
	}
	dirTestPath := filepath.Join(param.Cache_NamespaceLocation.GetString(), server_utils.MonitoringBaseNs, server_utils.DirectorTestDir)
	server_utils.LaunchWatcherMaintenance(ctx,
		[]string{dirTestPath},
		"cache director-based health test clean up",
		time.Hour,
		func(notifyEvent bool) error {
			return cleanupDirectorTestFiles(dirTestPath)
		},
	)
}
