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

// directorTestFilePattern matches the only path shape the eviction endpoint should ever accept:
//
//	<MonitoringBaseNs>/<DirectorTestDir>/<director-id>/YYYY-MM-DD/director-test-<suffix>
//
// The director-id is a non-empty path segment (typically the director's hostname) that
// keeps multiple directors from colliding under a shared cache. The suffix is left
// unconstrained so that both ".txt" and ".cinfo" files are accepted. Matching against
// a strict pattern (rather than a prefix check) rejects path-traversal attempts like
// "/pelican/monitoring/../../etc/passwd", double slashes, and any filename outside the
// director-test naming convention.
var directorTestFilePattern = regexp.MustCompile(
	`^` + regexp.QuoteMeta(server_utils.MonitoringBaseNs) +
		`/` + regexp.QuoteMeta(server_utils.DirectorTestDir) +
		`/[^/]+/\d{4}-\d{2}-\d{2}/` + regexp.QuoteMeta(server_utils.DirectorTest.String()) +
		`-[^/]+$`)

// removeTestFile deletes a single director-test file. When Server.DropPrivileges is
// enabled the file is owned by the xrootd user and the pelican process cannot remove
// it directly; in that case it routes the deletion through the cache's own evict API
// (which executes under xrootd's identity). Otherwise it uses os.Remove.
func removeTestFile(ctx context.Context, fsPath string) error {
	if !param.Server_DropPrivileges.GetBool() {
		return os.Remove(fsPath)
	}
	nsPath, err := fsToNamespacePath(fsPath)
	if err != nil {
		return err
	}
	return evictViaLocalPlugin(ctx, nsPath)
}

// cleanTestDir deletes every file under dirPath, which is an old day-directory being
// removed wholesale. With privileges it uses os.RemoveAll, which wipes the directory
// and everything below it. Under DropPrivileges it evicts each file via the API and
// leaves the now-empty directories in place — xrootd reaps empty dirs on its own.
//
// Cost note in DropPrivileges mode: each file costs one evict call (a freshly minted WLCG
// token plus one HTTP GET to the local xrootd evict endpoint) issued sequentially.
// There is no batch/directory mode on that endpoint (it uses the xrdhttp-pelican
// plugin, one path per call), so the per-file cost is intrinsic here. In normal
// operation it is negligible: the maintenance loop runs every minute and trims today's
// day-directory to the latest 2 files (see cleanupOldFilesInDir), so a directory has
// aged out holding only ~6 files by the time it reaches cleanTestDir. The pathological
// case is a maintenance loop that has been dead or failing for ~a day while xrootd kept
// accepting the director's writes (15s health-test cadence => up to ~5760 test files,
// plus .cinfo companions, in a single aged-out day-dir); the first recovered pass would
// then fire thousands of sequential evict requests. That is slow but bounded and safe:
// LaunchWatcherMaintenance runs maintenance synchronously in a single goroutine, so
// passes never overlap or pile up, and the burst is self-limiting (the directory is gone
// once it drains). Do NOT reuse this on an arbitrarily large or untrimmed directory under
// DropPrivileges expecting it to be cheap. And there's room for optimization.
func cleanTestDir(ctx context.Context, dirPath string) error {
	if !param.Server_DropPrivileges.GetBool() {
		return os.RemoveAll(dirPath)
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		entryPath := filepath.Join(dirPath, entry.Name())
		// Day-directories are expected to be flat. An unexpected nested directory shouldn't
		// happen, but if one does we still recurse into it and evict its contents.
		if entry.IsDir() {
			log.Warnf("Unexpected nested directory %q under director-test day-directory; cleaning up its contents anyway", entryPath)
			if err := cleanTestDir(ctx, entryPath); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := removeTestFile(ctx, entryPath); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// fsToNamespacePath strips the cache namespace-location prefix from an absolute
// filesystem path, returning the namespace-relative path the evict API expects.
func fsToNamespacePath(fsPath string) (string, error) {
	nsLoc := strings.TrimRight(param.Cache_NamespaceLocation.GetString(), "/")
	if nsLoc == "" {
		return "", errors.New("cache namespace location is not configured")
	}
	if !strings.HasPrefix(fsPath, nsLoc+"/") {
		return "", fmt.Errorf("path %q is not under the cache namespace location", fsPath)
	}
	return strings.TrimPrefix(fsPath, nsLoc), nil
}

// cleanupDirectorTestFiles removes old director test files from the directorTest directory.
// It handles two layouts:
//   - Legacy flat files: directorTest/director-test-*.txt (pre-PR, swept entirely).
//   - Per-director daily-nested: directorTest/<id>/YYYY-MM-DD/director-test-*.txt
//     (current). Per-director subtrees are recursed into; within each, day-dirs older
//     than today are removed wholesale and today's dir is trimmed to the latest 2 files.
//
// Under Server.DropPrivileges, removals are routed through the cache's evict API
// (see removeTestFile / cleanTestDir) since the pelican process cannot directly
// delete xrootd-owned files.
func cleanupDirectorTestFiles(ctx context.Context, dirTestPath string) error {
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

	var legacyFiles []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			// Per-director subtree: directorTest/<id>/YYYY-MM-DD/...
			idDirPath := filepath.Join(dirTestPath, entry.Name())
			if err := cleanupDirectorIDSubtree(ctx, idDirPath, todayStr); err != nil {
				log.WithError(err).Warnf("Failed to clean up director subtree: %s", idDirPath)
			}
		} else if strings.HasPrefix(entry.Name(), server_utils.DirectorTest.String()) {
			// Collect legacy flat files (director-test-* files sitting directly in directorTest/)
			legacyFiles = append(legacyFiles, entry)
		}
	}

	// Clean up legacy flat files
	if len(legacyFiles) > 0 {
		for i := 0; i < len(legacyFiles); i++ {
			filePath := filepath.Join(dirTestPath, legacyFiles[i].Name())
			if err := removeTestFile(ctx, filePath); err != nil {
				log.WithError(err).Warnf("Failed to remove legacy director test file: %s", filePath)
			}
		}
	}

	return nil
}

// cleanupDirectorIDSubtree applies the daily-nested cleanup logic inside a single
// director's subtree (directorTest/<id>/YYYY-MM-DD/...). Day-directories older than
// today are removed wholesale; today's directory is trimmed to the latest 2 files
// (test file + .cinfo). The "keep 2" rule applies per-director, so multiple directors
// probing the same cache can each retain their most recent file independently.
func cleanupDirectorIDSubtree(ctx context.Context, idDirPath, todayStr string) error {
	entries, err := os.ReadDir(idDirPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !dateSubdirPattern.MatchString(entry.Name()) {
			continue
		}
		dateDir := filepath.Join(idDirPath, entry.Name())
		if entry.Name() < todayStr {
			if err := cleanTestDir(ctx, dateDir); err != nil {
				log.WithError(err).Warnf("Failed to remove old director test directory: %s", dateDir)
			}
		} else if entry.Name() == todayStr {
			if err := cleanupOldFilesInDir(ctx, dateDir, 2); err != nil {
				log.WithError(err).Warnf("Failed to clean up today's director test directory: %s", dateDir)
			}
		}
	}
	return nil
}

// cleanupOldFilesInDir removes all but the keepCount most recent files in a directory.
// Files are sorted by name (which includes an RFC3339 timestamp), so the last entries
// are the most recent.
func cleanupOldFilesInDir(ctx context.Context, dirPath string, keepCount int) error {
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
		if err := removeTestFile(ctx, filePath); err != nil {
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
		msg := "Failed to verify the token"
		if err != nil {
			msg = fmt.Sprintf("%s: %v", msg, err)
		}
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
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

	// Validate the path matches the director test file shape exactly to prevent
	// arbitrary evictions (including path-traversal attempts).
	if !directorTestFilePattern.MatchString(reqBody.Path) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path does not match the expected director test file shape",
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
//
// Note: a 200 OK response means xrootd's PFC has accepted the file as a purge candidate, not
// that the on-disk file has been unlinked. PFC defers physical removal to its periodic purge
// thread, which is gated by the configured disk-usage thresholds (pfc.diskusage). Under low
// cache pressure the data and meta blocks may persist for some time after a successful evict.
func evictViaLocalPlugin(ctx context.Context, testFilePath string) error {
	issuerUrl, err := config.GetServerIssuerURL()
	if err != nil {
		return errors.Wrap(err, "cannot mint evict token: failed to determine server issuer URL")
	}
	cacheUrl := param.Cache_Url.GetString()
	if cacheUrl == "" {
		return errors.Errorf("%s is empty; cannot call evict API", param.Cache_Url.GetName())
	}
	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuerUrl
	tokenCfg.Subject = "cache"
	// xrootd's scitokens plugin treats scope paths as relative to the issuer's
	// base_path (/pelican/monitoring), so we strip that prefix here. Passing an
	// absolute scope like /pelican/monitoring/directorTest/... gets the base path
	// prepended again, producing /pelican/monitoring/pelican/monitoring/... which
	// matches nothing. Scoping to the parent day-directory (rather than the file
	// itself) also covers companion .cinfo files within the same directory.
	relScope := strings.TrimPrefix(path.Dir(testFilePath), server_utils.MonitoringBaseNs)
	tokenCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, relScope))
	// Use the WLCG "any" audience. The cache's scitokens.cfg is generated without
	// a [Global] audience_json entry (WriteCacheScitokensConfig does not populate
	// cfg.Global.Audience the way WriteOriginScitokensConfig does), so the
	// scitokens plugin rejects tokens with any specific audience. Switching to a
	// scoped audience would require extending WriteCacheScitokensConfig to add a
	// cache-side audience first.
	tokenCfg.AddAudienceAny()

	tok, err := tokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create evict token")
	}

	evictUrl, err := url.Parse(cacheUrl)
	if err != nil {
		return errors.Wrapf(err, "failed to parse %s", param.Cache_Url.GetName())
	}
	evictUrl.Path = "/pelican/api/v1.0/evict"
	q := evictUrl.Query()
	q.Set("path", testFilePath)
	q.Set("authz", "Bearer "+tok)
	evictUrl.RawQuery = q.Encode()

	client := config.GetClient()
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
	return fmt.Errorf("evict API returned status %d: %q", resp.StatusCode, string(body))
}

// Periodically scan the directorTest directory to clean up test files.
// Handles both legacy flat files and daily-nested subdirectories (YYYY-MM-DD/).
//
// This serves as a backup cleanup mechanism. The primary cleanup is performed by the
// director, which asks the cache to evict old test files via the cache web API endpoint
// POST /api/v1.0/cache/evictTestFile (see HandleDirectorEvictRequest). This local cleanup
// catches files that the director failed to evict (e.g., due to network issues or director restarts).
//
// When Server.DropPrivileges is enabled the pelican process cannot remove xrootd-owned
// files directly, so cleanupDirectorTestFiles routes removals through the cache's evict
// API (see removeTestFile). Privilege-on deployments use os.Remove / os.RemoveAll.
func LaunchDirectorTestFileCleanup(ctx context.Context) {
	dirTestPath := filepath.Join(param.Cache_NamespaceLocation.GetString(), server_utils.MonitoringBaseNs, server_utils.DirectorTestDir)
	server_utils.LaunchWatcherMaintenance(ctx,
		[]string{dirTestPath},
		"cache director-based health test clean up",
		time.Minute,
		func(notifyEvent bool) error {
			return cleanupDirectorTestFiles(ctx, dirTestPath)
		},
	)
}
