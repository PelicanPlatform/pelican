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
	"bytes"
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
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	cacheEvictCmd = &cobra.Command{
		Use:   "evict <path>",
		Short: "Evict cached objects by path or prefix",
		Long: `Evict one or more objects from the running cache.

All objects whose path starts with (or exactly matches) the given
path are selected.  By default the selected objects are marked for
priority eviction (purge-first) so they will be removed during the
next eviction cycle.  Use --immediate to delete them right away.

The path should be an absolute namespace path (e.g. /data/file.dat or
/data/ for prefix eviction).

The command auto-generates an admin token when running on the same
host as the cache server.  Use --token to provide a token file instead.

Examples:
  pelican cache evict /data/file.dat
  pelican cache evict /data/project/
  pelican cache evict --immediate /data/project/
  pelican cache evict /data/project/ --token /path/to/token`,
		Args:         cobra.ExactArgs(1),
		RunE:         runCacheEvict,
		SilenceUsage: true,
	}

	cachePurgeCmd = &cobra.Command{
		Use:   "purge",
		Short: "Trigger LRU eviction on the running cache",
		Long: `Trigger an immediate LRU eviction cycle on the running cache.

Without --target, evicts down to the configured low water mark.
With --target, evicts down to the specified total cache size.

The --target value accepts human-readable sizes: 100GB, 500MB, 1TB, etc.

Examples:
  pelican cache purge
  pelican cache purge --target 100GB
  pelican cache purge --token /path/to/token`,
		RunE:         runCachePurge,
		SilenceUsage: true,
	}

	// Flags
	evictImmediate bool
	evictToken     string
	purgeTarget    string
	purgeToken     string
)

func init() {
	cacheCmd.AddCommand(cacheEvictCmd)
	cacheCmd.AddCommand(cachePurgeCmd)

	cacheEvictCmd.Flags().BoolVar(&evictImmediate, "immediate", false, "Delete objects immediately instead of marking them for priority eviction")
	cacheEvictCmd.Flags().StringVarP(&evictToken, "token", "t", "", "Path to token file (auto-generated if not provided)")

	cachePurgeCmd.Flags().StringVar(&purgeTarget, "target", "", "Target cache size (e.g. 100GB, 500MB); default: configured low water mark")
	cachePurgeCmd.Flags().StringVarP(&purgeToken, "token", "t", "", "Path to token file (auto-generated if not provided)")
}

// getCacheEvictToken generates a token with the appropriate scopes for
// cache eviction/purge operations.
func getCacheEvictToken(serverURL, tokenFile string, scopes []token_scopes.TokenScope, resourceScopes []token_scopes.ResourceScope) (string, error) {
	if tokenFile != "" {
		tok, err := utils.GetTokenFromFile(tokenFile)
		if err != nil {
			return "", errors.Wrapf(err, "failed to read token file %s", tokenFile)
		}
		return tok, nil
	}

	if err := initIntrospectConfig(); err != nil {
		return "", errors.Wrap(err, "failed to initialize config for token generation")
	}

	tc := token.NewWLCGToken()
	tc.Lifetime = 5 * time.Minute
	tc.Subject = "admin"
	issuerURL, issuerErr := config.GetServerIssuerURL()
	if issuerErr != nil || issuerURL == "" {
		issuerURL = serverURL
	}
	tc.Issuer = issuerURL
	tc.AddAudienceAny()
	if len(scopes) > 0 {
		tc.AddScopes(scopes...)
	}
	if len(resourceScopes) > 0 {
		tc.AddResourceScopes(resourceScopes...)
	}
	tok, err := tc.CreateToken()
	if err != nil {
		return "", errors.Wrap(err, "failed to create admin token")
	}
	return tok, nil
}

func runCacheEvict(cmd *cobra.Command, args []string) error {
	objectPath := path.Clean(args[0])
	if !path.IsAbs(objectPath) {
		return errors.New("path must be absolute (e.g. /data/file.dat)")
	}

	if err := initIntrospectConfig(); err != nil {
		return errors.Wrap(err, "failed to initialize config")
	}

	serverURL := discoverServerURL()
	if serverURL == "" {
		return errors.New("could not discover running cache server; is it running?")
	}

	// For the evict API we need a token with storage.modify scope for
	// the target path.  Generate a broad storage.modify:/ token so we
	// can evict any path.  The server re-checks authorization against
	// its own namespace configuration.
	tok, err := getCacheEvictToken(serverURL, evictToken,
		nil,
		[]token_scopes.ResourceScope{token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/")})
	if err != nil {
		return err
	}

	targetURL, err := url.Parse(serverURL)
	if err != nil {
		return errors.Wrap(err, "invalid server URL")
	}
	targetURL.Path = "/pelican/api/v1.0/evict"
	q := targetURL.Query()
	q.Set("path", objectPath)
	if evictImmediate {
		q.Set("immediate", "true")
	}
	targetURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "eviction request failed")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return errors.Errorf("eviction failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	fmt.Println(strings.TrimSpace(string(body)))
	return nil
}

func runCachePurge(cmd *cobra.Command, args []string) error {
	if err := initIntrospectConfig(); err != nil {
		return errors.Wrap(err, "failed to initialize config")
	}

	serverURL := discoverServerURL()
	if serverURL == "" {
		return errors.New("could not discover running cache server; is it running?")
	}

	tok, err := getCacheEvictToken(serverURL, purgeToken,
		[]token_scopes.TokenScope{token_scopes.Localcache_Purge, token_scopes.WebUi_Access},
		nil)
	if err != nil {
		return err
	}

	var apiPath string
	var reqBody io.Reader

	if purgeTarget != "" {
		targetBytes, parseErr := utils.ParseBytes(purgeTarget)
		if parseErr != nil {
			return errors.Errorf("invalid --target value %q: %v (examples: 100GB, 500MB, 1TB)", purgeTarget, parseErr)
		}

		apiPath = "/api/v1.0/cache/purge_to_target"
		payload, _ := json.Marshal(map[string]uint64{"target_bytes": targetBytes})
		reqBody = bytes.NewReader(payload)
		log.Infof("Purging cache to target %s (%d bytes)", purgeTarget, targetBytes)
	} else {
		apiPath = "/api/v1.0/cache/purge"
		log.Info("Purging cache to configured low water mark")
	}

	targetURL, err := url.Parse(serverURL)
	if err != nil {
		return errors.Wrap(err, "invalid server URL")
	}
	targetURL.Path = apiPath

	req, err := http.NewRequest("POST", targetURL.String(), reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "purge request failed")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var errResp server_structs.SimpleApiResp
		if json.Unmarshal(body, &errResp) == nil && errResp.Msg != "" {
			return errors.Errorf("purge failed (%d): %s", resp.StatusCode, errResp.Msg)
		}
		return errors.Errorf("purge failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if purgeTarget != "" {
		var result struct {
			FreedBytes     uint64 `json:"freed_bytes"`
			EvictedObjects int64  `json:"evicted_objects"`
		}
		if json.Unmarshal(body, &result) == nil {
			fmt.Printf("Purge complete: freed %s (%d objects evicted)\n",
				utils.HumanBytes(result.FreedBytes), result.EvictedObjects)
			return nil
		}
	}

	fmt.Println("Purge complete")
	return nil
}
