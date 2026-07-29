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

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
)

// DoEvict evicts cached objects matching the given path (or prefix) from the
// local cache.  Token bootstrapping follows the same logic as DoGet: tokens
// are discovered from the environment, credential files, or negotiated via
// OAuth when needed.
//
// The remoteObject argument is a pelican:// or osdf:// URL (or a schemeless
// namespace path when federation discovery is configured).
//
// When immediate is true the objects are deleted right away; otherwise they
// are marked for priority eviction (purge-first).
func DoEvict(ctx context.Context, remoteObject string, immediate bool, options ...TransferOption) (message string, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform eviction:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoEvict: %v", r)
			err = errors.New(ret)
		}
	}()

	// Parse the URL the same way DoGet / DoPrestage do.
	dOpts := []pelican_url.DiscoveryOption{pelican_url.WithContext(ctx)}
	rpUrl, parseErr := url.Parse(remoteObject)
	if parseErr != nil {
		return "", errors.Wrap(parseErr, "failed to parse remote object URL")
	}
	if err = handleSchemelessIfNeeded(ctx, rpUrl, &dOpts); err != nil {
		return "", errors.Wrap(err, "failed to handle schemeless URL")
	}
	pUrl, parseErr := pelican_url.Parse(remoteObject,
		[]pelican_url.ParseOption{pelican_url.ValidateQueryParams(false), pelican_url.AllowUnknownQueryParams(true)},
		dOpts,
	)
	if parseErr != nil {
		return "", errors.Wrapf(parseErr, "failed to parse remote object: %s", remoteObject)
	}

	// Create a transfer engine so we can query the director for namespace
	// info and bootstrap token discovery (same as object get).
	te, engineErr := NewTransferEngine(ctx)
	if engineErr != nil {
		return "", engineErr
	}
	defer func() {
		if shutErr := te.Shutdown(); shutErr != nil {
			log.Errorln("Failure when shutting down transfer engine:", shutErr)
		}
	}()

	tc, clientErr := te.NewClient(options...)
	if clientErr != nil {
		return "", clientErr
	}

	// Resolve the pelican URL to get federation metadata.
	pelicanURL, resolveErr := ParseRemoteAsPUrl(ctx, pUrl.GetRawUrl().String())
	if resolveErr != nil {
		return "", errors.Wrap(resolveErr, "error generating metadata for specified URL")
	}

	// Query the director for namespace / issuer configuration.
	dirResp, dirErr := getDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, "", false)
	if dirErr != nil {
		return "", errors.Wrapf(dirErr, "failed to get namespace information for %s", remoteObject)
	}

	// Build a token generator using config.TokenDelete which maps to
	// storage.modify — exactly the scope the evict handler requires.
	tokenGen := NewTokenGenerator(pelicanURL, &dirResp, config.TokenDelete, !tc.skipAcquire)
	if tc.token != "" {
		tokenGen.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		tokenGen.SetTokenLocation(tc.tokenLocation)
	}

	var bearerToken string
	if dirResp.XPelNsHdr.RequireToken {
		bearerToken, err = tokenGen.Get()
		if err != nil {
			return "", errors.Wrap(err, "failed to acquire token for eviction")
		}
	} else {
		// Even for public namespaces the evict handler requires
		// storage.modify, so we still try to obtain a token.
		bearerToken, _ = tokenGen.Get()
	}

	// Determine which cache(s) to evict from.
	//
	//   - With preferred caches (the --cache flag), evict from each specified
	//     cache.  generateSortedObjServers returns exactly those caches (plus
	//     the director's list when the "+" fallback sentinel is present), so a
	//     user can target one specific cache, several, or "cache,+".
	//   - Without --cache, evict from the director's top-choice cache only.
	//     We deliberately do NOT fan out over every entry in ObjectServers by
	//     default: for direct-read namespaces that list can include origins,
	//     which have no evict endpoint, and blindly evicting against them would
	//     fail.  Targeting the full federation is done by listing the caches
	//     explicitly (or with "+").
	sortedServers, nPreferred, sortErr := generateSortedObjServers(dirResp, tc.prefObjServers)
	if sortErr != nil {
		return "", errors.Wrap(sortErr, "failed to determine which caches to evict from")
	}
	if len(sortedServers) == 0 {
		return "", errors.New("director returned no cache servers for this path")
	}

	targetServers := sortedServers
	if nPreferred == 0 {
		// No user-specified caches: preserve the historical single-cache behavior.
		targetServers = sortedServers[:1]
	}

	httpClient := &http.Client{
		Transport: config.GetTransport().Clone(),
		Timeout:   30 * time.Second,
	}

	// Fast path: a single target cache returns that cache's message (or error)
	// directly, unchanged from the historical behavior.
	if len(targetServers) == 1 {
		return evictFromCache(ctx, httpClient, targetServers[0], pelicanURL.Path, immediate, bearerToken)
	}

	// Multiple target caches: evict from each and report a per-cache summary so
	// a partial failure (e.g. one cache down) is visible rather than hidden.
	var summary strings.Builder
	var nFail int
	for _, cacheUrl := range targetServers {
		cacheMsg, evictErr := evictFromCache(ctx, httpClient, cacheUrl, pelicanURL.Path, immediate, bearerToken)
		if evictErr != nil {
			nFail++
			fmt.Fprintf(&summary, "%s: FAILED: %v\n", cacheUrl.Host, evictErr)
		} else {
			fmt.Fprintf(&summary, "%s: %s\n", cacheUrl.Host, cacheMsg)
		}
	}
	result := strings.TrimSpace(summary.String())
	if nFail > 0 {
		return "", errors.Errorf("eviction failed on %d of %d cache(s):\n%s", nFail, len(targetServers), result)
	}
	return result, nil
}

// evictFromCache issues a single evict request to one cache and returns the
// cache's response body on success.
//
// NOTE: POST or DELETE would be semantically correct for a state-changing
// operation (GET is expected to be safe/idempotent and may be cached or
// replayed by intermediaries).  However, production caches running the
// xrdhttp-pelican C++ plugin only support GET.  We use GET here for backward
// compatibility.  Once the Go-based persistent cache is ubiquitous, we should
// switch to POST or DELETE.  See: https://github.com/PelicanPlatform/pelican/pull/3121
func evictFromCache(ctx context.Context, httpClient *http.Client, cacheUrl *url.URL, objectPath string, immediate bool, bearerToken string) (string, error) {
	apiUrl := *cacheUrl
	apiUrl.Path = "/pelican/api/v1.0/evict"
	q := apiUrl.Query()
	q.Set("path", objectPath)
	if immediate {
		q.Set("immediate", "true")
	}
	apiUrl.RawQuery = q.Encode()

	log.Debugf("Invoking evict API at %s for path %s (immediate=%v)", cacheUrl.Host, objectPath, immediate)

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, apiUrl.String(), nil)
	if reqErr != nil {
		return "", errors.Wrap(reqErr, "failed to create evict request")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, doErr := httpClient.Do(req)
	if doErr != nil {
		return "", errors.Wrap(doErr, "eviction request failed")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))
	if resp.StatusCode >= 300 {
		return "", errors.Errorf("eviction failed (%d): %s", resp.StatusCode, bodyStr)
	}
	return bodyStr, nil
}
