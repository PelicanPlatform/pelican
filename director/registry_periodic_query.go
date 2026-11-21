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
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	// allowedPrefixesForCaches maps cache hostnames to a set of prefixes the caches are allowed to serve
	allowedPrefixesForCaches atomic.Pointer[map[string]map[string]struct{}]
	// allowedPrefixesForCachesLastSetTimestamp tracks when allowedPrefixesForCaches was last set
	allowedPrefixesForCachesLastSetTimestamp atomic.Int64

	// registryNamespaceAds holds the namespace ads the registry advertises on
	// behalf of the namespaces whose owners stored an auth state there, as of
	// the last successful poll. Every entry carries FromRegistry = true.
	registryNamespaceAds atomic.Pointer[[]server_structs.NamespaceAd]
	// registryNamespaceAdsLastSetTimestamp tracks when registryNamespaceAds was last set
	registryNamespaceAdsLastSetTimestamp atomic.Int64
)

const (
	// registryRetryInterval is how often the registry is polled while any of
	// the data mirrored from it has never been fetched or is older than
	// registryDataStaleAfter
	registryRetryInterval  = 1 * time.Second
	registryDataStaleAfter = 15 * time.Minute
)

func init() {
	resetRegistryQueryState()
}

// resetRegistryQueryState puts the data mirrored from the registry back to its
// never-fetched state. A last-set timestamp of 0 means never set.
func resetRegistryQueryState() {
	emptyMap := make(map[string]map[string]struct{})
	allowedPrefixesForCaches.Store(&emptyMap)
	allowedPrefixesForCachesLastSetTimestamp.Store(0)

	emptyAds := []server_structs.NamespaceAd{}
	registryNamespaceAds.Store(&emptyAds)
	registryNamespaceAdsLastSetTimestamp.Store(0)
}

// allowedPrefixesInitWait bounds how long a cache advertisement will be held
// waiting for the director's allowed-prefixes data to arrive.
//
// This is not the bound that usually governs. A Pelican cache advertises with
// a client that sets no timeout of its own, so its transport does:
// Transport.ResponseHeaderTimeout, 10s by default. That client gives up first,
// the request context is cancelled, and the wait ends there -- so what
// actually decides whether an ad survives is the advertiser's timeout, not
// this constant. It sits just above that default to bound a caller willing to
// wait longer, and to keep a goroutine from being parked indefinitely by one
// that never hangs up.
//
// Widening the window is worthwhile even so: the registry fetch behind this
// retries every second, so most of what used to be refused inside 3s is now
// accepted. A registry that takes longer than the advertiser's timeout to come
// up will still cost that cache an advertisement cycle, because nothing on the
// advertising side retries -- see doAdvertise in launcher_utils/advertise.go.
const allowedPrefixesInitWait = 15 * time.Second

// waitForAllowedPrefixesForCaches blocks until the director has fetched the
// allowed prefixes for caches at least once, reporting whether it did.
//
// It returns immediately once the data is present, and gives up when the
// caller's context is cancelled or allowedPrefixesInitWait elapses.
func waitForAllowedPrefixesForCaches(ctx context.Context) bool {
	if allowedPrefixesForCachesLastSetTimestamp.Load() != 0 {
		return true
	}

	deadline := time.NewTimer(allowedPrefixesInitWait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if allowedPrefixesForCachesLastSetTimestamp.Load() != 0 {
				return true
			}
		case <-deadline.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
}

// getRegistryNamespaceAds returns the namespace ads from the last successful
// poll of the registry's advertised-namespaces endpoint, in a slice the caller
// may reorder or truncate. The entries' own slices (token issuers, token
// generation) are shared with the snapshot and must be treated as read-only.
func getRegistryNamespaceAds() []server_structs.NamespaceAd {
	return slices.Clone(*registryNamespaceAds.Load())
}

// convertListToSet converts a map of string to list of strings into a map of string to set of strings.
func convertMapOfListToMapOfSet(input map[string][]string) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for key, list := range input {
		set := make(map[string]struct{})
		for _, item := range list {
			set[item] = struct{}{}
		}
		result[key] = set
	}
	return result
}

// getFromRegistry issues a GET for apiPath, relative to /api/v1.0/registry,
// against the federation's registry. The caller owns the response body.
func getFromRegistry(ctx context.Context, apiPath string) (*http.Response, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return nil, err
	}
	registryUrl, err := url.Parse(fedInfo.RegistryEndpoint)
	if err != nil {
		return nil, err
	}
	reqUrl := registryUrl.JoinPath("/api/v1.0/registry", apiPath)

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-director/"+config.GetVersion())

	return client.Do(req)
}

// fetchAllowedPrefixesForCaches makes a request to the registry endpoint to retrieve
// information about allowed prefixes for caches and returns the result as a map with sets.
func fetchAllowedPrefixesForCaches(ctx context.Context) (map[string]map[string]struct{}, error) {
	resp, err := getFromRegistry(ctx, "caches/allowedPrefixes")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to fetch allowed prefixes for caches from the registry: unexpected status code %d", resp.StatusCode)
	}

	var result map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return convertMapOfListToMapOfSet(result), nil
}

// fetchRegistryNamespaceAds retrieves the namespace ads the registry advertises
// on behalf of the namespace owners who stored an auth state there.
func fetchRegistryNamespaceAds(ctx context.Context) ([]server_structs.NamespaceAd, error) {
	resp, err := getFromRegistry(ctx, "namespaces/advertised")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// An old registry answers 404, which is the normal state until it is
		// upgraded, so it yields an empty list rather than an error
		log.Debug("The registry does not serve the advertised-namespaces endpoint (HTTP 404), so no namespace is advertised from the registry until it is upgraded")
		return []server_structs.NamespaceAd{}, nil
	default:
		return nil, errors.Errorf("failed to fetch the advertised namespaces from the registry: unexpected status code %d", resp.StatusCode)
	}

	var ads []server_structs.NamespaceAd
	if err := json.NewDecoder(resp.Body).Decode(&ads); err != nil {
		return nil, errors.Wrap(err, "failed to decode the advertised namespaces from the registry")
	}
	return ads, nil
}

// ingestRegistryNamespaceAds prepares the ads the registry served for use as
// the director's namespace ads. This duplicates the registry’s validation as
// a second line of defense.
//   - a path that is not absolute or that names a server registration
//     (/origins/<host>, /caches/<host>), which is not a namespace.
//   - an entry that requires a token (reads without public reads, or writes)
//     but lists no token issuer.
func ingestRegistryNamespaceAds(ads []server_structs.NamespaceAd) []server_structs.NamespaceAd {
	kept := make([]server_structs.NamespaceAd, 0, len(ads))
	for _, ad := range ads {
		if !strings.HasPrefix(ad.Path, "/") || server_structs.IsServerPrefix(ad.Path) {
			log.Warningf("Ignoring a namespace advertised by the registry with the invalid path %q", ad.Path)
			continue
		}
		requiresToken := (ad.Caps.Reads && !ad.Caps.PublicReads) || ad.Caps.Writes
		if requiresToken && len(ad.Issuer) == 0 {
			log.Warningf("Ignoring the namespace %s advertised by the registry: it requires a token but lists no token issuer", ad.Path)
			continue
		}
		ad.FromRegistry = true
		ad.FromTopology = false
		kept = append(kept, ad)
	}
	return kept
}

// refreshAllowedPrefixesForCaches fetches the allowed prefixes for caches and
// stores them; on error the stored data is left as it was.
func refreshAllowedPrefixesForCaches(ctx context.Context) error {
	data, err := fetchAllowedPrefixesForCaches(ctx)
	if err != nil {
		return err
	}
	allowedPrefixesForCaches.Store(&data)
	allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())
	return nil
}

// refreshRegistryNamespaceAds fetches the namespaces the registry advertises
// and stores them; on error the stored data is left as it was.
func refreshRegistryNamespaceAds(ctx context.Context) error {
	ads, err := fetchRegistryNamespaceAds(ctx)
	if err != nil {
		return err
	}
	ads = ingestRegistryNamespaceAds(ads)
	registryNamespaceAds.Store(&ads)
	registryNamespaceAdsLastSetTimestamp.Store(time.Now().Unix())
	metrics.PelicanDirectorRegistryNamespaces.Set(float64(len(ads)))
	return nil
}

// registryDataset is one set of data the director mirrors from the registry.
type registryDataset struct {
	name    string
	refresh func(ctx context.Context) error
	lastSet *atomic.Int64 // Unix seconds of the last successful refresh; 0 when never set
}

// registryDatasets is what LaunchRegistryPeriodicQuery keeps up to date.
var registryDatasets = []registryDataset{
	{name: "allowed prefixes for caches", refresh: refreshAllowedPrefixesForCaches, lastSet: &allowedPrefixesForCachesLastSetTimestamp},
	{name: "advertised namespaces", refresh: refreshRegistryNamespaceAds, lastSet: &registryNamespaceAdsLastSetTimestamp},
}

// refreshRegistryDatasets refreshes every dataset once, each independently of
// the others, and reports whether any of them is still missing or stale
// afterwards, in which case the registry should be polled again soon.
func refreshRegistryDatasets(ctx context.Context) (stale bool) {
	for _, ds := range registryDatasets {
		if err := ds.refresh(ctx); err != nil {
			log.Warningf("Error fetching the %s from the registry: %v", ds.name, err)
			lastSet := ds.lastSet.Load()
			if lastSet == 0 || time.Since(time.Unix(lastSet, 0)) >= registryDataStaleAfter {
				log.Debugf("The %s from the registry were never fetched or are over %v old; polling at the higher frequency", ds.name, registryDataStaleAfter)
				stale = true
			}
			continue
		}
		log.Debugf("The %s from the registry were updated", ds.name)
	}
	return stale
}

// LaunchRegistryPeriodicQuery starts a goroutine that keeps the data the
// director mirrors from the registry up to date: the allowed prefixes for
// caches, and the namespaces the registry advertises on behalf of their
// owners. Both are fetched once synchronously, then at the interval set by
// Director.RegistryQueryInterval. While either has never been fetched or is
// older than 15 minutes, the registry is polled every second instead, until
// the fetch succeeds.
func LaunchRegistryPeriodicQuery(ctx context.Context, egrp *errgroup.Group) {
	refreshInterval := param.Director_RegistryQueryInterval.GetDuration()

	ticker := time.NewTicker(refreshInterval)
	if refreshRegistryDatasets(ctx) {
		ticker.Reset(registryRetryInterval)
	}

	egrp.Go(func() error {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if refreshRegistryDatasets(ctx) {
					ticker.Reset(registryRetryInterval)
				} else {
					ticker.Reset(refreshInterval)
				}
			case <-ctx.Done():
				log.Debug("Periodic fetch of the registry data terminated")
				return nil
			}
		}
	})
}
