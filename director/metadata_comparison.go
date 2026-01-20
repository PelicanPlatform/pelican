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

package director

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

type (
	// UrlMismatch describes a mismatch between Director and Discovery URL values
	UrlMismatch struct {
		DirectorValue  string `json:"directorValue"`  // What the Director serves
		DiscoveryValue string `json:"discoveryValue"` // What the Discovery URL serves
	}

	// MetadataDiscrepancy holds the result of comparing Director and Discovery URL metadata
	MetadataDiscrepancy struct {
		HasDiscrepancy      bool         `json:"hasDiscrepancy"`
		DirectorUrlMismatch *UrlMismatch `json:"directorUrlMismatch,omitempty"`
		RegistryUrlMismatch *UrlMismatch `json:"registryUrlMismatch,omitempty"`
		JwksHasOverlap      bool         `json:"jwksHasOverlap"`      // true = at least one key matches
		JwksOverlapChecked  bool         `json:"jwksOverlapChecked"`  // false if couldn't fetch JWKS
		JwksError           string       `json:"jwksError,omitempty"` // error message if JWKS check failed
		LastChecked         time.Time    `json:"lastChecked"`
		DiscoveryUrl        string       `json:"discoveryUrl"`
		Enabled             bool         `json:"enabled"` // false if Director is the discovery URL
	}
)

var (
	// currentMetadataDiscrepancy stores the latest metadata comparison result
	currentMetadataDiscrepancy     *MetadataDiscrepancy
	currentMetadataDiscrepancyLock sync.RWMutex
)

func init() {
	// Initialize with a default state indicating comparison hasn't run yet
	currentMetadataDiscrepancy = &MetadataDiscrepancy{
		Enabled: false,
	}
}

// GetMetadataDiscrepancy returns the current metadata discrepancy state
func GetMetadataDiscrepancy() MetadataDiscrepancy {
	currentMetadataDiscrepancyLock.RLock()
	defer currentMetadataDiscrepancyLock.RUnlock()
	if currentMetadataDiscrepancy == nil {
		return MetadataDiscrepancy{Enabled: false}
	}
	return *currentMetadataDiscrepancy
}

// setMetadataDiscrepancy updates the current metadata discrepancy state
func setMetadataDiscrepancy(discrepancy *MetadataDiscrepancy) {
	currentMetadataDiscrepancyLock.Lock()
	defer currentMetadataDiscrepancyLock.Unlock()
	currentMetadataDiscrepancy = discrepancy
}

// fetchDiscoveryMetadata fetches the federation metadata from the discovery URL
func fetchDiscoveryMetadata(ctx context.Context, discoveryUrlStr string) (*pelican_url.FederationDiscovery, error) {
	discoveryUrl, err := url.Parse(discoveryUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse discovery URL")
	}

	// Clear path for discovery - DiscoverFederation will add the well-known path
	discoveryUrl.Path = ""

	httpClient := config.GetClient()

	ua := "pelican-director/" + config.GetVersion()
	metadata, err := pelican_url.DiscoverFederation(ctx, httpClient, ua, discoveryUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch federation metadata from discovery URL")
	}

	return &metadata, nil
}

// fetchJwks fetches and parses JWKS from the given URI
func fetchJwks(ctx context.Context, jwksUri string) (jwk.Set, error) {
	httpClient := config.GetClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksUri, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JWKS request")
	}
	req.Header.Set("User-Agent", "pelican-director/"+config.GetVersion())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch JWKS")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read JWKS response body")
	}

	keySet, err := jwk.Parse(body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse JWKS")
	}

	return keySet, nil
}

// compareJwksKeys checks if there is at least one overlapping key between two JWKS URIs
func compareJwksKeys(ctx context.Context, directorJwksUri, discoveryJwksUri string) (hasOverlap bool, err error) {
	// If URIs are the same, they trivially overlap
	if directorJwksUri == discoveryJwksUri {
		return true, nil
	}

	directorKeys, err := fetchJwks(ctx, directorJwksUri)
	if err != nil {
		return false, errors.Wrap(err, "failed to fetch Director JWKS")
	}

	discoveryKeys, err := fetchJwks(ctx, discoveryJwksUri)
	if err != nil {
		return false, errors.Wrap(err, "failed to fetch Discovery URL JWKS")
	}

	// Check for any overlapping keys using jwk.Equal
	for i := 0; i < directorKeys.Len(); i++ {
		key, ok := directorKeys.Key(i)
		if !ok {
			continue
		}
		_, found := discoveryKeys.LookupKeyID(key.KeyID())
		if found {
			return true, nil
		}
	}
	log.Debugf("No overlapping JWKS keys found between Director (%s) and Discovery URL (%s)", directorJwksUri, discoveryJwksUri)
	return false, nil
}

// normalizeUrl normalizes URLs for comparison by ensuring consistent formatting
func normalizeUrl(urlStr string) string {
	if urlStr == "" {
		return ""
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	// Remove trailing slash from path
	if len(parsed.Path) > 1 && parsed.Path[len(parsed.Path)-1] == '/' {
		parsed.Path = parsed.Path[:len(parsed.Path)-1]
	}
	return parsed.String()
}

// CompareMetadata compares the Director's local federation metadata with the Discovery URL's metadata
// and returns a MetadataDiscrepancy struct describing any differences found.
func CompareMetadata(ctx context.Context) (*MetadataDiscrepancy, error) {
	result := &MetadataDiscrepancy{
		LastChecked: time.Now(),
		Enabled:     true,
	}

	// Get federation info from configs
	localFedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get local federation info")
	}

	discoveryUrlStr := localFedInfo.DiscoveryEndpoint
	result.DiscoveryUrl = discoveryUrlStr

	// If the Director IS the discovery URL, skip comparison
	externalWebUrl := normalizeUrl(param.Server_ExternalWebUrl.GetString())
	normalizedDiscoveryUrl := normalizeUrl(discoveryUrlStr)

	if externalWebUrl == normalizedDiscoveryUrl || discoveryUrlStr == "" {
		result.Enabled = false
		result.HasDiscrepancy = false
		log.Debug("Director URL is the Discovery URL or no Discovery URL configured; skipping metadata comparison")
		return result, nil
	}

	// Fetch metadata from the discovery URL
	discoveryMetadata, err := fetchDiscoveryMetadata(ctx, discoveryUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch discovery metadata")
	}

	// Compare director_endpoint
	localDirector := normalizeUrl(localFedInfo.DirectorEndpoint)
	discoveryDirector := normalizeUrl(discoveryMetadata.DirectorEndpoint)
	if localDirector != discoveryDirector {
		result.DirectorUrlMismatch = &UrlMismatch{
			DirectorValue:  localDirector,
			DiscoveryValue: discoveryDirector,
		}
		result.HasDiscrepancy = true
		log.Errorf("Metadata discrepancy detected: Director endpoint mismatch. Director serves '%s', Discovery URL has '%s'",
			localDirector, discoveryDirector)
	}

	// Compare namespace_registration_endpoint (registry)
	localRegistry := normalizeUrl(localFedInfo.RegistryEndpoint)
	discoveryRegistry := normalizeUrl(discoveryMetadata.RegistryEndpoint)
	if localRegistry != discoveryRegistry {
		result.RegistryUrlMismatch = &UrlMismatch{
			DirectorValue:  localRegistry,
			DiscoveryValue: discoveryRegistry,
		}
		result.HasDiscrepancy = true
		log.Errorf("Metadata discrepancy detected: Registry endpoint mismatch. Director serves '%s', Discovery URL has '%s'",
			localRegistry, discoveryRegistry)
	}

	// Compare JWKS keys for intersection
	localJwksUri := localFedInfo.JwksUri
	discoveryJwksUri := discoveryMetadata.JwksUri
	log.Tracef("Comparing JWKS keys between Director (%s) and Discovery URL (%s)", localJwksUri, discoveryJwksUri)

	if localJwksUri != "" && discoveryJwksUri != "" {
		hasOverlap, jwksErr := compareJwksKeys(ctx, localJwksUri, discoveryJwksUri)
		result.JwksOverlapChecked = true
		result.JwksHasOverlap = hasOverlap
		result.JwksError = ""

		if jwksErr != nil {
			result.JwksError = jwksErr.Error()
			log.Errorf("Failed to compare JWKS keys: %v", jwksErr)
		} else if !hasOverlap {
			result.HasDiscrepancy = true
			log.Errorf("Metadata discrepancy detected: No overlapping JWKS keys between Director (%s) and Discovery URL (%s)",
				localJwksUri, discoveryJwksUri)
		}
	} else {
		result.JwksOverlapChecked = false
		if localJwksUri == "" {
			result.JwksError = "Director JWKS URI is not configured"
		} else if discoveryJwksUri == "" {
			result.JwksError = "Discovery URL did not provide a JWKS URI"
		}
	}

	if !result.HasDiscrepancy {
		log.Debug("Metadata comparison completed: no discrepancies found")
	}

	return result, nil
}

// compareAndStoreMetadataDiscrepancy runs the metadata comparison and stores the result.
// This function is safe to call from a goroutine and handles errors gracefully.
func compareAndStoreMetadataDiscrepancy(ctx context.Context) {
	result, err := CompareMetadata(ctx)
	if err != nil {
		log.Warnf("Failed to compare federation metadata: %v", err)
		errorResult := &MetadataDiscrepancy{
			LastChecked: time.Now(),
			Enabled:     true,
		}
		setMetadataDiscrepancy(errorResult)
		return
	}

	setMetadataDiscrepancy(result)
}

// ResetMetadataDiscrepancyForTest resets the metadata discrepancy state for testing
func ResetMetadataDiscrepancyForTest() {
	currentMetadataDiscrepancyLock.Lock()
	defer currentMetadataDiscrepancyLock.Unlock()
	currentMetadataDiscrepancy = &MetadataDiscrepancy{
		Enabled: false,
	}
}

// LaunchMetadataComparisonLoop starts a goroutine that periodically compares
// federation metadata between the Director and the Discovery URL.
// The comparison interval is configured via Director.MetadataComparisonInterval.
func LaunchMetadataComparisonLoop(ctx context.Context, egrp *errgroup.Group) {
	comparisonInterval := param.Director_MetadataComparisonInterval.GetDuration()

	if comparisonInterval <= 0 {
		log.Debug("Metadata comparison interval is 0 or negative, skipping periodic metadata comparison")
		return
	}

	ticker := time.NewTicker(comparisonInterval)

	// Initial metadata comparison
	compareAndStoreMetadataDiscrepancy(ctx)

	egrp.Go(func() error {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				compareAndStoreMetadataDiscrepancy(ctx)
			case <-ctx.Done():
				log.Debug("Metadata comparison loop terminated")
				return nil
			}
		}
	})
}
