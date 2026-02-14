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

package local_cache

import (
	"strconv"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/param"
)

// CacheDirectives holds parsed Cache-Control header values that are
// relevant to the persistent cache.
type CacheDirectives struct {
	NoStore       bool          // Response must not be stored in any cache
	NoCache       bool          // Response may be stored but must be revalidated before each use
	Private       bool          // Response is for a single user; must not be stored in a shared cache
	MustRevalidate bool         // Once stale, must revalidate before use (even if stale-while-revalidate allows it)
	MaxAge        time.Duration // Maximum time the response is considered fresh (0 means not set)
	MaxAgeSet     bool          // True if max-age was explicitly present (distinguishes 0 from absent)
	SMaxAge       time.Duration // Like MaxAge but for shared caches (0 means not set)
	SMaxAgeSet    bool          // True if s-maxage was explicitly present
}

// ShouldStore returns true if the response is allowed to be stored in the cache.
// A shared cache must not store no-store or private responses.
func (cd *CacheDirectives) ShouldStore() bool {
	return !cd.NoStore && !cd.Private
}

// Freshness returns the freshness lifetime for this response.
// For a shared cache, s-maxage takes priority over max-age.
// Returns 0 and false if no freshness information is available.
func (cd *CacheDirectives) Freshness() (time.Duration, bool) {
	if cd.SMaxAgeSet {
		return cd.SMaxAge, true
	}
	if cd.MaxAgeSet {
		return cd.MaxAge, true
	}
	return 0, false
}

// NoCacheGracePeriod is the minimum interval between revalidation attempts
// when the origin sends Cache-Control: no-cache.  Strictly speaking, no-cache
// means "must revalidate before each use," but revalidation in Pelican
// requires a full GET (no conditional-request support yet), which is
// expensive.  A short grace period prevents a thundering-herd of redundant
// downloads when many clients hit the same object concurrently.
const NoCacheGracePeriod = 5 * time.Second

// IsStale checks whether a cached response is stale given when it was last
// validated (or originally stored).
// If no freshness information is available (no max-age / s-maxage / no-cache),
// applies the default cache policy from params with jitter.
func (cd *CacheDirectives) IsStale(lastValidated time.Time) bool {
	if cd.NoCache {
		// no-cache requires revalidation, but we allow a short grace
		// period to avoid thundering-herd when many concurrent requests
		// arrive for the same object.
		return time.Since(lastValidated) > NoCacheGracePeriod
	}
	freshness, ok := cd.Freshness()
	if !ok {
		// No explicit freshness info — apply default policy from configuration.
		// This provides a sensible default for origins that don't set Cache-Control.
		return cd.IsStaleWithDefaults(lastValidated)
	}
	return time.Since(lastValidated) > freshness
}

// IsStaleWithDefaults checks staleness using configured default values and jitter.
// This is used when the origin doesn't provide explicit Cache-Control headers.
func (cd *CacheDirectives) IsStaleWithDefaults(lastValidated time.Time) bool {
	defaultMaxAge := param.LocalCache_DefaultMaxAge.GetDuration()
	if defaultMaxAge <= 0 {
		defaultMaxAge = 24 * time.Hour // Fallback default
	}

	jitterPercent := param.LocalCache_RevalidationJitter.GetInt()
	if jitterPercent < 0 {
		jitterPercent = 0
	} else if jitterPercent > 100 {
		jitterPercent = 100
	}

	// Apply jitter: reduce max age by up to jitterPercent (25% random component)
	// Example: 24h with 10% jitter => grace period varies by 2.4h (21.6h - 24h)
	// The random component is based on lastValidated to be deterministic per object
	jitterFactor := 1.0 - (float64(jitterPercent) / 100.0)
	minFreshness := time.Duration(float64(defaultMaxAge) * jitterFactor)
	
	// Add 25% random variation to the grace period to avoid synchronization
	
	// Use a simple hash of the validation time to get deterministic randomness
	// This ensures the same object gets the same jitter value across requests
	seed := uint64(lastValidated.Unix())
	seed = seed ^ (seed >> 33)
	seed *= 0xff51afd7ed558ccd
	seed = seed ^ (seed >> 33)
	jitterRand := float64(seed%10000) / 10000.0 // 0.0 to 1.0
	
	// Apply 25% random jitter to avoid unintended synchronization
	gracePeriod := defaultMaxAge - minFreshness
	jitterRange := time.Duration(float64(gracePeriod) * 0.25)
	actualFreshness := minFreshness + gracePeriod - jitterRange + time.Duration(float64(jitterRange*2)*jitterRand)
	return time.Since(lastValidated) > actualFreshness
}

// ParseCacheControl parses a Cache-Control header value into structured
// directives.
// The parsing is case-insensitive for directive names, as required by RFC 7234.
func ParseCacheControl(header string) CacheDirectives {
	var cd CacheDirectives
	if header == "" {
		return cd
	}

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split on '=' for directives with values
		directive := part
		value := ""
		if eqIdx := strings.IndexByte(part, '='); eqIdx >= 0 {
			directive = strings.TrimSpace(part[:eqIdx])
			value = strings.TrimSpace(part[eqIdx+1:])
			// Strip surrounding quotes from value
			value = strings.Trim(value, "\"")
		}

		switch strings.ToLower(directive) {
		case "no-store":
			cd.NoStore = true
		case "no-cache":
			cd.NoCache = true
		case "private":
			cd.Private = true
		case "must-revalidate":
			cd.MustRevalidate = true
		case "max-age":
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
				cd.MaxAge = time.Duration(seconds) * time.Second
				cd.MaxAgeSet = true
			}
		case "s-maxage":
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
				cd.SMaxAge = time.Duration(seconds) * time.Second
				cd.SMaxAgeSet = true
			}
		}
	}

	return cd
}
