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

// Bit flags for CacheDirectives.flags.
// These are the same values used in CacheMetadata.CCFlags so that
// round-tripping through storage is a direct copy.
const (
	ccNoStore        uint8 = 0x01 // no-store
	ccNoCache        uint8 = 0x02 // no-cache
	ccPrivate        uint8 = 0x04 // private
	ccMustRevalidate uint8 = 0x08 // must-revalidate
	ccMaxAgeSet      uint8 = 0x10 // max-age or s-maxage was present
)

// CacheDirectives holds parsed Cache-Control header values that are
// relevant to the persistent cache.
//
// Boolean directives are packed into a bitfield; use the accessor methods
// (NoStore, NoCache, etc.) instead of reading fields directly.
//
// max-age and s-maxage are merged into a single freshness lifetime:
// when both are present the maximum of the two is kept, because the
// Pelican local cache does not distinguish shared from private.
type CacheDirectives struct {
	flags  uint8
	maxAge time.Duration // merged freshness lifetime (valid only when ccMaxAgeSet is set)
}

// --- flag accessors --------------------------------------------------------

func (cd *CacheDirectives) NoStore() bool         { return cd.flags&ccNoStore != 0 }
func (cd *CacheDirectives) NoCache() bool         { return cd.flags&ccNoCache != 0 }
func (cd *CacheDirectives) Private() bool         { return cd.flags&ccPrivate != 0 }
func (cd *CacheDirectives) MustRevalidate() bool  { return cd.flags&ccMustRevalidate != 0 }
func (cd *CacheDirectives) MaxAgeSet() bool       { return cd.flags&ccMaxAgeSet != 0 }
func (cd *CacheDirectives) MaxAge() time.Duration { return cd.maxAge }

// Flags returns the raw packed bitfield.
// Callers should prefer the named accessors; this is provided for
// efficient serialization into CacheMetadata.CCFlags.
func (cd *CacheDirectives) Flags() uint8 { return cd.flags }

// --- derived helpers -------------------------------------------------------

// ShouldStore returns true if the response is allowed to be stored in the cache.
func (cd *CacheDirectives) ShouldStore() bool {
	return cd.flags&(ccNoStore|ccPrivate) == 0
}

// HasFreshness returns true if the origin provided explicit freshness
// information (max-age or s-maxage).
func (cd *CacheDirectives) HasFreshness() bool {
	return cd.flags&ccMaxAgeSet != 0
}

// Freshness returns the merged freshness lifetime and whether it was set.
func (cd *CacheDirectives) Freshness() (time.Duration, bool) {
	if cd.flags&ccMaxAgeSet != 0 {
		return cd.maxAge, true
	}
	return 0, false
}

// HasDirectives returns true if any Cache-Control directive was parsed.
func (cd *CacheDirectives) HasDirectives() bool {
	return cd.flags != 0 || cd.maxAge != 0
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
	if cd.NoCache() {
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
	return time.Since(lastValidated) > DefaultFreshness(lastValidated)
}

// DefaultFreshness returns the jittered freshness lifetime used when the origin
// doesn't provide explicit Cache-Control headers.  The jitter is deterministic
// per object (seeded from lastValidated) so that repeated calls for the same
// object return the same duration.
func DefaultFreshness(lastValidated time.Time) time.Duration {
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
	return minFreshness + gracePeriod - jitterRange + time.Duration(float64(jitterRange*2)*jitterRand)
}

// RemainingFreshness returns how much freshness lifetime is left for an object
// whose origin did not specify Cache-Control, clamped to zero.
func RemainingFreshness(lastValidated time.Time) time.Duration {
	remaining := DefaultFreshness(lastValidated) - time.Since(lastValidated)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ParseCacheControl parses a Cache-Control header value into structured
// directives.
// The parsing is case-insensitive for directive names, as required by RFC 7234.
// When both max-age and s-maxage are present, the maximum of the two durations
// is kept (the Pelican local cache does not distinguish shared from private).
func ParseCacheControl(header string) CacheDirectives {
	var cd CacheDirectives
	if header == "" {
		return cd
	}

	var (
		maxAge    time.Duration
		maxAgeOk  bool
		sMaxAge   time.Duration
		sMaxAgeOk bool
	)

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
			cd.flags |= ccNoStore
		case "no-cache":
			cd.flags |= ccNoCache
		case "private":
			cd.flags |= ccPrivate
		case "must-revalidate":
			cd.flags |= ccMustRevalidate
		case "max-age":
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
				maxAge = time.Duration(seconds) * time.Second
				maxAgeOk = true
			}
		case "s-maxage":
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
				sMaxAge = time.Duration(seconds) * time.Second
				sMaxAgeOk = true
			}
		}
	}

	// Merge max-age and s-maxage: take the maximum of the two.
	switch {
	case maxAgeOk && sMaxAgeOk:
		cd.maxAge = maxAge
		if sMaxAge > maxAge {
			cd.maxAge = sMaxAge
		}
		cd.flags |= ccMaxAgeSet
	case sMaxAgeOk:
		cd.maxAge = sMaxAge
		cd.flags |= ccMaxAgeSet
	case maxAgeOk:
		cd.maxAge = maxAge
		cd.flags |= ccMaxAgeSet
	}

	return cd
}
