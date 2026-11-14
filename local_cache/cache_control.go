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
	"time"

	"github.com/pelicanplatform/pelican/cache_control"
	"github.com/pelicanplatform/pelican/param"
)

// Bit flags for the parsed directives.  These are the same values used in
// CacheMetadata.CCFlags so that round-tripping through storage is a direct
// copy; they live in the cache_control package, which owns the bit layout.
const (
	ccNoStore        = cache_control.FlagNoStore
	ccNoCache        = cache_control.FlagNoCache
	ccPrivate        = cache_control.FlagPrivate
	ccMustRevalidate = cache_control.FlagMustRevalidate
	ccMaxAgeSet      = cache_control.FlagMaxAgeSet
)

// NoCacheGracePeriod is the minimum interval between revalidation attempts
// for an object whose origin sent Cache-Control: no-cache.
const NoCacheGracePeriod = cache_control.NoCacheGracePeriod

// CacheDirectives holds parsed Cache-Control header values that are relevant
// to the persistent cache.  The parsing and the freshness rules live in the
// cache_control package; this type adds the local cache's own configuration
// (LocalCache.DefaultMaxAge and LocalCache.RevalidationJitter) on top.
type CacheDirectives struct {
	cache_control.Directives
}

// ParseCacheControl parses a Cache-Control header value into structured
// directives.  Directive names are matched case-insensitively; when both
// max-age and s-maxage are present the larger is kept.
func ParseCacheControl(header string) CacheDirectives {
	return CacheDirectives{cache_control.Parse(header)}
}

// localCachePolicy returns the freshness policy from the LocalCache
// configuration.  The local cache trusts its origins' Cache-Control values, so
// no MaxFreshness cap is applied.
func localCachePolicy() cache_control.Policy {
	defaultMaxAge := param.LocalCache_DefaultMaxAge.GetDuration()
	if defaultMaxAge <= 0 {
		defaultMaxAge = 24 * time.Hour // Fallback default
	}
	return cache_control.Policy{
		DefaultMaxAge: defaultMaxAge,
		JitterPercent: param.LocalCache_RevalidationJitter.GetInt(),
	}
}

// IsStale checks whether a cached response is stale given when it was last
// validated (or originally stored).  If the origin supplied no freshness
// information, the configured LocalCache default policy applies, with jitter.
func (cd *CacheDirectives) IsStale(lastValidated time.Time) bool {
	return cd.IsStaleFor(lastValidated, localCachePolicy(), "")
}

// IsStaleWithDefaults checks staleness using the configured default values and
// jitter, ignoring any freshness directive the origin supplied.
func (cd *CacheDirectives) IsStaleWithDefaults(lastValidated time.Time) bool {
	return time.Since(lastValidated) > DefaultFreshness(lastValidated)
}

// DefaultFreshness returns the jittered freshness lifetime used when the origin
// doesn't provide explicit Cache-Control headers.
//
// The jitter is deterministic in lastValidated, so repeated calls for the same
// object return the same duration.  Note that the local cache does not key the
// jitter by object: objects validated within the same second share a jitter
// value.  (Callers that need per-object spreading, such as the origin's
// storage cache, call cache_control.FreshnessFor with an object key.)
func DefaultFreshness(lastValidated time.Time) time.Duration {
	p := localCachePolicy()
	return cache_control.FreshnessFor(lastValidated, p.DefaultMaxAge, p.JitterPercent, "")
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
