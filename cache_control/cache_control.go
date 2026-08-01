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

// Package cache_control parses HTTP Cache-Control directives and applies
// freshness policy to them.
//
// It is deliberately a leaf package: it depends only on the standard library,
// with no reference to Pelican's configuration.  Callers supply their own
// policy through Policy, so components with unrelated configuration knobs (the
// local cache's LocalCache.* settings, the origin's Origin.StorageCache*
// settings) can share one implementation of the caching rules without sharing
// a dependency graph.
package cache_control

import (
	"hash/fnv"
	"strconv"
	"strings"
	"time"
)

// Bit flags for Directives.flags.  These values are persisted directly in the
// local cache's on-disk metadata (CacheMetadata.CCFlags), so they must not be
// renumbered.
const (
	FlagNoStore        uint8 = 0x01 // no-store
	FlagNoCache        uint8 = 0x02 // no-cache
	FlagPrivate        uint8 = 0x04 // private
	FlagMustRevalidate uint8 = 0x08 // must-revalidate
	FlagMaxAgeSet      uint8 = 0x10 // max-age or s-maxage was present
)

// NoCacheGracePeriod is the minimum interval between revalidation attempts
// when the response carries Cache-Control: no-cache.  Strictly speaking,
// no-cache means "revalidate before each use", but revalidation costs a
// round trip; a short grace period collapses a burst of concurrent requests
// for the same object into a single revalidation.
const NoCacheGracePeriod = 5 * time.Second

// Directives holds the parsed Cache-Control values relevant to caching.
//
// Boolean directives are packed into a bitfield; use the accessors rather
// than reading the field directly.
//
// max-age and s-maxage are merged into a single freshness lifetime: when both
// are present the larger is kept, because neither Pelican cache distinguishes
// shared from private storage.
type Directives struct {
	flags  uint8
	maxAge time.Duration // valid only when FlagMaxAgeSet is set
}

// Policy is the caller's freshness configuration, applied when the response's
// own directives do not fully determine staleness.
type Policy struct {
	// DefaultMaxAge is the freshness lifetime for responses that carry no
	// freshness directive.  A value <= 0 means "no default freshness": such
	// responses are always stale and must be revalidated on every use.
	DefaultMaxAge time.Duration

	// JitterPercent (clamped to 0-100) is the deterministic per-object jitter
	// applied to DefaultMaxAge, so that objects cached together do not all
	// expire at the same instant.
	JitterPercent int

	// MaxFreshness caps the freshness a response may claim for itself via
	// max-age / s-maxage.  Zero means no cap.  Capping matters when the
	// backend's metadata is not fully trusted: without it, whoever can set an
	// object's Cache-Control can pin content in the cache indefinitely.
	MaxFreshness time.Duration
}

// --- flag accessors --------------------------------------------------------

func (d Directives) NoStore() bool         { return d.flags&FlagNoStore != 0 }
func (d Directives) NoCache() bool         { return d.flags&FlagNoCache != 0 }
func (d Directives) Private() bool         { return d.flags&FlagPrivate != 0 }
func (d Directives) MustRevalidate() bool  { return d.flags&FlagMustRevalidate != 0 }
func (d Directives) MaxAgeSet() bool       { return d.flags&FlagMaxAgeSet != 0 }
func (d Directives) MaxAge() time.Duration { return d.maxAge }

// Flags returns the raw packed bitfield, for efficient serialization.
// Prefer the named accessors when reading individual directives.
func (d Directives) Flags() uint8 { return d.flags }

// --- derived helpers -------------------------------------------------------

// ShouldStore reports whether the response may be written to a shared cache.
func (d Directives) ShouldStore() bool {
	return d.flags&(FlagNoStore|FlagPrivate) == 0
}

// HasFreshness reports whether the response supplied explicit freshness
// information (max-age or s-maxage).
func (d Directives) HasFreshness() bool { return d.flags&FlagMaxAgeSet != 0 }

// Freshness returns the merged freshness lifetime and whether it was set.
func (d Directives) Freshness() (time.Duration, bool) {
	if d.flags&FlagMaxAgeSet != 0 {
		return d.maxAge, true
	}
	return 0, false
}

// HasDirectives reports whether any directive was parsed.
func (d Directives) HasDirectives() bool { return d.flags != 0 || d.maxAge != 0 }

// FromFlags rebuilds Directives from a persisted bitfield and max-age.  A
// positive maxAge implies FlagMaxAgeSet regardless of whether the caller
// included it in flags, since the two are stored separately on disk.
func FromFlags(flags uint8, maxAge time.Duration) Directives {
	d := Directives{flags: flags}
	if maxAge > 0 {
		d.maxAge = maxAge
		d.flags |= FlagMaxAgeSet
	}
	return d
}

// IsStaleFor reports whether a response last validated at lastValidated must
// be revalidated before it may be served again.
//
// key identifies the object, and seeds the jitter applied to
// policy.DefaultMaxAge so that each object gets its own expiry instant; pass
// the object's path (or any stable per-object string).  An empty key seeds the
// jitter from lastValidated alone, which spreads objects validated at
// different times but not objects validated together.
func (d Directives) IsStaleFor(lastValidated time.Time, policy Policy, key string) bool {
	age := time.Since(lastValidated)
	if d.NoCache() {
		return age > NoCacheGracePeriod
	}
	if freshness, ok := d.Freshness(); ok {
		if policy.MaxFreshness > 0 && freshness > policy.MaxFreshness {
			freshness = policy.MaxFreshness
		}
		return age > freshness
	}
	if policy.DefaultMaxAge <= 0 {
		return true
	}
	return age > FreshnessFor(lastValidated, policy.DefaultMaxAge, policy.JitterPercent, key)
}

// FreshnessFor computes the jittered freshness lifetime for a response with no
// freshness directive of its own.
//
// The result is deterministic in (lastValidated, key), so repeated calls for
// the same object agree, and lies in [defaultMaxAge*(1-jitter), defaultMaxAge]
// — jitter only ever shortens the window.
func FreshnessFor(lastValidated time.Time, defaultMaxAge time.Duration, jitterPercent int, key string) time.Duration {
	if jitterPercent < 0 {
		jitterPercent = 0
	} else if jitterPercent > 100 {
		jitterPercent = 100
	}

	jitterFactor := 1.0 - (float64(jitterPercent) / 100.0)
	minFreshness := time.Duration(float64(defaultMaxAge) * jitterFactor)

	// Mix the object key into the seed.  Seeding from lastValidated alone
	// would give every object validated in the same second an identical
	// jitter, which defeats the purpose: a burst of objects fetched together
	// would still expire together.
	seed := uint64(lastValidated.Unix())
	if key != "" {
		h := fnv.New64a()
		_, _ = h.Write([]byte(key))
		seed ^= h.Sum64()
	}
	seed ^= seed >> 33
	seed *= 0xff51afd7ed558ccd
	seed ^= seed >> 33
	jitterRand := float64(seed%10000) / 10000.0 // 0.0 to 1.0

	return minFreshness + time.Duration(float64(defaultMaxAge-minFreshness)*jitterRand)
}

// Parse converts a Cache-Control header value into structured directives.
// Directive names are matched case-insensitively, as RFC 7234 requires.
func Parse(header string) Directives {
	var d Directives
	if header == "" {
		return d
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

		directive := part
		value := ""
		if eqIdx := strings.IndexByte(part, '='); eqIdx >= 0 {
			directive = strings.TrimSpace(part[:eqIdx])
			value = strings.TrimSpace(part[eqIdx+1:])
			value = strings.Trim(value, "\"")
		}

		switch strings.ToLower(directive) {
		case "no-store":
			d.flags |= FlagNoStore
		case "no-cache":
			d.flags |= FlagNoCache
		case "private":
			d.flags |= FlagPrivate
		case "must-revalidate":
			d.flags |= FlagMustRevalidate
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

	// Merge max-age and s-maxage: keep the larger of the two.
	switch {
	case maxAgeOk && sMaxAgeOk:
		d.maxAge = maxAge
		if sMaxAge > maxAge {
			d.maxAge = sMaxAge
		}
		d.flags |= FlagMaxAgeSet
	case sMaxAgeOk:
		d.maxAge = sMaxAge
		d.flags |= FlagMaxAgeSet
	case maxAgeOk:
		d.maxAge = maxAge
		d.flags |= FlagMaxAgeSet
	}

	return d
}
