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

package cache_control

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Parse must recognize every directive the caches act on, in the forms real
// servers emit them: any case, arbitrary surrounding whitespace, optionally
// quoted values.  Values it cannot make sense of are ignored rather than
// guessed at, because a misparsed max-age silently changes how long content is
// served without checking the origin.
func TestParseDirectives(t *testing.T) {
	for _, tc := range []struct {
		name           string
		header         string
		wantNoStore    bool
		wantNoCache    bool
		wantPrivate    bool
		wantMustReval  bool
		wantMaxAgeSet  bool
		wantMaxAge     time.Duration
		wantDirectives bool
	}{
		{name: "empty header"},
		{name: "no-store", header: "no-store", wantNoStore: true, wantDirectives: true},
		{name: "no-cache", header: "no-cache", wantNoCache: true, wantDirectives: true},
		{name: "private", header: "private", wantPrivate: true, wantDirectives: true},
		{name: "must-revalidate", header: "must-revalidate", wantMustReval: true, wantDirectives: true},
		{
			name: "max-age", header: "max-age=60",
			wantMaxAgeSet: true, wantMaxAge: time.Minute, wantDirectives: true,
		},
		{
			name: "zero max-age is still explicit", header: "max-age=0",
			wantMaxAgeSet: true, wantMaxAge: 0, wantDirectives: true,
		},
		{
			// Neither cache distinguishes shared from private storage, so the
			// two lifetimes merge to the larger.
			name: "s-maxage larger than max-age wins", header: "max-age=60, s-maxage=120",
			wantMaxAgeSet: true, wantMaxAge: 2 * time.Minute, wantDirectives: true,
		},
		{
			name: "max-age larger than s-maxage wins", header: "s-maxage=60, max-age=600",
			wantMaxAgeSet: true, wantMaxAge: 10 * time.Minute, wantDirectives: true,
		},
		{
			name: "s-maxage alone", header: "s-maxage=90",
			wantMaxAgeSet: true, wantMaxAge: 90 * time.Second, wantDirectives: true,
		},
		{
			name: "quoted value", header: `max-age="60"`,
			wantMaxAgeSet: true, wantMaxAge: time.Minute, wantDirectives: true,
		},
		{
			name: "case insensitive", header: "MAX-AGE=60, No-Store, NO-CACHE, Private, Must-Revalidate",
			wantNoStore: true, wantNoCache: true, wantPrivate: true, wantMustReval: true,
			wantMaxAgeSet: true, wantMaxAge: time.Minute, wantDirectives: true,
		},
		{
			name: "surrounding whitespace and empty elements", header: "  ,  max-age = 60 ,, no-store  ,",
			wantNoStore: true, wantMaxAgeSet: true, wantMaxAge: time.Minute, wantDirectives: true,
		},
		{name: "non-numeric max-age is ignored", header: "max-age=abc"},
		{name: "negative max-age is ignored", header: "max-age=-5"},
		{name: "empty max-age is ignored", header: "max-age="},
		{name: "overflowing max-age is ignored", header: "max-age=99999999999999999999"},
		{name: "unknown directives are ignored", header: "immutable, stale-while-revalidate=30, foo=bar"},
		{
			name: "junk alongside a good directive", header: "max-age=nope, no-store",
			wantNoStore: true, wantDirectives: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Parse(tc.header)
			assert.Equal(t, tc.wantNoStore, d.NoStore(), "no-store")
			assert.Equal(t, tc.wantNoCache, d.NoCache(), "no-cache")
			assert.Equal(t, tc.wantPrivate, d.Private(), "private")
			assert.Equal(t, tc.wantMustReval, d.MustRevalidate(), "must-revalidate")
			assert.Equal(t, tc.wantMaxAgeSet, d.MaxAgeSet(), "max-age set")
			assert.Equal(t, tc.wantMaxAgeSet, d.HasFreshness(), "HasFreshness must track MaxAgeSet")
			assert.Equal(t, tc.wantMaxAge, d.MaxAge(), "max-age value")
			freshness, ok := d.Freshness()
			assert.Equal(t, tc.wantMaxAgeSet, ok, "Freshness ok")
			if ok {
				assert.Equal(t, tc.wantMaxAge, freshness, "Freshness value")
			}
			assert.Equal(t, tc.wantDirectives, d.HasDirectives(), "HasDirectives")
		})
	}
}

// The flag values are persisted in the local cache's on-disk metadata, so a
// round trip through the serialized form must reproduce the parsed directives
// exactly — including "max-age=0", whose max-age is indistinguishable from
// "unset" unless the flag is carried across.
func TestFromFlagsRoundTrip(t *testing.T) {
	for _, header := range []string{
		"",
		"no-store",
		"no-cache",
		"private, must-revalidate",
		"max-age=60",
		"max-age=0",
		"no-cache, max-age=300",
		"no-store, no-cache, private, must-revalidate, max-age=1, s-maxage=2",
	} {
		t.Run(fmt.Sprintf("header %q", header), func(t *testing.T) {
			original := Parse(header)
			restored := FromFlags(original.Flags(), original.MaxAge())
			assert.Equal(t, original, restored)
		})
	}

	// A positive max-age implies the flag even when the caller omits it: the
	// two halves are stored in separate on-disk fields.
	d := FromFlags(0, 30*time.Second)
	assert.True(t, d.MaxAgeSet())
	assert.Equal(t, 30*time.Second, d.MaxAge())

	// A non-positive max-age never sets the flag on its own.
	d = FromFlags(FlagNoStore, 0)
	assert.False(t, d.MaxAgeSet())
	assert.True(t, d.NoStore())
}

// ShouldStore gates whether a response may be written to a shared cache at
// all: no-store and private must never reach disk, while no-cache responses
// are stored (they are merely revalidated before nearly every use).
func TestShouldStore(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{"", true},
		{"max-age=600", true},
		{"no-cache", true},
		{"must-revalidate", true},
		{"no-store", false},
		{"private", false},
		{"private, max-age=600", false},
		{"no-store, max-age=600", false},
		{"public, no-store", false},
	} {
		t.Run(fmt.Sprintf("header %q", tc.header), func(t *testing.T) {
			assert.Equal(t, tc.want, Parse(tc.header).ShouldStore())
		})
	}
}

// IsStaleFor decides whether a copy may be served without contacting the
// origin.  The rules it must hold to: no-cache revalidates outside a short
// coalescing grace period; an explicit max-age wins over the caller's default
// but is capped by MaxFreshness, so a backend cannot pin content in the cache;
// and a non-positive DefaultMaxAge means "revalidate every time".
func TestIsStaleFor(t *testing.T) {
	now := time.Now()

	t.Run("no-cache revalidates outside the grace period", func(t *testing.T) {
		d := Parse("no-cache")
		policy := Policy{DefaultMaxAge: 24 * time.Hour}
		assert.False(t, d.IsStaleFor(now, policy, "/obj"), "within grace")
		assert.True(t, d.IsStaleFor(now.Add(-2*NoCacheGracePeriod), policy, "/obj"), "past grace")
	})

	t.Run("no-cache ignores a long max-age", func(t *testing.T) {
		d := Parse("no-cache, max-age=86400")
		policy := Policy{DefaultMaxAge: 24 * time.Hour}
		assert.True(t, d.IsStaleFor(now.Add(-2*NoCacheGracePeriod), policy, "/obj"))
	})

	t.Run("explicit freshness overrides the default", func(t *testing.T) {
		d := Parse("max-age=60")
		// DefaultMaxAge of zero would make a directive-free response always
		// stale; an explicit max-age still governs.
		policy := Policy{DefaultMaxAge: 0}
		assert.False(t, d.IsStaleFor(now.Add(-30*time.Second), policy, "/obj"))
		assert.True(t, d.IsStaleFor(now.Add(-90*time.Second), policy, "/obj"))
	})

	t.Run("MaxFreshness caps a backend's claim", func(t *testing.T) {
		d := Parse("max-age=3600")
		uncapped := Policy{DefaultMaxAge: time.Hour}
		capped := Policy{DefaultMaxAge: time.Hour, MaxFreshness: time.Minute}
		assert.False(t, d.IsStaleFor(now.Add(-2*time.Minute), uncapped, "/obj"), "uncapped policy honours the backend")
		assert.True(t, d.IsStaleFor(now.Add(-2*time.Minute), capped, "/obj"), "cap must bound the backend's max-age")
		assert.False(t, d.IsStaleFor(now.Add(-30*time.Second), capped, "/obj"), "within the cap it is still fresh")
	})

	t.Run("MaxFreshness does not extend a short max-age", func(t *testing.T) {
		d := Parse("max-age=10")
		policy := Policy{DefaultMaxAge: time.Hour, MaxFreshness: time.Hour}
		assert.True(t, d.IsStaleFor(now.Add(-time.Minute), policy, "/obj"))
	})

	t.Run("no default freshness means always stale", func(t *testing.T) {
		d := Parse("")
		assert.True(t, d.IsStaleFor(now, Policy{DefaultMaxAge: 0}, "/obj"))
		assert.True(t, d.IsStaleFor(now, Policy{DefaultMaxAge: -time.Hour}, "/obj"))
		assert.True(t, Parse("must-revalidate").IsStaleFor(now, Policy{}, "/obj"))
	})

	t.Run("default freshness applies when the response says nothing", func(t *testing.T) {
		d := Parse("")
		policy := Policy{DefaultMaxAge: time.Hour}
		assert.False(t, d.IsStaleFor(now, policy, "/obj"))
		assert.True(t, d.IsStaleFor(now.Add(-2*time.Hour), policy, "/obj"))
	})

	t.Run("jitter only shortens the default window", func(t *testing.T) {
		d := Parse("")
		policy := Policy{DefaultMaxAge: time.Hour, JitterPercent: 50}
		// Half the window is inside the jitter floor for every key.
		assert.False(t, d.IsStaleFor(now.Add(-29*time.Minute), policy, "/obj"))
		assert.True(t, d.IsStaleFor(now.Add(-61*time.Minute), policy, "/obj"))
	})
}

// FreshnessFor spreads expiry across objects without ever extending the
// operator's window: it is deterministic per (time, key), never exceeds
// defaultMaxAge, never drops below the jitter floor, differs between objects
// validated at the same instant, and clamps nonsensical jitter percentages
// instead of producing negative or over-long lifetimes.
func TestFreshnessFor(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	const maxAge = time.Hour

	t.Run("deterministic", func(t *testing.T) {
		first := FreshnessFor(base, maxAge, 50, "/some/object")
		for i := 0; i < 5; i++ {
			assert.Equal(t, first, FreshnessFor(base, maxAge, 50, "/some/object"))
		}
	})

	t.Run("no jitter yields the full window", func(t *testing.T) {
		assert.Equal(t, maxAge, FreshnessFor(base, maxAge, 0, "/some/object"))
		assert.Equal(t, maxAge, FreshnessFor(base, maxAge, 0, ""))
	})

	t.Run("bounded by the jitter floor and the full window", func(t *testing.T) {
		const jitter = 50
		floor := maxAge / 2
		for i := 0; i < 200; i++ {
			key := fmt.Sprintf("/obj-%d", i)
			got := FreshnessFor(base, maxAge, jitter, key)
			assert.GreaterOrEqual(t, got, floor, "key %s below the jitter floor", key)
			assert.LessOrEqual(t, got, maxAge, "key %s exceeds the configured window", key)
		}
	})

	t.Run("varies per object", func(t *testing.T) {
		// Objects fetched together must not all expire together, so the same
		// instant with different keys must not collapse to one lifetime.
		assert.NotEqual(t, FreshnessFor(base, maxAge, 50, "/obj-a"), FreshnessFor(base, maxAge, 50, "/obj-b"))

		distinct := make(map[time.Duration]bool)
		for i := 0; i < 50; i++ {
			distinct[FreshnessFor(base, maxAge, 50, fmt.Sprintf("/obj-%d", i))] = true
		}
		assert.Greater(t, len(distinct), 25, "jitter should spread objects across the window")
	})

	t.Run("empty key still varies with the validation time", func(t *testing.T) {
		a := FreshnessFor(base, maxAge, 50, "")
		b := FreshnessFor(base.Add(time.Second), maxAge, 50, "")
		assert.Equal(t, a, FreshnessFor(base, maxAge, 50, ""), "must stay deterministic")
		assert.NotEqual(t, a, b, "different validation instants should not share a lifetime")
	})

	t.Run("jitter percent is clamped", func(t *testing.T) {
		key := "/clamped"
		assert.Equal(t, FreshnessFor(base, maxAge, 0, key), FreshnessFor(base, maxAge, -25, key),
			"negative jitter must behave like none")
		assert.Equal(t, FreshnessFor(base, maxAge, 100, key), FreshnessFor(base, maxAge, 250, key),
			"jitter above 100 must behave like 100")
		full := FreshnessFor(base, maxAge, 250, key)
		assert.GreaterOrEqual(t, full, time.Duration(0))
		assert.LessOrEqual(t, full, maxAge)
	})

	t.Run("zero window stays zero", func(t *testing.T) {
		assert.Equal(t, time.Duration(0), FreshnessFor(base, 0, 50, "/obj"))
	})
}

// The persisted flag values are part of the local cache's on-disk format;
// renumbering them would silently reinterpret every stored entry.
func TestFlagValuesAreStable(t *testing.T) {
	require.Equal(t, uint8(0x01), FlagNoStore)
	require.Equal(t, uint8(0x02), FlagNoCache)
	require.Equal(t, uint8(0x04), FlagPrivate)
	require.Equal(t, uint8(0x08), FlagMustRevalidate)
	require.Equal(t, uint8(0x10), FlagMaxAgeSet)

	d := Parse("no-store, no-cache, private, must-revalidate, max-age=1")
	assert.Equal(t, FlagNoStore|FlagNoCache|FlagPrivate|FlagMustRevalidate|FlagMaxAgeSet, d.Flags())
}
