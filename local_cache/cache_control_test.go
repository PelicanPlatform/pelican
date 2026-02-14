/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseCacheControl_Empty(t *testing.T) {
	cd := ParseCacheControl("")
	assert.False(t, cd.NoStore())
	assert.False(t, cd.NoCache())
	assert.False(t, cd.Private())
	assert.False(t, cd.MustRevalidate())
	assert.False(t, cd.MaxAgeSet())
}

func TestParseCacheControl_NoStore(t *testing.T) {
	cd := ParseCacheControl("no-store")
	assert.True(t, cd.NoStore())
	assert.False(t, cd.ShouldStore())
}

func TestParseCacheControl_Private(t *testing.T) {
	cd := ParseCacheControl("private")
	assert.True(t, cd.Private())
	assert.False(t, cd.ShouldStore())
}

func TestParseCacheControl_MaxAge(t *testing.T) {
	cd := ParseCacheControl("max-age=3600")
	assert.True(t, cd.MaxAgeSet())
	assert.Equal(t, 3600*time.Second, cd.MaxAge())

	freshness, ok := cd.Freshness()
	assert.True(t, ok)
	assert.Equal(t, 3600*time.Second, freshness)
}

func TestParseCacheControl_SMaxAge(t *testing.T) {
	cd := ParseCacheControl("s-maxage=300, max-age=3600")
	assert.True(t, cd.MaxAgeSet())

	// max-age and s-maxage are merged; the maximum of the two is kept
	freshness, ok := cd.Freshness()
	assert.True(t, ok)
	assert.Equal(t, 3600*time.Second, freshness)
}

func TestParseCacheControl_CaseInsensitive(t *testing.T) {
	cd := ParseCacheControl("No-Store, MAX-AGE=60")
	assert.True(t, cd.NoStore())
	assert.True(t, cd.MaxAgeSet())
	assert.Equal(t, 60*time.Second, cd.MaxAge())
}

func TestParseCacheControl_MustRevalidate(t *testing.T) {
	cd := ParseCacheControl("must-revalidate, max-age=0")
	assert.True(t, cd.MustRevalidate())
	assert.True(t, cd.MaxAgeSet())
	assert.Equal(t, time.Duration(0), cd.MaxAge())
}

func TestParseCacheControl_NoCache(t *testing.T) {
	cd := ParseCacheControl("no-cache")
	assert.True(t, cd.NoCache())
	assert.True(t, cd.ShouldStore(), "no-cache is allowed to be stored, just must revalidate")
}

func TestParseCacheControl_Complex(t *testing.T) {
	cd := ParseCacheControl("public, max-age=86400, s-maxage=600, must-revalidate")
	assert.False(t, cd.NoStore())
	assert.False(t, cd.Private())
	assert.True(t, cd.MustRevalidate())
	assert.Equal(t, 86400*time.Second, cd.MaxAge()) // max of 86400 and 600
	assert.True(t, cd.ShouldStore())
}

func TestParseCacheControl_InvalidMaxAge(t *testing.T) {
	cd := ParseCacheControl("max-age=abc")
	assert.False(t, cd.MaxAgeSet())
	assert.Equal(t, time.Duration(0), cd.MaxAge())
}

func TestParseCacheControl_NegativeMaxAge(t *testing.T) {
	cd := ParseCacheControl("max-age=-10")
	assert.False(t, cd.MaxAgeSet())
}

func TestParseCacheControl_QuotedValue(t *testing.T) {
	cd := ParseCacheControl(`max-age="3600"`)
	assert.True(t, cd.MaxAgeSet())
	assert.Equal(t, 3600*time.Second, cd.MaxAge())
}

func TestParseCacheControl_ExtraWhitespace(t *testing.T) {
	cd := ParseCacheControl("  no-store ,  max-age = 60  , private  ")
	assert.True(t, cd.NoStore())
	assert.True(t, cd.Private())
	assert.True(t, cd.MaxAgeSet())
	assert.Equal(t, 60*time.Second, cd.MaxAge())
}

func TestShouldStore(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty", "", true},
		{"public", "public, max-age=3600", true},
		{"no-cache", "no-cache", true},
		{"no-store", "no-store", false},
		{"private", "private", false},
		{"no-store+private", "no-store, private", false},
		{"must-revalidate", "must-revalidate", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cd := ParseCacheControl(tt.header)
			assert.Equal(t, tt.want, cd.ShouldStore())
		})
	}
}

func TestIsStale(t *testing.T) {
	t.Run("no-cache within grace period is fresh", func(t *testing.T) {
		cd := ParseCacheControl("no-cache, max-age=999999")
		// Just validated — within grace period, treat as fresh
		assert.False(t, cd.IsStale(time.Now()))
	})

	t.Run("no-cache past grace period is stale", func(t *testing.T) {
		cd := ParseCacheControl("no-cache")
		// Validated well beyond the grace period — should be stale
		assert.True(t, cd.IsStale(time.Now().Add(-2*NoCacheGracePeriod)))
	})

	t.Run("within max-age is fresh", func(t *testing.T) {
		cd := ParseCacheControl("max-age=3600")
		assert.False(t, cd.IsStale(time.Now().Add(-30*time.Minute)))
	})

	t.Run("past max-age is stale", func(t *testing.T) {
		cd := ParseCacheControl("max-age=3600")
		assert.True(t, cd.IsStale(time.Now().Add(-2*time.Hour)))
	})

	t.Run("merged freshness uses maximum of max-age and s-maxage", func(t *testing.T) {
		cd := ParseCacheControl("max-age=60, s-maxage=120")
		// Merged freshness is max(60, 120) = 120s
		// 90 seconds ago is within 120s => still fresh
		assert.False(t, cd.IsStale(time.Now().Add(-90*time.Second)))
		// 3 minutes ago exceeds 120s => stale
		assert.True(t, cd.IsStale(time.Now().Add(-3*time.Minute)))
	})

	t.Run("no freshness info means fresh (data federation default)", func(t *testing.T) {
		cd := ParseCacheControl("")
		assert.False(t, cd.IsStale(time.Now()))
	})

	t.Run("max-age=0 is immediately stale", func(t *testing.T) {
		cd := ParseCacheControl("max-age=0")
		assert.True(t, cd.IsStale(time.Now().Add(-1*time.Millisecond)))
	})
}

func TestFreshness(t *testing.T) {
	t.Run("no freshness info", func(t *testing.T) {
		cd := ParseCacheControl("")
		_, ok := cd.Freshness()
		assert.False(t, ok)
	})

	t.Run("max-age only", func(t *testing.T) {
		cd := ParseCacheControl("max-age=600")
		f, ok := cd.Freshness()
		assert.True(t, ok)
		assert.Equal(t, 600*time.Second, f)
	})

	t.Run("max-age and s-maxage merged to maximum", func(t *testing.T) {
		cd := ParseCacheControl("max-age=3600, s-maxage=120")
		f, ok := cd.Freshness()
		assert.True(t, ok)
		assert.Equal(t, 3600*time.Second, f)
	})
}
