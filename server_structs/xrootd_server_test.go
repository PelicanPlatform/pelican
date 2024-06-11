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

package server_structs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCacheNS(t *testing.T) {
	t.Run("returns-empty-string-w-empty-input", func(t *testing.T) {
		assert.Empty(t, GetCacheNS(""))
	})

	t.Run("returns-prefix", func(t *testing.T) {
		assert.Equal(t, "/caches/hostname", GetCacheNS("hostname"))
		assert.Equal(t, "/caches/127.0.0.1", GetCacheNS("127.0.0.1"))
		assert.Equal(t, "/caches/https://example.org", GetCacheNS("https://example.org"))
		assert.Equal(t, "/caches/localhost:2000", GetCacheNS("localhost:2000"))
	})
}

func TestGetOriginNS(t *testing.T) {
	t.Run("returns-empty-string-w-empty-input", func(t *testing.T) {
		assert.Empty(t, GetOriginNs(""))
	})

	t.Run("returns-prefix", func(t *testing.T) {
		assert.Equal(t, "/origins/hostname", GetOriginNs("hostname"))
		assert.Equal(t, "/origins/127.0.0.1", GetOriginNs("127.0.0.1"))
		assert.Equal(t, "/origins/https://example.org", GetOriginNs("https://example.org"))
		assert.Equal(t, "/origins/localhost:2000", GetOriginNs("localhost:2000"))
	})
}

func TestIsCacheNS(t *testing.T) {
	t.Run("empty-ns-returns-false", func(t *testing.T) {
		assert.False(t, IsCacheNS(""))
	})

	t.Run("only-prefix-returns-false", func(t *testing.T) {
		assert.False(t, IsCacheNS("/caches"))
	})

	t.Run("only-prefix-with-slash-returns-false", func(t *testing.T) {
		assert.False(t, IsCacheNS("/caches/"))
	})

	t.Run("origin-prefix-returns-false", func(t *testing.T) {
		assert.False(t, IsCacheNS("/origins/"))
		assert.False(t, IsCacheNS("/origins/127.0.0.1"))
		assert.False(t, IsCacheNS("/origins/https://example.org"))
		assert.False(t, IsCacheNS("/origins/localhost:2000"))
	})

	t.Run("correct-ns-returns-true", func(t *testing.T) {
		assert.True(t, IsCacheNS("/caches/hostname"))
		assert.True(t, IsCacheNS("/caches/127.0.0.1"))
		assert.True(t, IsCacheNS("/caches/https://example.org"))
		assert.True(t, IsCacheNS("/caches/localhost:2000"))
	})
}

func TestIsOriginNS(t *testing.T) {
	t.Run("empty-ns-returns-false", func(t *testing.T) {
		assert.False(t, IsOriginNS(""))
	})

	t.Run("only-prefix-returns-false", func(t *testing.T) {
		assert.False(t, IsOriginNS("/origins"))
	})

	t.Run("only-prefix-with-slash-returns-false", func(t *testing.T) {
		assert.False(t, IsOriginNS("/origins/"))
	})

	t.Run("cache-prefix-returns-false", func(t *testing.T) {
		assert.False(t, IsOriginNS("/caches/"))
		assert.False(t, IsOriginNS("/caches/127.0.0.1"))
		assert.False(t, IsOriginNS("/caches/https://example.org"))
		assert.False(t, IsOriginNS("/caches/localhost:2000"))
	})

	t.Run("correct-ns-returns-true", func(t *testing.T) {
		assert.True(t, IsOriginNS("/origins/hostname"))
		assert.True(t, IsOriginNS("/origins/127.0.0.1"))
		assert.True(t, IsOriginNS("/origins/https://example.org"))
		assert.True(t, IsOriginNS("/origins/localhost:2000"))
	})
}
