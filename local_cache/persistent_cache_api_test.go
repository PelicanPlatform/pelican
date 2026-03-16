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

	"github.com/stretchr/testify/assert"
)

func TestIsFederationAllowed(t *testing.T) {
	const primary = "director.example.com:8444"

	t.Run("PrimaryAlwaysAllowed", func(t *testing.T) {
		assert.True(t, isFederationAllowed(primary, primary, nil))
		assert.True(t, isFederationAllowed(primary, primary, []string{}))
		assert.True(t, isFederationAllowed(primary, primary, []string{"other.example.com:443"}))
	})

	t.Run("PrimaryCaseInsensitive", func(t *testing.T) {
		assert.True(t, isFederationAllowed("Director.Example.COM:8444", primary, nil))
	})

	t.Run("EmptyListRejectsNonPrimary", func(t *testing.T) {
		assert.False(t, isFederationAllowed("other.example.com:443", primary, nil))
		assert.False(t, isFederationAllowed("other.example.com:443", primary, []string{}))
	})

	t.Run("WildcardAllowsAll", func(t *testing.T) {
		assert.True(t, isFederationAllowed("any.federation.org:443", primary, []string{"*"}))
		assert.True(t, isFederationAllowed("random.host:9999", primary, []string{"specific.host:443", "*"}))
	})

	t.Run("ExplicitListEntry", func(t *testing.T) {
		list := []string{"allowed.example.com:443", "also-allowed.org:8444"}
		assert.True(t, isFederationAllowed("allowed.example.com:443", primary, list))
		assert.True(t, isFederationAllowed("also-allowed.org:8444", primary, list))
		assert.False(t, isFederationAllowed("not-in-list.org:443", primary, list))
	})

	t.Run("ListEntryCaseInsensitive", func(t *testing.T) {
		list := []string{"Allowed.Example.COM:443"}
		assert.True(t, isFederationAllowed("allowed.example.com:443", primary, list))
	})
}
