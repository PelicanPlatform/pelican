//go:build linux && !ppc64le

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

package lotman

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestLotmanNewBindings exercises every wrapper added in PR-1 against a
// freshly-initialised lotman DB pre-populated by resources/lots-config.yaml
// (which installs the lots `default`, `root`, `test-1` and `test-2`).
func TestLotmanNewBindings(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	test_utils.InitServerForTest(t, context.Background(), server_structs.CacheType, test_utils.WithLazyFederationMock(nil, nil))

	success, cleanup := setupLotmanFromConf(t, true, "LotmanNewBindings", param.Federation_DiscoveryUrl.GetString(), nil)
	defer cleanup()
	require.True(t, success, "lotman initialisation must succeed before exercising bindings")

	t.Run("BindingsRegistered", func(t *testing.T) {
		require.NotNil(t, LotmanIsRoot)
		require.NotNil(t, LotmanListAllLots)
		require.NotNil(t, LotmanGetLotChildren)
		require.NotNil(t, LotmanGetLotsPastExp)
		require.NotNil(t, LotmanGetLotsPastDel)
		require.NotNil(t, LotmanGetLotsPastDed)
		require.NotNil(t, LotmanGetLotsPastOpp)
		require.NotNil(t, LotmanGetLotsPastObj)
		require.NotNil(t, LotmanGetPolicyAttributes)
		require.NotNil(t, LotmanGetLotDirs)
		require.NotNil(t, LotmanGetLotUsage)
		require.NotNil(t, LotmanGetAvailableCapacity)
		require.NotNil(t, LotmanRemoveLot)
		require.NotNil(t, LotmanFreeStringList)
		require.NotNil(t, LotmanSetContextInt)
		require.NotNil(t, LotmanGetContextInt)
	})

	t.Run("ListAllLots", func(t *testing.T) {
		lots, err := ListAllLots()
		require.NoError(t, err)
		assert.Contains(t, lots, "default")
		assert.Contains(t, lots, "root")
		assert.Contains(t, lots, "test-1")
		assert.Contains(t, lots, "test-2")
	})

	t.Run("LotExists", func(t *testing.T) {
		exists, err := LotExists("test-1")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, err = LotExists("nope-not-a-lot")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("IsRoot", func(t *testing.T) {
		isRoot, err := IsRoot("default")
		require.NoError(t, err)
		assert.True(t, isRoot, "default lot should be a root")

		isRoot, err = IsRoot("test-2")
		require.NoError(t, err)
		assert.False(t, isRoot, "test-2 should not be a root (its parent is test-1)")
	})

	t.Run("GetParentNames", func(t *testing.T) {
		parents, err := GetParentNames("test-2", false, false)
		require.NoError(t, err)
		assert.Equal(t, []string{"test-1"}, parents)

		parents, err = GetParentNames("test-2", true, false)
		require.NoError(t, err)
		assert.Contains(t, parents, "test-1")
		assert.Contains(t, parents, "root")
	})

	t.Run("GetChildrenNames", func(t *testing.T) {
		children, err := GetChildrenNames("test-1", false, false)
		require.NoError(t, err)
		assert.Equal(t, []string{"test-2"}, children)

		children, err = GetChildrenNames("root", true, false)
		require.NoError(t, err)
		assert.Contains(t, children, "test-1")
		assert.Contains(t, children, "test-2")
	})

	t.Run("GetOwners", func(t *testing.T) {
		owners, err := GetOwners("test-2", false)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://another-fake-federation.com"}, owners)

		owners, err = GetOwners("test-2", true)
		require.NoError(t, err)
		assert.Contains(t, owners, "https://another-fake-federation.com")
		assert.Contains(t, owners, "https://different-fake-federation.com")
		assert.Contains(t, owners, param.Federation_DiscoveryUrl.GetString())
	})

	t.Run("GetLotsFromDir", func(t *testing.T) {
		// test-1/test-2 declare creation_time=1234, expiration_time=12345.
		// Query within their active window (the new lotman API filters by time).
		lots, err := GetLotsFromDir("/test-1/test-2", false, 2000)
		require.NoError(t, err)
		assert.Equal(t, []string{"test-2"}, lots)

		// An unknown path resolves to the default lot.
		lots, err = GetLotsFromDir("/totally/unknown/path", false, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{"default"}, lots)
	})

	t.Run("GetLotDirs", func(t *testing.T) {
		dirs, err := GetLotDirs("test-1", false)
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		// Newer lotman may return the path with a trailing slash.
		assert.Contains(t, []string{"/test-1", "/test-1/"}, dirs[0].Path)
	})

	t.Run("GetLotUsage", func(t *testing.T) {
		yes := true
		usage, err := GetLotUsage(UsageRequest{
			LotName:     "test-1",
			DedicatedGB: &yes,
		})
		require.NoError(t, err)
		require.NotNil(t, usage)
		// No XRootD telemetry has been fed in, so dedicated usage must be zero.
		assert.Equal(t, float64(0), usage.DedicatedGB.Total)
	})

	t.Run("GetPolicyAttributes", func(t *testing.T) {
		rmpa, err := GetPolicyAttributes(PolicyAttrsRequest{
			LotName:     "test-2",
			DedicatedGB: true,
		})
		require.NoError(t, err)
		require.NotNil(t, rmpa)
		// `recursive` is implicit (the bool acts as the recursion flag in the
		// C API). The restricting value is therefore the smallest dedicated_GB
		// across {test-2, test-1, root}. test-2's configured value (1.11) is
		// the smallest, so it is the binding constraint.
		assert.InDelta(t, 1.11, rmpa.DedicatedGB.Value, 1e-6)
		assert.Equal(t, "test-2", rmpa.DedicatedGB.LotName)
	})

	t.Run("GetLotsPastExp", func(t *testing.T) {
		// The configured expiration_time for test-1 and test-2 is 12345ms
		// since the epoch -- decades in the past.
		expired, err := GetLotsPastExp(time.Now().UnixMilli(), false, false)
		require.NoError(t, err)
		assert.Contains(t, expired, "test-1")
		assert.Contains(t, expired, "test-2")
	})

	t.Run("GetLotsPastDel", func(t *testing.T) {
		// deletion_time was 123456ms -- also long past.
		past, err := GetLotsPastDel(time.Now().UnixMilli(), false, false)
		require.NoError(t, err)
		assert.Contains(t, past, "test-1")
	})

	t.Run("GetLotsPastDedHierarchical", func(t *testing.T) {
		// No usage reported -> nothing is past dedicated quota. We mainly want
		// to confirm the binding round-trips without error and respects the
		// hierarchical flag.
		_, err := GetLotsPastDed(true, false, false, true)
		require.NoError(t, err)
	})

	t.Run("GetLotsPastOpp", func(t *testing.T) {
		_, err := GetLotsPastOpp(true, false, false, false)
		require.NoError(t, err)
	})

	t.Run("GetLotsPastObj", func(t *testing.T) {
		_, err := GetLotsPastObj(true, false, false, false)
		require.NoError(t, err)
	})

	t.Run("GetAvailableCapacity", func(t *testing.T) {
		// Wide window covering test-1's configured creation_time..deletion_time.
		ac, err := GetAvailableCapacity("root", 0, time.Now().Add(365*24*time.Hour).UnixMilli())
		require.NoError(t, err)
		require.NotNil(t, ac)
		// root is a non-expiring container with the full cache disk as its
		// dedicated quota. We only assert the call succeeded and decoded;
		// capacity arithmetic is tested in unit tests closer to the C layer.
		_ = ac
	})

	t.Run("SetGetContextInt", func(t *testing.T) {
		require.NoError(t, SetContextInt("db_timeout", 7500))
		got, err := GetContextInt("db_timeout")
		require.NoError(t, err)
		assert.Equal(t, 7500, got)
	})

	t.Run("RemoveLot", func(t *testing.T) {
		// test-2 is a leaf -- safe to delete with no orphan-reassignment options.
		// The caller must be one of the lot's recursive owners; the federation
		// (root) issuer always qualifies.
		require.NoError(t, RemoveLot("test-2", false, false, false, false, param.Federation_DiscoveryUrl.GetString()))

		exists, err := LotExists("test-2")
		require.NoError(t, err)
		assert.False(t, exists, "test-2 should be gone after RemoveLot")
	})
}
