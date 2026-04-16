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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

//go:embed resources/lots-config.yaml
var yamlMockup string

//go:embed resources/malformed-lots-config.yaml
var badYamlMockup string

// Helper function for determining policy index from lot config yaml
func findPolicyIndex(policyName string, policies []PurgePolicy) int {
	for i, policy := range policies {
		if policy.PolicyName == policyName {
			return i
		}
	}
	return -1
}

// lotmanTestOpts controls optional behaviour of setupLotmanFromConf.
type lotmanTestOpts struct {
	clearCacheDataLocations bool
}

type lotmanTestOption func(*lotmanTestOpts)

// withoutCacheDataLocations forces Cache.DataLocations to an empty slice
// before InitLotman runs, exercising the HighWaterMark fallback path in
// computeRootDedicatedGB. Use only for tests that specifically validate
// that fallback; the default helper points DataLocations at a tmpdir so
// the disk-usage probe finds a real, accessible filesystem path.
func withoutCacheDataLocations() lotmanTestOption {
	return func(o *lotmanTestOpts) { o.clearCacheDataLocations = true }
}

// Initialize Lotman
// If we read from the embedded yaml, we need to override the SHOULD_OVERRIDE keys with the discUrl
// so that underlying metadata discovery can happen against the mock discovery host
func setupLotmanFromConf(t *testing.T, readConfig bool, name string, discUrl string, nsAds []server_structs.NamespaceAdV2, opts ...lotmanTestOption) (bool, func()) {
	o := lotmanTestOpts{}
	for _, opt := range opts {
		opt(&o)
	}
	// Load in our config and handle overriding the SHOULD_OVERRIDE keys with the discUrl
	// Load in our config
	require.NoError(t, param.Cache_HighWaterMark.Set("100g"))
	require.NoError(t, param.Cache_LowWatermark.Set("50g"))
	require.NoError(t, param.Logging_Level.Set("debug"))
	// The newer lotman library strictly enforces creation_time < expiration_time
	// when storing a lot. The auto-created `default` and `root` lots derive
	// their timestamps from these params, so we must ensure non-zero defaults
	// regardless of whether the embedded yaml is loaded.
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(168*time.Hour))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(168*time.Hour))
	if readConfig {
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(strings.NewReader(yamlMockup))
		if err != nil {
			t.Fatalf("Error reading config: %v", err)
		}

		// Grab the policy, figure out which one we're using and override the lot issuers/owners
		var policies []PurgePolicy
		err = viper.UnmarshalKey("Lotman.PolicyDefinitions", &policies)
		require.NoError(t, err)
		enabledPolicy := viper.GetString("Lotman.EnabledPolicy")
		policyIndex := findPolicyIndex(enabledPolicy, policies)
		if policyIndex == -1 {
			t.Fatalf("Policy %s not found", enabledPolicy)
		}
		policy := policies[policyIndex]

		for i, lot := range policy.Lots {
			if lot.Owner == "SHOULD_OVERRIDE" {
				lot.Owner = discUrl
				policy.Lots[i] = lot
			}
		}

		// Update the policy in viper
		policies[policyIndex] = policy
		require.NoError(t, param.Lotman_PolicyDefinitions.Set(policies))
	} else {
		// If we're not reading from the embedded yaml, grab the
		// default configuration. We need _some_ configuration to work.
		require.NoError(t, param.ConfigBase.Set(t.TempDir()))
		_ = config.InitServer(context.Background(), server_structs.CacheType)
	}

	tmpPathPattern := name + "*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	require.NoError(t, param.Lotman_LotHome.Set(tmpPath))
	// Always override Cache.DataLocations so InitLotman's disk-usage probe
	// never touches the real default path ("/run/pelican/cache/data"),
	// which does not exist in CI environments. Tests that need to exercise
	// the HighWaterMark fallback in computeRootDedicatedGB must opt in
	// explicitly via withoutCacheDataLocations(); we can't honour a
	// caller-set value here because param.IsSet() returns true even when
	// only the default is in play.
	if o.clearCacheDataLocations {
		require.NoError(t, param.Cache_DataLocations.Set([]string{}))
	} else {
		require.NoError(t, param.Cache_DataLocations.Set([]string{tmpPath}))
	}
	success := InitLotman(nsAds)
	//reset func
	return success, func() {
		server_utils.ResetTestState()
	}
}

// Create a mock discovery host that returns the servers URL as the value for each pelican-configuration key
func getMockDiscoveryHost() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/pelican-configuration" {
			w.Header().Set("Content-Type", "application/json")
			serverURL := r.Host
			response := fmt.Sprintf(`{
  "director_endpoint": "https://%s/osdf-director.osg-htc.org",
  "namespace_registration_endpoint": "https://%s/osdf-registry.osg-htc.org",
  "jwks_uri": "https://%s/osdf/public_signing_key.jwks"
}`, serverURL, serverURL, serverURL)
			_, _ = w.Write([]byte(response))
		} else {
			http.NotFound(w, r)
		}
	}))
}

// Test the library initializer. NOTE: this also tests CreateLot, which is a part of initialization.
func TestLotmanInit(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	t.Run("TestBadInit", func(t *testing.T) {
		// We haven't set various bits needed to create the lots, like discovery URL
		success, cleanup := setupLotmanFromConf(t, false, "LotmanBadInit", "", nil)
		defer cleanup()
		require.False(t, success)
	})

	t.Run("TestGoodInit", func(t *testing.T) {
		require.NoError(t, param.Logging_Level.Set("debug"))
		server := getMockDiscoveryHost()
		// Set the Federation.DiscoveryUrl to the test server's URL
		// Lotman uses the discovered URLs/keys to determine some aspects of lot ownership
		require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

		success, cleanup := setupLotmanFromConf(t, false, "LotmanGoodInit", server.URL, nil, withoutCacheDataLocations())
		defer cleanup()
		require.True(t, success)

		// Now that we've initialized (without config) test that we have default/root
		defaultOutput := make([]byte, 4096)
		errMsg := make([]byte, 2048)

		ret := LotmanGetLotJSON("default", false, &defaultOutput, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			t.Fatalf("Error getting lot JSON: %s", string(errMsg))
		}
		trimBuf(&defaultOutput)
		var defaultLot Lot
		err := json.Unmarshal(defaultOutput, &defaultLot)
		require.NoError(t, err, fmt.Sprintf("Error unmarshalling default lot JSON: %s", string(defaultOutput)))
		require.Equal(t, "default", defaultLot.LotName)
		require.Equal(t, server.URL, defaultLot.Owner)
		require.Equal(t, "default", defaultLot.Parents[0])
		// default has literal-zero storage quotas (lotman PR #46 reserves -1
		// for unbounded). Any usage of default puts it over-quota and the
		// purge plugin reclaims it on the next cycle.
		require.Equal(t, float64(0), *(defaultLot.MPA.DedicatedGB))
		require.Equal(t, float64(0), *(defaultLot.MPA.OpportunisticGB))
		require.Equal(t, int64(0), defaultLot.MPA.MaxNumObjects.Value)

		rootOutput := make([]byte, 4096)
		ret = LotmanGetLotJSON("root", false, &rootOutput, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			t.Fatalf("Error getting lot JSON: %s", string(errMsg))
		}
		trimBuf(&rootOutput)
		var rootLot Lot
		err = json.Unmarshal(rootOutput, &rootLot)
		require.NoError(t, err, fmt.Sprintf("Error unmarshalling root lot JSON: %s", string(rootOutput)))
		require.Equal(t, "root", rootLot.LotName)
		require.Equal(t, server.URL, rootLot.Owner)
		require.Equal(t, "root", rootLot.Parents[0])
		// root's dedicatedGB is set to the full cache disk space; when no
		// disks are detected (as in this test) it falls back to
		// Cache.HighWaterMark, which setupLotmanFromConf sets to "100g".
		// Opportunistic and object quotas are unbounded (-1 sentinel,
		// lotman PR #46).
		require.InDelta(t, float64(100), *(rootLot.MPA.DedicatedGB), 1e-6)
		require.Equal(t, float64(-1), *(rootLot.MPA.OpportunisticGB))
		require.Equal(t, int64(-1), rootLot.MPA.MaxNumObjects.Value)
	})
}

func TestLotmanInitFromConfig(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Lotman is initialized, let's check that it has the information it should based on the config
	defaultOutput := make([]byte, 4096)
	errMsg := make([]byte, 2048)

	// Check for default lot
	ret := LotmanGetLotJSON("default", false, &defaultOutput, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		t.Fatalf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&defaultOutput)
	var defaultLot Lot
	err := json.Unmarshal(defaultOutput, &defaultLot)
	require.NoError(t, err, fmt.Sprintf("Error unmarshalling default lot JSON: %s", string(defaultOutput)))
	require.Equal(t, "default", defaultLot.LotName)
	require.Equal(t, server.URL, defaultLot.Owner)
	require.Equal(t, "default", defaultLot.Parents[0])

	// Now root
	rootOutput := make([]byte, 4096)
	ret = LotmanGetLotJSON("root", false, &rootOutput, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		t.Fatalf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&rootOutput)
	var rootLot Lot
	err = json.Unmarshal(rootOutput, &rootLot)
	require.NoError(t, err, fmt.Sprintf("Error unmarshalling root lot JSON: %s", string(rootOutput)))
	require.Equal(t, "root", rootLot.LotName)
	require.Equal(t, server.URL, rootLot.Owner)
	require.Equal(t, "root", rootLot.Parents[0])
	require.Equal(t, "/", rootLot.Paths[0].Path)
	require.False(t, rootLot.Paths[0].Recursive)

	// Now test-1
	test1Output := make([]byte, 4096)
	ret = LotmanGetLotJSON("test-1", false, &test1Output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		t.Fatalf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&test1Output)
	var test1Lot Lot
	err = json.Unmarshal(test1Output, &test1Lot)
	require.NoError(t, err, fmt.Sprintf("Error unmarshalling test-1 lot JSON: %s", string(test1Output)))
	require.Equal(t, "test-1", test1Lot.LotName)
	require.Equal(t, "https://different-fake-federation.com", test1Lot.Owner)
	require.Equal(t, "root", test1Lot.Parents[0])
	require.Equal(t, 1.11, *(test1Lot.MPA.DedicatedGB))
	require.Equal(t, int64(42), test1Lot.MPA.MaxNumObjects.Value)
	// Newer lotman normalises lot paths with a trailing slash on retrieval.
	require.Equal(t, "/test-1/", test1Lot.Paths[0].Path)
	require.False(t, test1Lot.Paths[0].Recursive)

	// Finally test-2
	test2Output := make([]byte, 4096)
	ret = LotmanGetLotJSON("test-2", false, &test2Output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		t.Fatalf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&test2Output)
	var test2Lot Lot
	err = json.Unmarshal(test2Output, &test2Lot)
	require.NoError(t, err, fmt.Sprintf("Error unmarshalling test-2 lot JSON: %s", string(test2Output)))
	require.Equal(t, "test-2", test2Lot.LotName)
	require.Equal(t, "https://another-fake-federation.com", test2Lot.Owner)
	require.Equal(t, "test-1", test2Lot.Parents[0])
	require.Equal(t, 1.11, *(test2Lot.MPA.DedicatedGB))
	require.Equal(t, int64(42), test2Lot.MPA.MaxNumObjects.Value)
	// Newer lotman normalises lot paths with a trailing slash on retrieval.
	require.Equal(t, "/test-1/test-2/", test2Lot.Paths[0].Path)
	require.True(t, test2Lot.Paths[0].Recursive)
}

func TestGetLotmanLib(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	libLoc := getLotmanLib()
	require.Equal(t, "/usr/lib64/libLotMan.so", libLoc)

	// Now try to fool it and see that we get the same value back. We can detect this by
	// capturing the log output
	logOutput := &(bytes.Buffer{})
	log.SetOutput(logOutput)
	config.SetLogging(log.DebugLevel)
	require.NoError(t, param.Lotman_LibLocation.Set("/not/a/pathlibLotMan.so"))
	libLoc = getLotmanLib()
	require.Equal(t, "/usr/lib64/libLotMan.so", libLoc)
	require.Contains(t, logOutput.String(), "libLotMan.so not found in configured path, attempting to find using known fallbacks")
}

func TestGetAuthzCallers(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanGetAuthzCalleres", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Lotman is initialized, let's check that it has the information it should based on the config
	// test-2's authzed callers are the owners of root and test-1
	authzedCallers, err := GetAuthorizedCallers("test-2")
	require.NoError(t, err, "Failed to get authorized callers")
	require.Equal(t, 2, len(*authzedCallers))
	require.Contains(t, *authzedCallers, server.URL)
	require.Contains(t, *authzedCallers, "https://different-fake-federation.com")

	// test with a non-existent lot
	_, err = GetAuthorizedCallers("non-existent-lot")
	require.Error(t, err, "Expected error for non-existent lot")
}

func TestGetLot(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanGetLot", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	lot, err := GetLot("test-2", true)
	require.NoError(t, err, "Failed to get lot")
	require.NotNil(t, lot)
	require.Equal(t, "test-2", (lot).LotName)
	require.Equal(t, 2, len(lot.Parents))
	require.Contains(t, lot.Parents, "root")
	require.Contains(t, lot.Parents, "test-1")
	require.Equal(t, 3, len(lot.Owners))
	require.Contains(t, lot.Owners, server.URL)
	require.Contains(t, lot.Owners, "https://different-fake-federation.com")
	require.Contains(t, lot.Owners, "https://another-fake-federation.com")
	require.Equal(t, 1.11, *(lot.MPA.DedicatedGB))
	require.Equal(t, int64(42), lot.MPA.MaxNumObjects.Value)
	// Newer lotman normalises lot paths with a trailing slash on retrieval.
	require.Equal(t, "/test-1/test-2/", lot.Paths[0].Path)
	require.True(t, lot.Paths[0].Recursive)
}

func TestUpdateLot(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Update the test-1 lot. Under strict_hierarchy a child's DedicatedGB
	// cannot exceed its parent's (root), which is derived from
	// Cache.HighWaterMark ("100g" in tests). Use 50 GB: clearly different
	// from the initial 1.11 and well within root's 100 GB ceiling.
	dedicatedGB := float64(50.0)
	lotUpdate := LotUpdate{
		LotName: "test-1",
		MPA: &MPA{
			DedicatedGB: &dedicatedGB,
			MaxNumObjects: &Int64FromFloat{
				Value: 84,
			},
		},
		Paths: &[]PathUpdate{
			{
				Current:   "/test-1",
				New:       "/test-1-updated",
				Recursive: false,
			},
		},
	}

	err := UpdateLot(&lotUpdate, server.URL)
	require.NoError(t, err, "Failed to update lot")

	// Now check that the update was successful
	lot, err := GetLot("test-1", true)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, dedicatedGB, *(lot.MPA.DedicatedGB))
	require.Equal(t, int64(84), lot.MPA.MaxNumObjects.Value)
	// Newer lotman normalises lot paths with a trailing slash on retrieval.
	require.Equal(t, "/test-1-updated/", lot.Paths[0].Path)
	require.False(t, lot.Paths[0].Recursive)
}

func TestAddToLot(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	newLotPath := LotPath{
		Path:      "/a/new/path",
		Recursive: true,
	}
	// default has zero storage MPAs (lotman PR #46), so we must explicitly
	// attribute 0 of test-1's quota to default; root absorbs the full
	// child MPA (test-1 is configured with 1.11 / 2.22 / 42).
	zeroDed := float64(0)
	zeroOpp := float64(0)
	childDed := float64(1.11)
	childOpp := float64(2.22)
	addition := LotAddition{
		LotName: "test-1",
		Paths:   []LotPath{newLotPath},
		Parents: []string{"default"},
		ParentAttributions: map[string]ParentAttribution{
			"default": {DedicatedGB: &zeroDed, OpportunisticGB: &zeroOpp, MaxNumObjects: &Int64FromFloat{Value: 0}},
			"root":    {DedicatedGB: &childDed, OpportunisticGB: &childOpp, MaxNumObjects: &Int64FromFloat{Value: 42}},
		},
	}

	err := AddToLot(&addition, server.URL)
	require.NoError(t, err, "Failed to add to lot")
	// Only after adding values to the lot do we set the lot name
	// -- this lets us do the comparison later, as `GetLot()`` sets this value but
	// `AddToLot()`` doesn't accept it
	newLotPath.LotName = "test-1"
	// Newer lotman normalises lot paths with a trailing slash on retrieval.
	newLotPath.Path = "/a/new/path/"

	// Now check that the addition was successful
	lot, err := GetLot("test-1", false)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, 2, len(lot.Paths), fmt.Sprintf("Expected 2 paths, got %+v", lot.Paths))
	require.Contains(t, lot.Paths, newLotPath)
}

func TestRemoveLotParents(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// First add default lot as parent to test-1, then remove it. We do this
	// because lotman won't let us remove _all_ parents.
	// default has zero storage MPAs (lotman PR #46), so attribute 0 to it
	// and the full child MPA to root.
	zeroDed := float64(0)
	zeroOpp := float64(0)
	childDed := float64(1.11)
	childOpp := float64(2.22)
	addition := LotAddition{
		LotName: "test-1",
		Parents: []string{"default"},
		ParentAttributions: map[string]ParentAttribution{
			"default": {DedicatedGB: &zeroDed, OpportunisticGB: &zeroOpp, MaxNumObjects: &Int64FromFloat{Value: 0}},
			"root":    {DedicatedGB: &childDed, OpportunisticGB: &childOpp, MaxNumObjects: &Int64FromFloat{Value: 42}},
		},
	}
	err := AddToLot(&addition, server.URL)
	require.NoError(t, err, "Failed to add to lot")
	// Now check that the addition was successful
	lot, err := GetLot("test-1", false)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, 2, len(lot.Parents), fmt.Sprintf("Expected 2 parents, got %+v", lot.Parents))
	require.Contains(t, lot.Parents, "default")

	// Now remove the default parent
	removal := LotParentRemoval{
		LotName: "test-1",
		Parents: []string{"default"},
	}
	err = RemoveLotParents(&removal, server.URL)
	require.NoError(t, err, "Failed to remove lot parents")
	// Now check that the removal was successful
	lot, err = GetLot("test-1", false)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, 1, len(lot.Parents), fmt.Sprintf("Expected 1 parent, got %+v", lot.Parents))
	require.NotContains(t, lot.Parents, "default")
}

func TestRemoveLotPaths(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Remove the pre-configured path
	removal := LotPathRemoval{
		Paths: []string{"/test-1"},
	}

	err := RemoveLotPaths(&removal, server.URL)
	require.NoError(t, err, "Failed to remove lot paths")
	// Now check that the removal was successful
	lot, err := GetLot("test-1", false)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, 0, len(lot.Paths), fmt.Sprintf("Expected 0 paths, got %+v", lot.Paths))
}

func TestDeleteLotsRec(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Delete test-1, then verify both it and test-2 are gone
	err := DeleteLotsRecursive("test-1", server.URL)
	require.NoError(t, err, "Failed to delete lot")

	// Now check that the delete was successful
	lot, err := GetLot("test-1", false)
	require.Error(t, err, "Expected error for non-existent lot")
	require.Nil(t, lot)

	lot, err = GetLot("test-2", false)
	require.Error(t, err, "Expected error for non-existent lot")
	require.Nil(t, lot)
}

// In any case where two MPA values are both set, the value in MPA1 should win.
func TestMergeMPAs(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	dedicatedGB1 := 10.0
	maxNumObjects1 := Int64FromFloat{Value: 50}
	creationTime1 := Int64FromFloat{Value: 200}
	deletionTime1 := Int64FromFloat{Value: 400}

	dedicatedGB2 := 20.0
	opportunisticGB2 := 30.0
	maxNumObjects2 := Int64FromFloat{Value: 100}
	expirationTime2 := Int64FromFloat{Value: 300}

	mpa1 := &MPA{
		DedicatedGB:   &dedicatedGB1,
		MaxNumObjects: &maxNumObjects1,
		CreationTime:  &creationTime1,
		DeletionTime:  &deletionTime1,
	}

	mpa2 := &MPA{
		DedicatedGB:     &dedicatedGB2,
		OpportunisticGB: &opportunisticGB2,
		MaxNumObjects:   &maxNumObjects2,
		ExpirationTime:  &expirationTime2,
	}

	expectedMPA := &MPA{
		DedicatedGB:     &dedicatedGB1,
		OpportunisticGB: &opportunisticGB2,
		MaxNumObjects:   &maxNumObjects1,
		CreationTime:    &creationTime1,
		ExpirationTime:  &expirationTime2,
		DeletionTime:    &deletionTime1,
	}

	mergedMPA := mergeMPAs(mpa1, mpa2)
	require.Equal(t, expectedMPA, mergedMPA)
}

func TestLotMerging(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Owner should be set to lot1 owner
	owner1 := "owner1"
	owner2 := "owner2"

	// Parents should be the union of lot1 and lot2 parents
	parent1 := "parent1"
	parent2 := "parent2"
	parent3 := "parent3"

	// MPA should be the MPA of lot1, unless no value is set
	dedicatedGB1 := 10.0
	dedicatedGB2 := 20.0
	opportunisticGB2 := 30.0

	lot1 := Lot{
		LotName: "some-lot",
		Owner:   owner1,
		Parents: []string{parent1, parent2},
		MPA: &MPA{
			DedicatedGB: &dedicatedGB1,
		},
	}

	lot2 := Lot{
		LotName: "some-lot",
		Owner:   owner2,
		Parents: []string{parent2, parent3},
		MPA: &MPA{
			DedicatedGB:     &dedicatedGB2,
			OpportunisticGB: &opportunisticGB2,
		},
	}

	expectedMergedLot := Lot{
		LotName: "some-lot",
		Owner:   owner1,
		Parents: []string{parent1, parent2, parent3},
		MPA: &MPA{
			DedicatedGB:     &dedicatedGB1,
			OpportunisticGB: &opportunisticGB2,
		},
	}

	mergedLot, err := mergeLots(lot1, lot2)
	require.NoError(t, err)
	require.Equal(t, expectedMergedLot.LotName, mergedLot.LotName)
	require.Equal(t, expectedMergedLot.Owner, mergedLot.Owner)
	require.ElementsMatch(t, expectedMergedLot.Parents, mergedLot.Parents)
	require.Equal(t, expectedMergedLot.MPA.DedicatedGB, mergedLot.MPA.DedicatedGB)
	require.Equal(t, expectedMergedLot.MPA.OpportunisticGB, mergedLot.MPA.OpportunisticGB)

	// Now test with no MPA set in lot1
	lot1.MPA = nil
	expectedMergedLot.MPA.DedicatedGB = &dedicatedGB2
	mergedLot, err = mergeLots(lot1, lot2)
	require.NoError(t, err)
	require.Equal(t, expectedMergedLot.MPA.DedicatedGB, mergedLot.MPA.DedicatedGB)

	// Make sure we can't merge lots with different names
	lot2.LotName = "different-lot"
	mergedLot, err = mergeLots(lot1, lot2)
	require.Error(t, err)

	// Test merging lot maps -- reset lot2's name so we can merge them
	// Here we intentionally assign lot2 to the lot1 key to test that the merge works
	// while also adding lot2 as its own key to test that the merge works with multiple lots
	lot2.LotName = "some-lot"
	lotMap1 := map[string]Lot{
		"lot1": lot1,
	}
	lotMap2 := map[string]Lot{
		"lot1": lot2,
		"lot2": lot2,
	}
	mergedMaps, err := mergeLotMaps(lotMap1, lotMap2)
	require.NoError(t, err)
	require.Equal(t, 2, len(mergedMaps))
	require.Equal(t, "some-lot", mergedMaps["lot1"].LotName)
	require.Equal(t, expectedMergedLot.Owner, mergedMaps["lot1"].Owner)
	require.ElementsMatch(t, expectedMergedLot.Parents, mergedMaps["lot1"].Parents)
	require.Equal(t, expectedMergedLot.MPA.DedicatedGB, mergedMaps["lot1"].MPA.DedicatedGB)
	require.Equal(t, expectedMergedLot.MPA.OpportunisticGB, mergedMaps["lot1"].MPA.OpportunisticGB)
}

// Read the mockup yaml and make sure we grab the list of policy definitions as expected
func TestGetPolicyMap(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name             string
		yamlConfig       string
		expectErr        bool
		expectedPolicies []string
	}{
		{
			name:             "ValidConfig",
			yamlConfig:       yamlMockup,
			expectErr:        false,
			expectedPolicies: []string{"different-policy", "another policy"},
		},
		{
			name:             "InvalidConfig",
			yamlConfig:       badYamlMockup,
			expectErr:        true,
			expectedPolicies: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.SetConfigType("yaml")
			err := viper.ReadConfig(strings.NewReader(tc.yamlConfig))
			if err != nil {
				t.Fatalf("Error reading config: %v", err)
			}

			policyMap, err := GetPolicyMap()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.expectedPolicies), len(policyMap))
				for _, policy := range tc.expectedPolicies {
					require.Contains(t, policyMap, policy)
				}
				require.Equal(t, "different-policy", viper.GetString("Lotman.EnabledPolicy"))
			}
		})
	}
}

func TestByteConversions(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	bytes := uint64(120530000000) // 120.53 GB

	// forward pass
	gb := bytesToGigabytes(bytes)
	require.Equal(t, 120.53, gb)

	// reverse pass
	bytes = gigabytesToBytes(gb)
	require.Equal(t, uint64(120530000000), bytes)
}

// Valid lot configuration not only requires that all fields are present, but also that the sum of all lots' dedicatedGB values
// does not exceed the high watermark.
func TestLotValidation(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	type testCase struct {
		name            string
		lots            []Lot
		hwm             string
		totalDiskSpaceB uint64
		errorStrings    []string
	}

	createValidLot := func(name string, owner string, parent string, path string, dedicatedGB float64) Lot {
		return Lot{
			LotName: name,
			Owner:   owner,
			Parents: []string{parent},
			Paths: []LotPath{
				{
					Path:      path,
					Recursive: false,
				},
			},
			MPA: &MPA{
				DedicatedGB:     &dedicatedGB,
				OpportunisticGB: &dedicatedGB,
				CreationTime:    &Int64FromFloat{Value: 1},
				ExpirationTime:  &Int64FromFloat{Value: 2},
				DeletionTime:    &Int64FromFloat{Value: 3},
			},
		}
	}

	testCases := []testCase{
		{
			name: "Valid lots",
			lots: []Lot{
				createValidLot("lot1", "owner1", "root", "/foo/bar", 10.0),
				createValidLot("lot2", "owner2", "root", "/foo/baz", 20.0),
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    nil,
		},
		{
			name: "Missing lot name",
			lots: []Lot{
				createValidLot("", "owner1", "root", "/foo/bar", 10.0),
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"detected a lot with no name"},
		},
		{
			name: "Missing lot owner",
			lots: []Lot{
				createValidLot("lot1", "", "root", "/foo/bar", 10.0),
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the lot 'lot1' is missing required values", "Owner"},
		},
		{
			name: "Missing lot parent",
			lots: []Lot{
				createValidLot("lot1", "owner", "", "/foo/bar", 10.0),
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the lot 'lot1' is missing required values", "Parents"},
		},
		{
			name: "Missing lot path",
			lots: []Lot{
				createValidLot("lot1", "owner", "root", "", 10.0),
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the lot 'lot1' is missing required values", "Paths.Path"},
		},
		{
			name: "Missing lot MPA",
			lots: []Lot{
				{
					LotName: "lot1",
					Owner:   "owner1",
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/foo/bar",
							Recursive: false,
						},
					},
				},
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the lot 'lot1' is missing required values", "ManagementPolicyAttrs"},
		},
		{
			name: "Missing lot MPA subfield",
			lots: []Lot{
				{
					LotName: "lot1",
					Owner:   "owner1",
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/foo/bar",
							Recursive: false,
						},
					},
					MPA: &MPA{},
				},
			},
			hwm:             "30g",
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the lot 'lot1' is missing required values", "ManagementPolicyAttrs.DedicatedGB"},
		},
		{
			name: "Invalid dedGB sum",
			lots: []Lot{
				createValidLot("lot1", "owner1", "root", "/foo/bar", 10.0),
				createValidLot("lot2", "owner2", "root", "/foo/baz", 20.0),
			},
			hwm:             "20g", // sum of dedGB should not be greater than hwm
			totalDiskSpaceB: gigabytesToBytes(40.0),
			errorStrings:    []string{"the sum of all lots' dedicatedGB values exceeds the high watermark of 20g."},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()
			require.NoError(t, param.Cache_HighWaterMark.Set(tc.hwm))
			err := validateLotsConfig(tc.lots, tc.totalDiskSpaceB)
			if len(tc.errorStrings) > 0 {
				require.Error(t, err)
				for _, errStr := range tc.errorStrings {
					require.Contains(t, err.Error(), errStr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Make sure we handle various suffixes and non-suffixed percentages correctly
func TestConvertWatermarkToBytes(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	type testCase struct {
		Name          string
		Watermark     string
		Expected      uint64
		ErrorExpected bool
	}

	totDisk := uint64(1000000000000) // 1TB
	testCases := []testCase{
		{
			Name:          "Valid 'k' suffix",
			Watermark:     "100.1k",
			Expected:      uint64(100100), // 100KB
			ErrorExpected: false,
		},
		{
			Name:          "Valid 'm' suffix",
			Watermark:     "100m",
			Expected:      uint64(100000000), // 100MB
			ErrorExpected: false,
		},
		{
			Name:          "Valid 'g' suffix",
			Watermark:     "100g",
			Expected:      uint64(100000000000), // 100GB
			ErrorExpected: false,
		},
		{
			Name:          "Valid 't' suffix",
			Watermark:     "100t",
			Expected:      uint64(100000000000000), // 100TB
			ErrorExpected: false,
		},
		{
			Name:          "No suffix is percentage",
			Watermark:     "50.5",
			Expected:      uint64(505000000000), // 500GB
			ErrorExpected: false,
		},
		{
			Name:          "Invalid suffix",
			Watermark:     "100z",
			Expected:      uint64(0),
			ErrorExpected: true,
		},
		{
			Name:          "Invalid value",
			Watermark:     "foo",
			Expected:      uint64(0),
			ErrorExpected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := convertWatermarkToBytes(tc.Watermark, totDisk)
			if tc.ErrorExpected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf("%d", tc.Expected), fmt.Sprintf("%d", result))
			}
		})
	}
}

// TestComputeRootDedicatedGB_ClampsToHWM verifies that the root lot's
// dedicated quota is clamped down to Cache.HighWaterMark and
// Cache.FilesMaxSize when those would be lower than raw disk total,
// since xrootd will purge once usage exceeds those thresholds.
func TestComputeRootDedicatedGB_ClampsToHWM(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	totalDisk := gigabytesToBytes(1000.0) // 1 TB

	t.Run("no disk falls back to HWM as absolute bytes", func(t *testing.T) {
		server_utils.ResetTestState()
		defer server_utils.ResetTestState()
		require.NoError(t, param.Cache_HighWaterMark.Set("100g"))
		got := computeRootDedicatedGB(0)
		require.InDelta(t, 100.0, got, 0.001)
	})

	t.Run("HWM percent clamps below disk total", func(t *testing.T) {
		server_utils.ResetTestState()
		defer server_utils.ResetTestState()
		require.NoError(t, param.Cache_HighWaterMark.Set("90"))
		got := computeRootDedicatedGB(totalDisk)
		// 90% of 1000 GB = 900 GB
		require.InDelta(t, 900.0, got, 0.001)
	})

	t.Run("HWM byte value clamps below disk total", func(t *testing.T) {
		server_utils.ResetTestState()
		defer server_utils.ResetTestState()
		require.NoError(t, param.Cache_HighWaterMark.Set("500g"))
		got := computeRootDedicatedGB(totalDisk)
		require.InDelta(t, 500.0, got, 0.001)
	})

	t.Run("HWM higher than disk uses disk total", func(t *testing.T) {
		server_utils.ResetTestState()
		defer server_utils.ResetTestState()
		require.NoError(t, param.Cache_HighWaterMark.Set("100"))
		got := computeRootDedicatedGB(totalDisk)
		require.InDelta(t, 1000.0, got, 0.001)
	})

	t.Run("FilesMaxSize clamps below HWM-clamped disk total", func(t *testing.T) {
		server_utils.ResetTestState()
		defer server_utils.ResetTestState()
		require.NoError(t, param.Cache_HighWaterMark.Set("90"))
		require.NoError(t, param.Cache_FilesMaxSize.Set("250g"))
		got := computeRootDedicatedGB(totalDisk)
		require.InDelta(t, 250.0, got, 0.001)
	})
}

// TestStrictHierarchyContextSet verifies that InitLotman installs the
// strict-hierarchy execution context (PR-2): the three flags
// strict_hierarchy, contraction_policy, and admin_override must each be
// readable via lotman_get_context_str with the documented values after a
// successful init.
func TestStrictHierarchyContextSet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanStrictHierCtx", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	cases := []struct {
		key, want string
	}{
		{"strict_hierarchy", "true"},
		{"contraction_policy", "always"},
		{"admin_override", "false"},
	}
	for _, c := range cases {
		out := make([]byte, 256)
		errMsg := make([]byte, 2048)
		ret := LotmanGetContextStr(c.key, &out, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			t.Fatalf("LotmanGetContextStr(%s) failed: %s", c.key, string(errMsg))
		}
		trimBuf(&out)
		assert.Equal(t, c.want, string(out), "context flag %s should be %q", c.key, c.want)
	}
}

// TestLotmanVersionCompatibility verifies that checkLotmanVersionCompatibility
// accepts the version string returned by the currently loaded libLotMan.so
// (which must be >= v0.1.0 to support strict_hierarchy + parent_attributions).
func TestLotmanVersionCompatibility(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	success, cleanup := setupLotmanFromConf(t, true, "LotmanVersionCheck", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	assert.True(t, checkLotmanVersionCompatibility(),
		"installed lotman version %q must be >= %s", LotmanVersion(), minLotmanVersion)
}

// TestInitLotmanNestedNamespaces drives the full PR-3/PR-4 path-prefix
// nesting pipeline through a real lotman_add_lot call. Three namespaces
// are submitted: /a, /a/b, and /c. Expected lot tree:
//
//	root -> /a -> /a/b
//	root -> /c
//
// The test confirms (1) parent linkage stored by lotman matches the tree
// computed by buildLotTree, (2) per-axis ParentAttributions written via
// lotman_add_lot are honoured by lotman_get_lot_as_json, and (3) the
// (N+1) allocator yields the documented quotas at each level.
func TestInitLotmanNestedNamespaces(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	server := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

	nsAds := makeAds("/a", "/a/b", "/c")
	success, cleanup := setupLotmanFromConf(t, false, "LotmanNested", server.URL, nsAds, withoutCacheDataLocations())
	defer cleanup()
	require.True(t, success)

	// Lots are named with v4 UUIDs internally; resolve UUID names by
	// asking lotman which lot owns the namespace path right now.
	nowMs := time.Now().UnixMilli()
	nameForPath := func(p string) string {
		owners, err := GetLotsFromDir(p, false, nowMs)
		require.NoErrorf(t, err, "GetLotsFromDir(%q)", p)
		require.NotEmptyf(t, owners, "no lot owns %q", p)
		// owners[0] is the most-specific lot for the path.
		return owners[0]
	}

	getLot := func(name string) Lot {
		buf := make([]byte, 8192)
		errBuf := make([]byte, 2048)
		ret := LotmanGetLotJSON(name, false, &buf, &errBuf)
		if ret != 0 {
			trimBuf(&errBuf)
			t.Fatalf("get lot %q failed: %s", name, string(errBuf))
		}
		trimBuf(&buf)
		var l Lot
		require.NoErrorf(t, json.Unmarshal(buf, &l), "unmarshal %q: %s", name, string(buf))
		return l
	}

	aName := nameForPath("/a")
	bName := nameForPath("/a/b")
	cName := nameForPath("/c")
	a := getLot(aName)
	b := getLot(bName)
	c := getLot(cName)

	// Parent linkage as computed by buildLotTree.
	assert.Equal(t, []string{"root"}, a.Parents)
	assert.Equal(t, []string{aName}, b.Parents)
	assert.Equal(t, []string{"root"}, c.Parents)

	// (N+1) allocator: root has HighWaterMark=100GB (no Cache.DataLocations
	// set, so HWM is the fallback root quota) and 2 top-level children
	// /a and /c, so each gets 100/2 = 50 GB.
	require.NotNil(t, a.MPA.DedicatedGB)
	require.NotNil(t, c.MPA.DedicatedGB)
	assert.InDelta(t, 50.0, *a.MPA.DedicatedGB, 1e-9)
	assert.InDelta(t, 50.0, *c.MPA.DedicatedGB, 1e-9)

	// /a then has 1 child, divisor = N+1 = 2, so /a/b gets 50/2 = 25 GB.
	require.NotNil(t, b.MPA.DedicatedGB)
	assert.InDelta(t, 25.0, *b.MPA.DedicatedGB, 1e-9)

	// ParentAttributions wired through to lotman: each child's attribution
	// equals its own dedicated quota (axiom 1 trivially satisfied).
	require.Contains(t, a.ParentAttributions, "root")
	require.Contains(t, b.ParentAttributions, aName)
	require.Contains(t, c.ParentAttributions, "root")
	assert.InDelta(t, 50.0, *a.ParentAttributions["root"].DedicatedGB, 1e-9)
	assert.InDelta(t, 25.0, *b.ParentAttributions[aName].DedicatedGB, 1e-9)
	assert.InDelta(t, 50.0, *c.ParentAttributions["root"].DedicatedGB, 1e-9)

	// Sentinel propagation (root.opportunistic = -1, root.max_num_objects = -1):
	// lotman PR #46 accepts -1 verbatim as "unbounded" for both MPAs and
	// parent attributions.
	require.NotNil(t, a.MPA.OpportunisticGB)
	assert.Equal(t, float64(-1), *a.MPA.OpportunisticGB)
	require.NotNil(t, a.MPA.MaxNumObjects)
	assert.Equal(t, int64(-1), a.MPA.MaxNumObjects.Value)
}
