//go:build lotman && linux && !ppc64le

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

package lotman

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
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

// Initialize Lotman
// If we read from the embedded yaml, we need to override the SHOULD_OVERRIDE keys with the discUrl
// so that underlying metadata discovery can happen against the mock discovery host
func setupLotmanFromConf(t *testing.T, readConfig bool, name string, discUrl string, nsAds []server_structs.NamespaceAdV2) (bool, func()) {
	// Load in our config and handle overriding the SHOULD_OVERRIDE keys with the discUrl
	// Load in our config
	viper.Set("Cache.HighWaterMark", "100g")
	viper.Set("Cache.LowWaterMark", "50g")
	viper.Set("Debug", true)
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
		viper.Set("Lotman.PolicyDefinitions", policies)
	} else {
		// If we're not reading from the embedded yaml, grab the
		// default configuration. We need _some_ configuration to work.
		viper.Set("ConfigDir", t.TempDir())
		config.InitConfig()
	}

	tmpPathPattern := name + "*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	viper.Set("Lotman.DbLocation", tmpPath)
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
			w.Write([]byte(response))
		} else {
			http.NotFound(w, r)
		}
	}))
}

// Test the library initializer. NOTE: this also tests CreateLot, which is a part of initialization.
func TestLotmanInit(t *testing.T) {
	server_utils.ResetTestState()

	t.Run("TestBadInit", func(t *testing.T) {
		// We haven't set various bits needed to create the lots, like discovery URL
		success, cleanup := setupLotmanFromConf(t, false, "LotmanBadInit", "", nil)
		defer cleanup()
		require.False(t, success)
	})

	t.Run("TestGoodInit", func(t *testing.T) {
		viper.Set("Log.Level", "debug")
		server := getMockDiscoveryHost()
		// Set the Federation.DiscoveryUrl to the test server's URL
		// Lotman uses the discovered URLs/keys to determine some aspects of lot ownership
		viper.Set("Federation.DiscoveryUrl", server.URL)

		success, cleanup := setupLotmanFromConf(t, false, "LotmanGoodInit", server.URL, nil)
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
		require.Equal(t, 0.0, *(defaultLot.MPA.DedicatedGB))
		require.Equal(t, int64(0), (defaultLot.MPA.MaxNumObjects.Value))

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
		require.Equal(t, 0.0, *(rootLot.MPA.DedicatedGB))
		require.Equal(t, int64(0), (rootLot.MPA.MaxNumObjects.Value))
	})
}

func TestLotmanInitFromConfig(t *testing.T) {
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	viper.Set("Federation.DiscoveryUrl", server.URL)
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
	require.Equal(t, "/test-1", test1Lot.Paths[0].Path)
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
	require.Equal(t, "/test-1/test-2", test2Lot.Paths[0].Path)
	require.True(t, test2Lot.Paths[0].Recursive)
}

func TestGetLotmanLib(t *testing.T) {
	libLoc := getLotmanLib()
	require.Equal(t, "/usr/lib64/libLotMan.so", libLoc)

	// Now try to fool it and see that we get the same value back. We can detect this by
	// capturing the log output
	logOutput := &(bytes.Buffer{})
	log.SetOutput(logOutput)
	log.SetLevel(log.DebugLevel)
	viper.Set("Lotman.LibLocation", "/not/a/pathlibLotMan.so")
	libLoc = getLotmanLib()
	require.Equal(t, "/usr/lib64/libLotMan.so", libLoc)
	require.Contains(t, logOutput.String(), "libLotMan.so not found in configured path, attempting to find using known fallbacks")
}

func TestGetAuthzCallers(t *testing.T) {
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	viper.Set("Federation.DiscoveryUrl", server.URL)
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
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	viper.Set("Federation.DiscoveryUrl", server.URL)
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
	require.Equal(t, "/test-1/test-2", lot.Paths[0].Path)
	require.True(t, lot.Paths[0].Recursive)
}

func TestUpdateLot(t *testing.T) {
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	viper.Set("Federation.DiscoveryUrl", server.URL)
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf", server.URL, nil)
	defer cleanup()
	require.True(t, success)

	// Update the test-1 lot
	dedicatedGB := float64(999.0)
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
	require.Equal(t, "/test-1-updated", lot.Paths[0].Path)
	require.False(t, lot.Paths[0].Recursive)
}

func TestDeleteLotsRec(t *testing.T) {
	server_utils.ResetTestState()
	server := getMockDiscoveryHost()
	viper.Set("Federation.DiscoveryUrl", server.URL)
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
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name       string
		yamlConfig string
		expectErr  bool
		expectedPolicies []string
	}{
		{
			name:       "ValidConfig",
			yamlConfig: yamlMockup,
			expectErr:  false,
			expectedPolicies: []string{"different-policy", "another policy"},
		},
		{
			name:       "InvalidConfig",
			yamlConfig: badYamlMockup,
			expectErr:  true,
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

			policyMap, err := getPolicyMap()
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
			viper.Set("Cache.HighWaterMark", tc.hwm)
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
			Watermark:     "100k",
			Expected:      uint64(100000), // 100KB
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
			Watermark:     "50",
			Expected:      uint64(500000000000), // 500GB
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

// If so configured, we'll divide unallocated space between lot's dedicated GB and
// opportunistict GB values. This test ensures the calculations are correct and that
// hardcoded configuration isn't modified.
// I don't test for errors here because the internal functions capable of generating
// errors are tested elsewhere (e.g. convertWatermarkToBytes)
func TestDivideRemainingSpace(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	dedGB := float64(10.0)
	oppGB := float64(1.5)

	createLotMap := func() map[string]Lot {
        return map[string]Lot{
            "lot1": {
                LotName: "lot1",
                MPA: &MPA{
                    DedicatedGB:     &dedGB,
                    OpportunisticGB: &oppGB,
                },
            },
            "lot2": {
                LotName: "lot2",
                MPA:     &MPA{},
            },
            "lot3": {
                LotName: "lot3",
                MPA: &MPA{
                    DedicatedGB: &dedGB,
                },
            },
            "lot4": {
                LotName: "lot4",
                MPA: &MPA{
                    OpportunisticGB: &oppGB, // hardcoded values should be respected
                },
            },
        }
    }

	lotMap := createLotMap()
	totalDiskSpaceB := uint64(30000000000) // 30GB
	viper.Set("Cache.HighWaterMark", "25g")
	err := divideRemainingSpace(&lotMap, totalDiskSpaceB)
	require.NoError(t, err)
	// dedGB divisions should sum to HWM
	require.Equal(t, 10.0, *lotMap["lot1"].MPA.DedicatedGB)
	require.Equal(t, 2.5, *lotMap["lot2"].MPA.DedicatedGB)
	require.Equal(t, 10.0, *lotMap["lot3"].MPA.DedicatedGB)
	require.Equal(t, 2.5, *lotMap["lot4"].MPA.DedicatedGB)
	// oppGB should be HWM - dedGB unless hardcoded
	require.Equal(t, 1.5, *lotMap["lot1"].MPA.OpportunisticGB)
	require.Equal(t, 22.5, *lotMap["lot2"].MPA.OpportunisticGB)
	require.Equal(t, 15.0, *lotMap["lot3"].MPA.OpportunisticGB)
	require.Equal(t, 1.5, *lotMap["lot4"].MPA.OpportunisticGB)

	// Now make sure we this allocation fails if sum of dedGB is lower than HWM
	viper.Set("Cache.HighWaterMark", "1g")
	lotMap = createLotMap()
	err = divideRemainingSpace(&lotMap, totalDiskSpaceB)
	require.Error(t, err)
}

// Pretty straightforward -- tests should make sure we can grab viper config and use it when
// setting lot timestamps if they're not pre-configured.
func TestConfigLotTimestamps(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	now := time.Now().UnixMilli()
	viper.Set("Lotman.DefaultLotExpirationLifetime", "24h")
	viper.Set("Lotman.DefaultLotDeletionLifetime", "48h")

	defaultExpiration := now + 24*60*60*1000 // 24 hours in milliseconds
	defaultDeletion := now + 48*60*60*1000   // 48 hours in milliseconds

	// Helper function to create a lot with optional timestamps
	createLot := func(creationTime, expirationTime, deletionTime *Int64FromFloat) Lot {
		return Lot{
			MPA: &MPA{
				CreationTime:   creationTime,
				ExpirationTime: expirationTime,
				DeletionTime:   deletionTime,
			},
		}
	}

	// Define the test cases
	testCases := []struct {
		name           string
		lotMap         map[string]Lot
		expectedLotMap map[string]Lot
	}{
		{
			name: "Lots with missing timestamps",
			lotMap: map[string]Lot{
				"lot1": createLot(nil, nil, nil),
				"lot2": createLot(&Int64FromFloat{Value: 0}, &Int64FromFloat{Value: 0}, &Int64FromFloat{Value: 0}),
			},
			expectedLotMap: map[string]Lot{
				"lot1": createLot(&Int64FromFloat{Value: now}, &Int64FromFloat{Value: defaultExpiration}, &Int64FromFloat{Value: defaultDeletion}),
				"lot2": createLot(&Int64FromFloat{Value: now}, &Int64FromFloat{Value: defaultExpiration}, &Int64FromFloat{Value: defaultDeletion}),
			},
		},
		{
			name: "Lots with existing timestamps",
			lotMap: map[string]Lot{
				"lot1": createLot(&Int64FromFloat{Value: 1000}, &Int64FromFloat{Value: 2000}, &Int64FromFloat{Value: 3000}),
			},
			expectedLotMap: map[string]Lot{
				"lot1": createLot(&Int64FromFloat{Value: 1000}, &Int64FromFloat{Value: 2000}, &Int64FromFloat{Value: 3000}),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configLotTimestamps(&tc.lotMap)
			assert.Equal(t, tc.expectedLotMap, tc.lotMap)
		})
	}
}

func TestConfigLotsFromFedPrefixes(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	issuer1Str := "https://issuer1.com"
	issuer1, _ := url.Parse(issuer1Str)
	issuer2Str := "https://issuer2.com"
	issuer2, _ := url.Parse(issuer2Str)
	testCases := []struct {
		name                string
		nsAds               []server_structs.NamespaceAdV2
		federationIssuer    string
		directorUrl 	    string
		expectedLotMap      map[string]Lot
		expectedError       string
	}{
		{
			name: "Valid namespaces",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/namespace1",
					Issuer: []server_structs.TokenIssuer{
						{IssuerUrl: *issuer1},
					},
				},
				{
					Path: "/namespace2",
					Issuer: []server_structs.TokenIssuer{
						{IssuerUrl: *issuer2},
					},
				},
			},
			federationIssuer: "https://dne-discovery.com",
			directorUrl: "https://dne-director.com",
			expectedLotMap: map[string]Lot{
				"/namespace1": {
					LotName: "/namespace1",
					Owner:   issuer1Str,
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/namespace1",
							Recursive: true,
						},
					},
				},
				"/namespace2": {
					LotName: "/namespace2",
					Owner:   issuer2Str,
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/namespace2",
							Recursive: true,
						},
					},
				},
			},
			expectedError: "",
		},
		{
			name: "Skip monitoring namespaces",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/pelican/monitoring/namespace1",
					Issuer: []server_structs.TokenIssuer{
						{IssuerUrl: *issuer1},
					},
				},
				{
					Path: "/namespace2",
					Issuer: []server_structs.TokenIssuer{
						{IssuerUrl: *issuer2},
					},
				},
			},
			federationIssuer: "https://dne-discovery.com",
			directorUrl: "https://dne-director.com",
			expectedLotMap: map[string]Lot{
				"/namespace2": {
					LotName: "/namespace2",
					Owner:   issuer2Str,
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/namespace2",
							Recursive: true,
						},
					},
				},
			},
			expectedError: "",
		},
		{
			name: "Fallback to Director URL as issuer",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/namespace1",
				},
			},
			federationIssuer: "",
			directorUrl: "https://dne-director.com",
			expectedLotMap: map[string]Lot{
				"/namespace1": {
					LotName: "/namespace1",
					Owner:   "https://dne-director.com",
					Parents: []string{"root"},
					Paths: []LotPath{
						{
							Path:      "/namespace1",
							Recursive: true,
						},
					},
				},
			},
			expectedError: "",
		},
		{
			name: "Unresolvable issuer triggers error",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/namespace1",
				},
			},
			federationIssuer: "",
			directorUrl: "",
			expectedLotMap: map[string]Lot{},
			expectedError: "The detected federation issuer, which is needed by Lotman to determine lot/namespace ownership, is empty",
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetFederationForTest()
			fed := pelican_url.FederationDiscovery{
				// Most of these aren't actually used by the test, but to prevent auto discovery
				// and needing to spin up a separate mock discovery server, set them all.
				DiscoveryEndpoint: tc.federationIssuer,
				DirectorEndpoint:  tc.directorUrl,
				RegistryEndpoint: "https://dne-registry.com",
				JwksUri:     "https://dne-jwks.com",
				BrokerEndpoint:   "https://dne-broker.com",
			}
			config.SetFederation(fed)

			lotMap, err := configLotsFromFedPrefixes(tc.nsAds)
			if tc.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			}
			assert.Equal(t, tc.expectedLotMap, lotMap)
		})
	}
}
