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
	"os"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/server_utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

//go:embed resources/lots-config.yaml

var yamlMockup string

func setupLotmanFromConf(t *testing.T, readConfig bool, name string) (bool, func()) {
	// Load in our config
	if readConfig {
		viper.Set("Federation.DiscoveryUrl", "https://fake-federation.com")
		viper.SetConfigType("yaml")
		err := viper.ReadConfig(strings.NewReader(yamlMockup))
		if err != nil {
			t.Fatalf("Error reading config: %v", err)
		}
	}

	tmpPathPattern := name + "*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	viper.Set("Lotman.DbLocation", tmpPath)
	success := InitLotman()
	//reset func
	return success, func() {
		server_utils.ResetTestState()
	}
}

// Test the library initializer. NOTE: this also tests CreateLot, which is a part of initialization.
func TestLotmanInit(t *testing.T) {
	server_utils.ResetTestState()

	t.Run("TestBadInit", func(t *testing.T) {
		// We haven't set various bits needed to create the lots, like discovery URL
		success, cleanup := setupLotmanFromConf(t, false, "LotmanBadInit")
		defer cleanup()
		require.False(t, success)
	})

	t.Run("TestGoodInit", func(t *testing.T) {
		viper.Set("Log.Level", "debug")
		viper.Set("Federation.DiscoveryUrl", "https://fake-federation.com")
		success, cleanup := setupLotmanFromConf(t, false, "LotmanGoodInit")
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
		require.Equal(t, "https://fake-federation.com", defaultLot.Owner)
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
		require.Equal(t, "https://fake-federation.com", rootLot.Owner)
		require.Equal(t, "root", rootLot.Parents[0])
		require.Equal(t, 0.0, *(rootLot.MPA.DedicatedGB))
		require.Equal(t, int64(0), (rootLot.MPA.MaxNumObjects.Value))
	})
}

func TestLotmanInitFromConfig(t *testing.T) {
	server_utils.ResetTestState()

	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf")
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
	require.Equal(t, "https://fake-federation.com", defaultLot.Owner)
	require.Equal(t, "default", defaultLot.Parents[0])
	require.Equal(t, 100.0, *(defaultLot.MPA.DedicatedGB))
	require.Equal(t, int64(1000), (defaultLot.MPA.MaxNumObjects.Value))

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
	require.Equal(t, "https://fake-federation.com", rootLot.Owner)
	require.Equal(t, "root", rootLot.Parents[0])
	require.Equal(t, 1.0, *(rootLot.MPA.DedicatedGB))
	require.Equal(t, int64(10), rootLot.MPA.MaxNumObjects.Value)
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
	success, cleanup := setupLotmanFromConf(t, true, "LotmanGetAuthzCalleres")
	defer cleanup()
	require.True(t, success)

	// Lotman is initialized, let's check that it has the information it should based on the config
	// test-2's authzed callers are the owners of root and test-1
	authzedCallers, err := GetAuthorizedCallers("test-2")
	require.NoError(t, err, "Failed to get authorized callers")
	require.Equal(t, 2, len(*authzedCallers))
	require.Contains(t, *authzedCallers, "https://fake-federation.com")
	require.Contains(t, *authzedCallers, "https://different-fake-federation.com")

	// test with a non-existent lot
	_, err = GetAuthorizedCallers("non-existent-lot")
	require.Error(t, err, "Expected error for non-existent lot")
}

func TestGetLot(t *testing.T) {
	server_utils.ResetTestState()
	success, cleanup := setupLotmanFromConf(t, true, "LotmanGetLot")
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
	require.Contains(t, lot.Owners, "https://fake-federation.com")
	require.Contains(t, lot.Owners, "https://different-fake-federation.com")
	require.Contains(t, lot.Owners, "https://another-fake-federation.com")
	require.Equal(t, 1.11, *(lot.MPA.DedicatedGB))
	require.Equal(t, int64(42), lot.MPA.MaxNumObjects.Value)
	require.Equal(t, "/test-1/test-2", lot.Paths[0].Path)
	require.True(t, lot.Paths[0].Recursive)
}

func TestUpdateLot(t *testing.T) {
	server_utils.ResetTestState()
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf")
	defer cleanup()
	require.True(t, success)

	// Update the test-1 lot
	dedGB := float64(999.0)
	lotUpdate := LotUpdate{
		LotName: "test-1",
		MPA: &MPA{
			DedicatedGB: &dedGB,
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

	err := UpdateLot(&lotUpdate, "https://fake-federation.com")
	require.NoError(t, err, "Failed to update lot")

	// Now check that the update was successful
	lot, err := GetLot("test-1", true)
	require.NoError(t, err, "Failed to get lot")
	require.Equal(t, "test-1", lot.LotName)
	require.Equal(t, dedGB, *(lot.MPA.DedicatedGB))
	require.Equal(t, int64(84), lot.MPA.MaxNumObjects.Value)
	require.Equal(t, "/test-1-updated", lot.Paths[0].Path)
	require.False(t, lot.Paths[0].Recursive)
}

func TestDeleteLotsRec(t *testing.T) {
	server_utils.ResetTestState()
	success, cleanup := setupLotmanFromConf(t, true, "LotmanInitConf")
	defer cleanup()
	require.True(t, success)

	// Delete test-1, then verify both it and test-2 are gone
	err := DeleteLotsRecursive("test-1", "https://fake-federation.com")
	require.NoError(t, err, "Failed to delete lot")

	// Now check that the delete was successful
	lot, err := GetLot("test-1", false)
	require.Error(t, err, "Expected error for non-existent lot")
	require.Nil(t, lot)

	lot, err = GetLot("test-2", false)
	require.Error(t, err, "Expected error for non-existent lot")
	require.Nil(t, lot)
}
