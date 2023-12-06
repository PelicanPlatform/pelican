/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package nsregistry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
)

func topologyMockup(t *testing.T, namespaces []string) *httptest.Server {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var namespaceList []map[string]string
		for _, ns := range namespaces {
			namespaceList = append(namespaceList, map[string]string{"path": ns})
		}

		jsonData, err := json.Marshal(map[string][]map[string]string{"namespaces": namespaceList})
		if err != nil {
			t.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonData))
	}))

	return svr
}

func TestRegistryTopology(t *testing.T) {
	viper.Reset()

	topoNamespaces := []string{"/topo/foo", "/topo/bar"}
	svr := topologyMockup(t, topoNamespaces)
	defer svr.Close()

	registryDB := t.TempDir()
	viper.Set("Registry.DbLocation", filepath.Join(registryDB, "test.sqlite"))
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	config.InitConfig()

	err := InitializeDB()
	require.NoError(t, err)
	defer ShutdownDB()

	// Set value so that config.GetPreferredPrefix() returns "OSDF"
	config.SetPreferredPrefix("OSDF")

	//Test topology table population
	err = PopulateTopology()
	require.NoError(t, err)

	// Check that topology namespace exists
	exists, err := namespaceExists("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that topology namespace exists
	exists, err = namespaceExists("/topo/bar")
	require.NoError(t, err)
	require.True(t, exists)

	// Add a test namespace so we can test that checkExists still works
	ns := Namespace{
		ID:            0,
		Prefix:        "/regular/foo",
		Pubkey:        "",
		Identity:      "",
		AdminMetadata: "",
	}
	err = addNamespace(&ns)
	require.NoError(t, err)

	// Check that the regular namespace exists
	exists, err = namespaceExists("/regular/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that a bad namespace doesn't exist
	exists, err = namespaceExists("/bad/namespace")
	require.NoError(t, err)
	require.False(t, exists)

	// No kill the old topo server, and remove a namespace
	svr.Close()
	svr.CloseClientConnections()

	topoNamespaces = []string{"/topo/foo", "/topo/baz"}
	svr = topologyMockup(t, topoNamespaces)
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	defer svr.Close()

	// Re-populate topo
	//Test topology table population
	err = PopulateTopology()
	require.NoError(t, err)

	// Check that /topo/foo still exists
	exists, err = namespaceExists("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// And that /topo/baz was added
	exists, err = namespaceExists("/topo/baz")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that /topo/bar is gone
	exists, err = namespaceExists("/topo/bar")
	require.NoError(t, err)
	require.False(t, exists)

	// Finally, check that /regular/foo survived
	exists, err = namespaceExists("/regular/foo")
	require.NoError(t, err)
	require.True(t, exists)

	viper.Reset()
}
