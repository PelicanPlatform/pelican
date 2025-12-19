//go:build !windows

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

package fed_tests

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestCacheStatsE2E(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Shorten the interval for the test to make it faster
	oldInterval := metrics.XrdCurlStatsInterval
	metrics.XrdCurlStatsInterval = 500 * time.Millisecond
	defer func() {
		metrics.XrdCurlStatsInterval = oldInterval
	}()

	// Set up a federation with a public export
	originConfig := `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test-namespace
      Capabilities: ["PublicReads", "Reads", "Writes", "DirectReads", "Listings"]
`
	fed := fed_test_utils.NewFedTest(t, originConfig)

	// Prepare data on Origin
	storageDir := fed.Exports[0].StoragePrefix
	testFile := "test-file.txt"
	content := []byte("hello world")
	err := os.WriteFile(filepath.Join(storageDir, testFile), content, 0644)
	require.NoError(t, err)

	// Determine stats file location
	cacheRunDir := param.Cache_RunLocation.GetString()
	statsFile := filepath.Join(cacheRunDir, "xrootd.stats")

	// Transfer file through Cache
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	pelicanUrl := fmt.Sprintf("pelican://%s%s/%s", discoveryUrl.Host, fed.Exports[0].FederationPrefix, testFile)

	// Download to a temp file
	destFile := filepath.Join(t.TempDir(), "downloaded.txt")

	// Perform transfer. This will trigger the xrdcl-curl plugin in the cache
	// to talk to the origin.
	_, err = client.DoCopy(fed.Ctx, pelicanUrl, destFile, false)
	require.NoError(t, err)

	// Verify the downloaded content
	downloadedContent, err := os.ReadFile(destFile)
	require.NoError(t, err)
	assert.Equal(t, content, downloadedContent)

	// 1. Wait for stats file to appear on disk.
	assert.Eventually(t, func() bool {
		_, err := os.Stat(statsFile)
		return err == nil
	}, 20*time.Second, 1*time.Second, "Stats file was never created by XRootD plugin")

	// 2. Verify metrics are updated in Pelican.
	assert.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.XrdclQueueConsumed) > 0
	}, 10*time.Second, 500*time.Millisecond, "Metrics were never updated by Pelican monitoring")

	t.Logf("Successfully verified that monitoring picked up stats from %s", statsFile)
}
