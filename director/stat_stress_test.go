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

package director_test

import (
	_ "embed"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/director-public.yaml
	directorPublicCfg string
)

// A stress test for the director's memory cache
//
// Try to download as many non-existent objects as possible within a limited timeframe.
// The goal is to generate significant load on the "statUtils" cache within the director
// and related code to see if we can generate memory leaks / hoarding.
func TestStatMemory(t *testing.T) {
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, directorPublicCfg)
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	assert.NoError(t, err)

	grp, _ := errgroup.WithContext(fed.Ctx)
	grp.SetLimit(10)
	idx := 0
	start := time.Now()
	dest := filepath.Join(t.TempDir(), "dest.txt")

	for time.Since(start) < (time.Second) {
		downloadURL := fmt.Sprintf("pelican://%s%s/stress/%v.txt", discoveryUrl.Host, fed.Exports[0].FederationPrefix, idx)
		grp.Go(func() error {
			_, err := client.DoGet(fed.Ctx, downloadURL, dest, false)
			assert.Error(t, err)
			return nil
		})
		idx += 1
	}
	assert.NoError(t, grp.Wait())
	origIdx := idx

	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	goCnt := runtime.NumGoroutine()

	for time.Since(start) < 10*time.Second {
		downloadURL := fmt.Sprintf("pelican://%s%s/stress/%v.txt", discoveryUrl.Host, fed.Exports[0].FederationPrefix, idx)
		grp.Go(func() error {
			_, err := client.DoGet(fed.Ctx, downloadURL, dest, false)
			assert.Error(t, err)
			return nil
		})
		idx += 1
	}
	assert.NoError(t, grp.Wait())

	runtime.GC()
	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)
	afterGoCnt := runtime.NumGoroutine()

	log.Infoln("Total number of queries processed:", idx, " increase after warm-up:", idx-origIdx)
	log.Infoln("Heap alloc after warm-up:", stats.HeapAlloc)
	log.Infoln("Heap alloc after test:", afterStats.HeapAlloc)
	log.Infoln("Increase in heap size:", int64(afterStats.HeapAlloc)-int64(stats.HeapAlloc))
	log.Infoln("Go routine count after warm-up:", goCnt)
	log.Infoln("Go routine count after test:", afterGoCnt)

	assert.Less(t, afterStats.HeapAlloc, stats.HeapAlloc+7e5)
	assert.Less(t, afterGoCnt, goCnt+10)
}
