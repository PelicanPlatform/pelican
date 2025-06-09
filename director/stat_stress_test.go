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
	"context"
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/director-public.yaml
	directorPublicCfg string
)

// splitStackTraces splits the output of runtime.Stack(true) into individual goroutine stack traces.
func splitStackTraces(stackTrace string) []string {
	// Goroutine blocks are typically separated by a double newline.
	// The first block doesn't have a preceding double newline, but splitting by \n\n
	// handles the separation between subsequent goroutines correctly.
	// We might get an empty string at the end if the input ends with \n\n.
	parts := strings.Split(stackTrace, "\n\n")
	var result []string
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			result = append(result, part)
		}
	}
	return result
}

// splitStackLines splits a single goroutine stack trace block into lines.
func splitStackLines(stack string) []string {
	return strings.Split(stack, "\n")
}

// We have little control on how many goroutines the HTTP package starts up.
// This counts all stacks in the runtime *not* related to HTTP.  The intent
// is to have a more stable overall test by ignoring these transient stacks.
func countInterestingStacks() int {
	buf := make([]byte, 1024*1024)
	n := runtime.Stack(buf, true)

	interestingGoroutines := 0
	stackTraces := string(buf[:n])
	goroutineStacks := splitStackTraces(stackTraces)

	for _, stack := range goroutineStacks {
		lines := splitStackLines(stack)
		if len(lines) == 0 {
			continue
		}
		// The second line typically contains the function and file/line info
		fileLineInfo := lines[len(lines)-1]
		// Extract the file path part
		parts := strings.Fields(fileLineInfo)
		if len(parts) > 1 {
			filePathParts := strings.Split(parts[0], ":")
			if len(filePathParts) > 0 {
				filePath := filePathParts[0]
				if !strings.HasSuffix(filePath, "net/http/server.go") && !strings.HasSuffix(filePath, "net/http/transport.go") && !strings.HasSuffix(filePath, "net/http/h2_bundle.go") {
					interestingGoroutines++
				}
			}
		}
	}
	return interestingGoroutines
}

// A stress test for the director's memory cache
//
// Try to download as many non-existent objects as possible within a limited timeframe.
// The goal is to generate significant load on the "statUtils" cache within the director
// and related code to see if we can generate memory leaks / hoarding.
func TestStatMemory(t *testing.T) {
	server_utils.ResetTestState()

	viper.Set(param.Xrootd_EnableLocalMonitoring.GetName(), false)
	viper.Set(param.Server_AdLifetime.GetName(), "500ms")
	viper.Set(param.Cache_SelfTest.GetName(), false)
	viper.Set(param.Origin_DirectorTest.GetName(), false)
	viper.Set(param.Origin_SelfTest.GetName(), false)
	// Shutdown various TCP connections aggressively; after the test is done,
	// a modest sleep will reduce the "noise" goroutines
	viper.Set(param.Transport_DialerKeepAlive.GetName(), "50ms")
	viper.Set(param.Transport_IdleConnTimeout.GetName(), "50ms")
	viper.Set(param.Director_CachePresenceCapacity.GetName(), 500)
	fed := fed_test_utils.NewFedTest(t, directorPublicCfg)
	config.DisableLoggingCensor()
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	assert.NoError(t, err)

	require.NoError(t, config.InitClient())

	grp, _ := errgroup.WithContext(fed.Ctx)
	grp.SetLimit(10)
	idx := 0
	start := time.Now()
	cacheSize := param.Director_CachePresenceCapacity.GetInt()

	require.NoError(t, os.Mkdir(filepath.Join(fed.Exports[0].StoragePrefix, "stress"), os.FileMode(0700)))

	// Fill the cache before taking the baseline measurement. Otherwise,
	// it might end up that increased memory usage is due to filling up the
	// cache and not an actual memory leak.
	isCanceled := false
	for idx < cacheSize {
		downloadURL := fmt.Sprintf("pelican://%s%s/stress/%v.txt", discoveryUrl.Host, fed.Exports[0].FederationPrefix, idx)
		destName := filepath.Join(t.TempDir(), fmt.Sprintf("dest.%v.txt", idx))
		src := filepath.Join(fed.Exports[0].StoragePrefix, fmt.Sprintf("stress/%v.txt", idx))
		fmt.Println(src)
		require.NoError(t, os.WriteFile(src, []byte("foo"), os.FileMode(0600)))
		grp.Go(func() error {
			_, err := client.DoGet(fed.Ctx, downloadURL, destName, false)
			if errors.Is(err, context.Canceled) {
				isCanceled = true
			}
			assert.NoError(t, err)
			return nil
		})
		idx += 1
		require.False(t, isCanceled)
	}
	assert.NoError(t, grp.Wait())
	origIdx := idx
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	f, err := os.Create("baseline-heap.prof")
	require.NoError(t, err)
	defer f.Close()
	err = pprof.WriteHeapProfile(f)
	require.NoError(t, err)
	goCnt := countInterestingStacks()

	// Now, do enough work to fully evict and replace the cache's
	// contents from the "warm up" stage. If we're on an unusually
	// fast host, keep going until "enough" time has elapsed.
	for idx < 2*cacheSize || time.Since(start) < 10*time.Second {
		downloadURL := fmt.Sprintf("pelican://%s%s/stress/%v.txt", discoveryUrl.Host, fed.Exports[0].FederationPrefix, idx)
		destName := filepath.Join(t.TempDir(), fmt.Sprintf("dest.%v.txt", idx))
		src := filepath.Join(fed.Exports[0].StoragePrefix, fmt.Sprintf("stress/%v.txt", idx))
		fmt.Println(src)
		require.NoError(t, os.WriteFile(src, []byte("foo"), os.FileMode(0600)))
		grp.Go(func() error {
			fmt.Println("Launched download URL", downloadURL, err)
			_, err := client.DoGet(fed.Ctx, downloadURL, destName, false)
			if errors.Is(err, context.Canceled) {
				isCanceled = true
			}
			assert.NoError(t, err)
			return nil
		})
		require.False(t, isCanceled)
		idx += 1
	}
	// Cancel advertising to quiesce the services; otherwise, we advertise aggressively to the registry.
	fed.AdvertiseCancel()
	assert.NoError(t, grp.Wait())

	log.Info("Test has wrapped up; will run GC")
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	runtime.GC()
	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)
	f, err = os.Create("aftertest-heap.prof")
	require.NoError(t, err)
	defer f.Close()
	err = pprof.WriteHeapProfile(f)
	require.NoError(t, err)

	afterGoCnt := countInterestingStacks()

	log.Infoln("Total number of queries processed:", idx, " increase after warm-up:", idx-origIdx)
	log.Infoln("Heap alloc after warm-up:", stats.HeapAlloc)
	log.Infoln("Heap alloc after test:", afterStats.HeapAlloc)
	log.Infoln("Increase in heap size:", int64(afterStats.HeapAlloc)-int64(stats.HeapAlloc))
	log.Infoln("Go routine count after warm-up:", goCnt)
	log.Infoln("Go routine count after test:", afterGoCnt)

	assert.Less(t, afterStats.HeapAlloc, stats.HeapAlloc+5e5)
	assert.Less(t, afterGoCnt, goCnt+20)
}
