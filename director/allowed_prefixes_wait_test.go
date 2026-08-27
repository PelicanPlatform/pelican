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

package director

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestWaitForAllowedPrefixesForCaches covers the wait that decides whether a
// cache advertisement is held or refused.
//
// Holding matters because a refused cache does not advertise again until its
// next cycle (Server.AdvertisementInterval, a minute by default) -- so the
// wait has to outlast a registry that is merely slow to come up, while still
// ending the moment the data arrives and the moment the caller gives up.
func TestWaitForAllowedPrefixesForCaches(t *testing.T) {
	// This timestamp is package-global and shared with the rest of the
	// director tests; put back whatever was there.
	original := allowedPrefixesForCachesLastSetTimestamp.Load()
	t.Cleanup(func() { allowedPrefixesForCachesLastSetTimestamp.Store(original) })

	t.Run("returns at once when already initialized", func(t *testing.T) {
		allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())

		start := time.Now()
		assert.True(t, waitForAllowedPrefixesForCaches(context.Background()))
		assert.Less(t, time.Since(start), 100*time.Millisecond,
			"an initialized director must not delay the ad at all")
	})

	t.Run("returns once the data arrives", func(t *testing.T) {
		allowedPrefixesForCachesLastSetTimestamp.Store(0)

		// Stand in for the registry becoming reachable partway through the
		// wait, which is the case the hold exists for.
		go func() {
			time.Sleep(250 * time.Millisecond)
			allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())
		}()

		start := time.Now()
		assert.True(t, waitForAllowedPrefixesForCaches(context.Background()),
			"the ad should be held until the prefixes land, then accepted")
		elapsed := time.Since(start)
		assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "it must actually have waited")
		assert.Less(t, elapsed, allowedPrefixesInitWait,
			"and returned when the data arrived rather than running out the bound")
	})

	t.Run("gives up when the caller does", func(t *testing.T) {
		allowedPrefixesForCachesLastSetTimestamp.Store(0)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		assert.False(t, waitForAllowedPrefixesForCaches(ctx),
			"a caller that has hung up must not hold a director goroutine")
		assert.Less(t, time.Since(start), allowedPrefixesInitWait,
			"cancellation must end the wait early, not run out the bound")
	})
}
