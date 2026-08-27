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

package local_cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// setThrottleParams applies a full set of fair-scheduler parameters.
// newCacheScheduler reads them once, so they all have to be in place first.
func setThrottleParams(t *testing.T, pendingBuffer int) {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_WorkerCount.Set(4))
	require.NoError(t, param.Cache_Throttle_PerOriginStarvingPercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PerOriginActivePercent.Set(90))
	require.NoError(t, param.Cache_Throttle_PendingBufferSize.Set(pendingBuffer))
	require.NoError(t, param.Cache_Throttle_PerOriginPendingSize.Set(8))
	require.NoError(t, param.Cache_Throttle_EMAWindow.Set(time.Second))
}

// TestCacheSchedulerDisabledByZeroPendingBuffer pins the escape hatch.
// Operators need a way to turn the fair scheduler off entirely -- to rule it
// out while diagnosing something, or because their cache fronts a single
// origin and admission control only adds latency. Setting
// Cache.Throttle.PendingBufferSize to 0 is that switch, and it has to leave
// the engine on the plain unscheduled path rather than merely widening the
// caps.
//
// Note that 0 means something different one layer down: on
// client.SchedulerConfig the same field name means "queue without a bound".
// The translation happens here, and getting it backwards would silently turn
// the operator's "off" into an unbounded queue.
func TestCacheSchedulerDisabledByZeroPendingBuffer(t *testing.T) {
	setThrottleParams(t, 0)

	workers, sched := newCacheScheduler(CacheModeServer)
	assert.Nil(t, sched, "PendingBufferSize=0 must leave the cache with no scheduler at all")
	assert.Equal(t, 4, workers, "the pool is still sized from Cache.WorkerCount")
}

// TestCacheSchedulerEnabledInServerMode is the other half of the switch: a
// cache server with a positive pending buffer gets a scheduler, sized from
// Cache.WorkerCount. (How the configured percentages become absolute slot
// counts is the scheduler's own contract, covered in the client package.)
func TestCacheSchedulerEnabledInServerMode(t *testing.T) {
	setThrottleParams(t, 16)

	workers, sched := newCacheScheduler(CacheModeServer)
	require.NotNil(t, sched, "a cache server must get a fair scheduler")
	assert.Equal(t, 4, workers, "the pool the scheduler shares is Cache.WorkerCount")
}

// TestCacheSchedulerConfigMapping pins which parameter feeds which scheduler
// setting.
//
// A scheduler handed the wrong knob still constructs and still looks perfectly
// healthy -- it just enforces the wrong limit -- so nothing downstream would
// notice. Transposing the starving and active percentages, for instance, would
// silently invert the two caps. Every value here is distinct so a swapped pair
// cannot go unnoticed.
func TestCacheSchedulerConfigMapping(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_WorkerCount.Set(64))
	require.NoError(t, param.Cache_Throttle_PerOriginStarvingPercent.Set(11))
	require.NoError(t, param.Cache_Throttle_PerOriginActivePercent.Set(22))
	require.NoError(t, param.Cache_Throttle_PendingBufferSize.Set(33))
	require.NoError(t, param.Cache_Throttle_PerOriginPendingSize.Set(44))
	require.NoError(t, param.Cache_Throttle_EMAWindow.Set(55*time.Second))

	workers, cfg := cacheSchedulerConfig(CacheModeServer)
	assert.Equal(t, 64, workers, "Cache.WorkerCount")
	assert.Equal(t, 11, cfg.PerTagStarvingPercent, "Cache.Throttle.PerOriginStarvingPercent")
	assert.Equal(t, 22, cfg.PerTagActivePercent, "Cache.Throttle.PerOriginActivePercent")
	assert.Equal(t, 33, cfg.PendingBufferSize, "Cache.Throttle.PendingBufferSize")
	assert.Equal(t, 44, cfg.PerTagPendingSize, "Cache.Throttle.PerOriginPendingSize")
	assert.Equal(t, 55*time.Second, cfg.EMAWindow, "Cache.Throttle.EMAWindow")
}

// TestCacheSchedulerWorkerCountFallback pins that an unset or nonsensical
// Cache.WorkerCount does not produce a zero-worker pool, which would deadlock
// every transfer rather than merely running them slowly.
func TestCacheSchedulerWorkerCountFallback(t *testing.T) {
	for _, configured := range []int{0, -1} {
		setThrottleParams(t, 16)
		require.NoError(t, param.Cache_WorkerCount.Set(configured))

		workers, sched := newCacheScheduler(CacheModeServer)
		assert.Positive(t, workers, "worker count %d must fall back to a usable default", configured)
		require.NotNil(t, sched)
	}
}

// TestCacheSchedulerNotWiredOutsideServerMode pins that the local
// (client-side) cache is left alone. It serves one process rather than many
// tenants, so per-origin admission control would only get in the way of the
// very transfers it exists to make fast. A zero worker count tells the engine
// to keep its own client-side default.
func TestCacheSchedulerNotWiredOutsideServerMode(t *testing.T) {
	// Generous throttle settings: the mode, not the configuration, is what
	// decides whether a scheduler is wired in.
	setThrottleParams(t, 64)

	workers, sched := newCacheScheduler(CacheModeLocal)
	assert.Nil(t, sched, "the local cache runs without a fair scheduler")
	assert.Zero(t, workers, "the local cache keeps the client-side worker default")
}
