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

package htb

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTBCreation(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	assert.NotNil(t, h)
	stats := h.GetStats()
	assert.Equal(t, float64(1000), stats.ParentTokens)
	assert.Equal(t, 0, stats.NumChildren)
}

func TestHTBPanicsOnInvalidParams(t *testing.T) {
	assert.Panics(t, func() {
		New(0, 1000)
	})
	assert.Panics(t, func() {
		New(-1, 1000)
	})
	assert.Panics(t, func() {
		New(1000, 0)
	})
	assert.Panics(t, func() {
		New(1000, -1)
	})
}

func TestHTBSingleUserImmediate(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	// First request should succeed immediately
	tokens, err := h.Wait(ctx, "user1", 100)
	require.NoError(t, err)
	require.NotNil(t, tokens)

	stats := h.GetStats()
	assert.Equal(t, 1, stats.NumChildren)
	assert.Contains(t, stats.ChildrenStats, "user1")
}

func TestHTBTokensUse(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	tokens, err := h.Wait(ctx, "user1", 100)
	require.NoError(t, err)

	// Use 50 tokens
	unfulfilled := tokens.Use(50)
	assert.Equal(t, int64(0), unfulfilled)
	assert.Equal(t, int64(50), tokens.used)

	// Use another 40 tokens
	unfulfilled = tokens.Use(40)
	assert.Equal(t, int64(0), unfulfilled)
	assert.Equal(t, int64(90), tokens.used)

	// Try to use more than available
	unfulfilled = tokens.Use(20)
	assert.Equal(t, int64(10), unfulfilled)  // 10 tokens unfulfilled
	assert.Equal(t, int64(100), tokens.used) // All 100 used
}

func TestHTBTokensReturn(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	tokens, err := h.Wait(ctx, "user1", 100)
	require.NoError(t, err)

	// Use only 60 tokens
	tokens.Use(60)

	stats := h.GetStats()
	tokensBefore := stats.ChildrenStats["user1"].Tokens

	// Return unused tokens
	h.Return(tokens)

	stats = h.GetStats()
	tokensAfter := stats.ChildrenStats["user1"].Tokens

	// Should have returned 40 tokens
	assert.InDelta(t, 40, tokensAfter-tokensBefore, 1)
}

func TestHTBMultipleUsersCapacitySplit(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	// Add two users
	tokens1, err := h.Wait(ctx, "user1", 100)
	require.NoError(t, err)
	require.NotNil(t, tokens1)

	tokens2, err := h.Wait(ctx, "user2", 100)
	require.NoError(t, err)
	require.NotNil(t, tokens2)

	stats := h.GetStats()
	assert.Equal(t, 2, stats.NumChildren)

	// Each child should have capacity of 500 (1000 / 2)
	assert.Equal(t, int64(500), stats.ChildrenStats["user1"].Capacity)
	assert.Equal(t, int64(500), stats.ChildrenStats["user2"].Capacity)
}

func TestHTBOnDemandTicking(t *testing.T) {
	// Rate of 1000 tokens/sec = 100 tokens per 100ms tick
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	// User1 takes 400 tokens
	tokens, err := h.Wait(ctx, "user1", 400)
	require.NoError(t, err)
	tokens.Use(400)

	stats := h.GetStats()
	user1Before := stats.ChildrenStats["user1"].Tokens
	parentBefore := stats.ParentTokens
	combinedBefore := user1Before + parentBefore

	// Wait for more than two ticks
	time.Sleep(250 * time.Millisecond)

	// Trigger ticking by requesting tokens
	tokens2, err := h.Wait(ctx, "user1", 1)
	require.NoError(t, err)
	require.NotNil(t, tokens2)

	stats = h.GetStats()
	user1After := stats.ChildrenStats["user1"].Tokens
	parentAfter := stats.ParentTokens
	combinedAfter := user1After + parentAfter

	// Debug output
	t.Logf("Before: child=%.2f parent=%.2f combined=%.2f", user1Before, parentBefore, combinedBefore)
	t.Logf("After: child=%.2f parent=%.2f combined=%.2f", user1After, parentAfter, combinedAfter)

	// Should have gained approximately 200+ tokens total (2+ ticks worth)
	// Accounting for the 1 token taken in second request
	gained := (combinedAfter + 1) - combinedBefore
	t.Logf("Gained: %.2f", gained)
	assert.Greater(t, gained, float64(150))
}

func TestHTBBurstWithNegativeBalance(t *testing.T) {
	h := New(1000, 2000)
	defer h.Close()

	ctx := context.Background()

	// User requests more than available but within capacity
	tokens, err := h.Wait(ctx, "user1", 1500)
	require.NoError(t, err)
	require.NotNil(t, tokens)

	stats := h.GetStats()
	// Child may have gone negative
	assert.LessOrEqual(t, stats.ChildrenStats["user1"].Tokens, float64(2000))
}

func TestHTBStaleUserRemoval(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	// Use a short staleness timeout for testing
	h.stalenessTimeout = 200 * time.Millisecond

	ctx := context.Background()

	// Add a user
	tokens, err := h.Wait(ctx, "user1", 100)
	require.NoError(t, err)
	tokens.Use(100)

	stats := h.GetStats()
	assert.Equal(t, 1, stats.NumChildren)

	// Wait for staleness timeout + buffer
	time.Sleep(300 * time.Millisecond)

	// Trigger ticking with another user
	tokens2, err := h.Wait(ctx, "user2", 100)
	require.NoError(t, err)
	require.NotNil(t, tokens2)

	stats = h.GetStats()
	// user1 should have been removed
	assert.NotContains(t, stats.ChildrenStats, "user1")
	assert.Contains(t, stats.ChildrenStats, "user2")
}

func TestHTBWaitWithContext(t *testing.T) {
	// Create HTB with low capacity so we can quickly exhaust it
	h := New(10, 50) // 10 tokens/sec, 50 capacity
	defer h.Close()

	ctx := context.Background()

	// Take 50 tokens - this succeeds immediately
	tokens, err := h.Wait(ctx, "user1", 50)
	require.NoError(t, err)
	tokens.Use(50)
	h.Return(tokens)

	// Now bucket is empty (child=0, parent=0)
	// Try to get more tokens with a very short timeout
	// Timeout is much shorter than tick interval (100ms)
	ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	// This should timeout because:
	// 1. Bucket is empty (used 50 tokens, capacity 50)
	// 2. Rate is only 10/sec = 1 token per 100ms
	// 3. Context times out in 5ms, well before the next 100ms tick
	start := time.Now()
	_, err = h.Wait(ctx2, "user1", 10)
	elapsed := time.Since(start)
	t.Logf("Wait returned after %v with error: %v", elapsed, err)

	// Should timeout
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// Should have waited close to the timeout duration
	// Note: Windows has ~15.6ms timer resolution, so actual elapsed time can overshoot
	// the 5ms context deadline significantly. Use generous upper bound.
	assert.Greater(t, elapsed.Milliseconds(), int64(3), "Should have waited at least 3ms")
	assert.Less(t, elapsed.Milliseconds(), int64(50), "Should have timed out reasonably quickly")
}

func TestHTBTryTake(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	// First try should succeed
	tokens := h.TryTake("user1", 500)
	assert.NotNil(t, tokens)

	// Second try should succeed (can borrow from parent or burst)
	tokens2 := h.TryTake("user1", 400)
	assert.NotNil(t, tokens2)
}

func TestHTBConcurrentAccess(t *testing.T) {
	h := New(10000, 10000)
	defer h.Close()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Simulate concurrent access from multiple users
	users := []string{"user1", "user2", "user3", "user4", "user5"}
	for _, user := range users {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				tokens, err := h.Wait(ctx, u, 50)
				if err == nil && tokens != nil {
					tokens.Use(25)
					h.Return(tokens)
				}
			}(user)
		}
	}

	wg.Wait()

	stats := h.GetStats()
	// All users should exist or some may have been removed
	assert.GreaterOrEqual(t, stats.NumChildren, 1)
}

func TestHTBRequestExceedsCapacity(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	// Request more than total capacity
	_, err := h.Wait(ctx, "user1", 2000)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceed capacity")
}

func TestHTBZeroAndNegativeTokens(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	ctx := context.Background()

	// Zero tokens should succeed immediately
	tokens, err := h.Wait(ctx, "user1", 0)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)

	// TryTake with zero
	tokens2 := h.TryTake("user2", 0)
	assert.NotNil(t, tokens2)

	// Return nil (should be no-op)
	h.Return(nil)
}

func TestHTBReturnToNonexistentUser(t *testing.T) {
	h := New(1000, 1000)
	defer h.Close()

	// Use a short staleness timeout for testing
	h.stalenessTimeout = 200 * time.Millisecond

	ctx := context.Background()

	// Get tokens for user1
	tokens, err := h.Wait(ctx, "user1", 500)
	require.NoError(t, err)
	tokens.Use(250)

	// Wait for user1 to become stale and be removed
	time.Sleep(300 * time.Millisecond)

	// Trigger removal with another user
	_, _ = h.Wait(ctx, "user2", 100)

	stats := h.GetStats()
	parentBefore := stats.ParentTokens

	// Return tokens for user1 (now non-existent)
	h.Return(tokens)

	stats = h.GetStats()
	// Should have returned to parent
	assert.GreaterOrEqual(t, stats.ParentTokens, parentBefore)
}

func TestHTBBurstCapability(t *testing.T) {
	h := New(1000, 2000) // Capacity > rate to allow burst
	defer h.Close()

	ctx := context.Background()

	// User should be able to burst significantly
	tokens, err := h.Wait(ctx, "user1", 1800)
	require.NoError(t, err)
	require.NotNil(t, tokens)
}
