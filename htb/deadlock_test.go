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

	"github.com/stretchr/testify/require"
)

// TestHighConcurrencyNoDeadlock tests that high concurrency doesn't cause deadlock
// This test specifically addresses the issue where C16 was deadlocking
func TestHighConcurrencyNoDeadlock(t *testing.T) {
	h := New(1000*1000*1000, 1000*1000*1000) // 1 second capacity (large enough for test)

	numWorkers := 20
	opsPerWorker := 50

	done := make(chan bool, numWorkers)
	start := make(chan struct{})

	// Launch workers
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			userID := "user" + string(rune('A'+workerID))
			<-start // Wait for signal to start

			for j := 0; j < opsPerWorker; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

				// Request small amount of tokens (1ms each)
				tokens, err := h.Wait(ctx, userID, 1*1000*1000) // 1ms
				if err != nil {
					t.Errorf("Worker %d op %d: %v", workerID, j, err)
					cancel()
					done <- false
					return
				}

				// Simulate very brief work (in-memory operation)
				// Don't actually sleep to keep test fast

				// Return tokens immediately
				tokens.Use(500 * 1000) // Use half (0.5ms)
				h.Return(tokens)       // Return 0.5ms

				cancel()
			}

			done <- true
		}(i)
	}

	// Start all workers simultaneously
	close(start)

	// Wait for all workers with timeout
	timeout := time.After(30 * time.Second)
	for i := 0; i < numWorkers; i++ {
		select {
		case success := <-done:
			if !success {
				t.Fatal("Worker failed")
			}
		case <-timeout:
			t.Fatal("Deadlock detected: test timed out waiting for workers")
		}
	}
}

// TestWaiterWakeupOnReturn verifies that returning tokens wakes up waiters.
// Strategy: Same user makes two requests. First bursts into negative, second blocks.
func TestWaiterWakeupOnReturn(t *testing.T) {
	h := New(10*1000*1000, 10*1000*1000) // 10ms capacity

	ctx := context.Background()

	// user1's first two requests: exhaust the bucket completely
	tokens1, err := h.Wait(ctx, "user1", 10*1000*1000)
	require.NoError(t, err)

	// Take another burst immediately to force negative balance
	// With only one user, child.capacity = 10ms, but we can burst if potentialTokens >= capacity
	// After first request: child=0, parent=0. For burst to work on 10ms request:
	// potentialTokens = 0 + 0 = 0, NOT >= 10, so this should force actual debt
	tokens2, err := h.Wait(ctx, "user1", 10*1000*1000)
	require.NoError(t, err)
	// Now user1 should be at -10ms

	// Now a third request from user1 should definitely block
	blocked := make(chan bool, 1)
	waitDone := make(chan bool, 1)

	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		blocked <- true

		// This should block - user1's bucket is deeply negative
		tokens3, err := h.Wait(ctx2, "user1", 3*1000*1000)
		if err != nil {
			t.Error("Wait failed:", err)
			waitDone <- false
			return
		}
		tokens3.Use(3 * 1000 * 1000)
		h.Return(tokens3)
		waitDone <- true
	}()

	// Wait for goroutine to start waiting
	<-blocked
	time.Sleep(10 * time.Millisecond)

	// Verify waiter is still blocked
	select {
	case <-waitDone:
		t.Fatal("Waiter completed before Return() - should be blocked waiting for tokens")
	default:
		// Good, still blocked
	}

	// Return tokens from first request - this should wake up the waiter
	tokens1.Use(0)
	h.Return(tokens1)

	// Also return second request
	tokens2.Use(0)
	h.Return(tokens2)

	// Waiter should wake up quickly (well before 100ms tick)
	select {
	case success := <-waitDone:
		require.True(t, success, "Waiter failed after Return()")
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Waiter was not woken up by Return() within 50ms")
	}
}

// TestDeepNegativeDeadlock reproduces a deadlock bug when going deeply negative with multiple users.
func TestDeepNegativeDeadlock(t *testing.T) {
	h := New(30*1000*1000, 30*1000*1000) // 30ms capacity

	ctx := context.Background()

	// Pre-create waiter users
	numWaiters := 3
	for i := 0; i < numWaiters; i++ {
		userID := "waiter" + string(rune('A'+i))
		tokens, _ := h.Wait(ctx, userID, 1)
		tokens.Use(1)
	}
	t.Logf("Created %d waiters (waiterA, waiterB, waiterC)", numWaiters)
	t.Logf("Now we have 4 users total: user1 + 3 waiters, each gets 7.5ms fair share")

	// Exhaust capacity deeply with user1
	var heldTokens []*Tokens
	for i := 0; i < 8; i++ {
		tokens, err := h.Wait(ctx, "user1", 6*1000*1000)
		require.NoError(t, err)
		heldTokens = append(heldTokens, tokens)
	}
	t.Logf("user1 took 48ms from 30ms capacity - system at -18ms")
	t.Logf("user1 child bucket is deeply negative, parent is deeply negative")

	// Launch waiters that should block
	waiters := make([]chan bool, numWaiters)
	blocked := make(chan bool, numWaiters)

	for i := 0; i < numWaiters; i++ {
		waiters[i] = make(chan bool, 1)
		go func(id int, done chan bool) {
			// Generous timeout - should wake via Return processing waiters
			ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			userID := "waiter" + string(rune('A'+id))
			t.Logf("Waiter %s starting Wait(5ms)...", userID)
			blocked <- true

			tokens, err := h.Wait(ctx2, userID, 5*1000*1000) // 5ms each
			if err != nil {
				t.Logf("Waiter %s failed: %v", userID, err)
				done <- false
				return
			}
			t.Logf("Waiter %s succeeded!", userID)
			h.Return(tokens)
			done <- true
		}(i, waiters[i])
	}

	// Wait for all waiters to start
	for i := 0; i < numWaiters; i++ {
		<-blocked
	}
	t.Log("All waiters started, sleeping to ensure they're queued...")
	time.Sleep(20 * time.Millisecond)

	// Return all the tokens
	t.Log("Returning all 48ms of held tokens...")
	t.Log("When user1 returns tokens, user1's child will hit its 7.5ms cap")
	t.Log("Excess should overflow to parent, making ~40ms available in parent")
	for idx, tokens := range heldTokens {
		tokens.Use(0)
		h.Return(tokens)
		t.Logf("Returned tokens %d/8", idx+1)
	}
	t.Log("All returns complete - parent should have plenty of tokens")
	t.Log("processAllWaiters() should have been called by Return()")

	// Now wait for waiters
	t.Log("Waiting for waiters to complete (up to 2 seconds)...")
	timeout := time.After(2 * time.Second)
	for i := 0; i < numWaiters; i++ {
		select {
		case success := <-waiters[i]:
			if !success {
				t.Fatalf("Waiter %d failed", i)
			}
			t.Logf("Waiter %d completed", i)
		case <-timeout:
			t.Fatalf("DEADLOCK: Waiter %d never woke up even after Returns called processAllWaiters()", i)
		}
	}
	t.Log("SUCCESS: All waiters completed")
}

// TestOnDemandTickingDeadlock demonstrates the on-demand ticking deadlock bug.
// When all goroutines are waiting and no one calls Wait/TryTake, maybeTickLocked()
// never runs, so waiters never get woken up even though ticks should add tokens.
func TestOnDemandTickingDeadlock(t *testing.T) {
	h := New(10*1000*1000, 10*1000*1000) // 10ms capacity, 10ms/sec rate = 1ms per 100ms tick

	ctx := context.Background()

	// Exhaust the bucket
	tokens1, _ := h.Wait(ctx, "user1", 10*1000*1000)
	tokens2, _ := h.Wait(ctx, "user1", 10*1000*1000)
	t.Log("user1 took 20ms from 10ms capacity - deeply negative")

	// Start a waiter that should wake up after ~10 ticks (1 second)
	done := make(chan bool, 1)
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		t.Log("Waiter calling Wait(5ms)...")
		tokens3, err := h.Wait(ctx2, "user1", 5*1000*1000)
		if err != nil {
			t.Logf("Waiter failed: %v", err)
			done <- false
			return
		}
		t.Log("Waiter succeeded!")
		h.Return(tokens3)
		done <- true
	}()

	time.Sleep(50 * time.Millisecond)
	t.Log("Returning tokens to go back to positive balance...")

	// Return all tokens - user1 goes from -20ms to +20ms
	tokens1.Use(0)
	h.Return(tokens1)
	tokens2.Use(0)
	h.Return(tokens2)
	t.Log("Returns complete - bucket should have 20ms available now")

	select {
	case success := <-done:
		if success {
			t.Log("SUCCESS: Waiter woke up")
		} else {
			t.Fatal("Waiter failed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Waiter never woke despite 20ms being available.")
	}
}

// TestMultipleWaitersWakeup tests that multiple waiters can be processed correctly.
// With the lead waiter ticking mechanism, waiters may be woken by tick refills
// (lead waiter calls maybeTickLocked periodically). This test verifies the system
// doesn't deadlock and all waiters eventually complete.
func TestMultipleWaitersWakeup(t *testing.T) {
	h := New(30*1000*1000, 30*1000*1000) // 30ms capacity, 30ms/sec = 3ms per 100ms tick

	ctx := context.Background()

	// Completely exhaust the bucket with user1
	tokens1, err := h.Wait(ctx, "user1", 30*1000*1000) // Take all 30ms
	require.NoError(t, err)

	// Take another 30ms to go deeply negative
	tokens2, err := h.Wait(ctx, "user1", 30*1000*1000)
	require.NoError(t, err)
	t.Log("user1 took 60ms from 30ms capacity - system at -30ms")

	// Launch multiple waiters that will need tick refills to complete
	numWaiters := 5
	waiters := make([]chan bool, numWaiters)
	blocked := make(chan bool, numWaiters)

	for i := 0; i < numWaiters; i++ {
		waiters[i] = make(chan bool, 1)
		go func(id int, done chan bool) {
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			userID := "waiter" + string(rune('A'+id))
			blocked <- true                                  // Signal that we're about to wait
			tokens, err := h.Wait(ctx2, userID, 5*1000*1000) // 5ms each (total 25ms needed)
			if err != nil {
				t.Errorf("Waiter %d failed: %v", id, err)
				done <- false
				return
			}
			h.Return(tokens)
			done <- true
		}(i, waiters[i])
	}

	// Wait for all waiters to start
	for i := 0; i < numWaiters; i++ {
		<-blocked
	}
	time.Sleep(20 * time.Millisecond)
	t.Log("All waiters started")

	// Return tokens1 and tokens2 to bring system back to 0
	tokens1.Use(0)
	h.Return(tokens1)
	tokens2.Use(0)
	h.Return(tokens2)
	t.Log("Returned all tokens - system at 0ms, needs tick refills for waiters")

	// Waiters need ~25ms total (5ms * 5), at 3ms per tick = ~9 ticks = ~900ms
	// With lead waiter ticking, this should complete without deadlock
	timeout := time.After(2 * time.Second)
	for i := 0; i < numWaiters; i++ {
		select {
		case success := <-waiters[i]:
			if !success {
				t.Fatalf("Waiter %d failed", i)
			}
			t.Logf("Waiter %d completed", i)
		case <-timeout:
			t.Fatalf("Waiter %d timed out - deadlock detected", i)
		}
	}
	t.Log("All waiters completed successfully via lead waiter ticking")
}

// TestReturnToParentWakesAllChildren tests that the system handles multiple users correctly.
// With lead waiter ticking, waiters get tokens via tick refills even when starting at 0.
// This test verifies the system doesn't deadlock with multiple users waiting.
func TestReturnToParentWakesAllChildren(t *testing.T) {
	h := New(30*1000*1000, 30*1000*1000) // 30ms capacity, 30ms/sec = 3ms per 100ms tick

	ctx := context.Background()

	// Completely exhaust all tokens
	tokens1, _ := h.Wait(ctx, "user1", 10*1000*1000) // 10ms
	tokens2, _ := h.Wait(ctx, "user2", 10*1000*1000) // 10ms
	tokens3, _ := h.Wait(ctx, "user3", 10*1000*1000) // 10ms
	t.Log("All 30ms capacity exhausted")

	// Launch waiters for different users that will need ticks to complete
	var wg sync.WaitGroup
	blocked := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			userID := "user" + string(rune('1'+id))
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			blocked <- true                                  // Signal we're about to wait
			tokens, err := h.Wait(ctx2, userID, 8*1000*1000) // 8ms each = 24ms total
			if err != nil {
				t.Errorf("User %d wait failed: %v", id+1, err)
				return
			}
			h.Return(tokens)
		}(i)
	}

	// Wait for all waiters to start
	for i := 0; i < 3; i++ {
		<-blocked
	}
	time.Sleep(20 * time.Millisecond)
	t.Log("All waiters started and blocked")

	// Return some tokens, but not enough for all waiters
	tokens1.Use(5 * 1000 * 1000)
	h.Return(tokens1) // Returns 5ms

	tokens2.Use(5 * 1000 * 1000)
	h.Return(tokens2) // Returns 5ms

	tokens3.Use(5 * 1000 * 1000)
	h.Return(tokens3) // Returns 5ms

	t.Log("Returned 15ms, but waiters need 24ms total - lead waiter ticking should provide rest")

	// All waiters should complete via lead waiter tick refills
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("All waiters completed successfully via lead waiter ticking")
	case <-time.After(3 * time.Second):
		t.Fatal("Deadlock: Not all waiters completed despite lead waiter ticking")
	}
}
