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

// TestWaiterWakeupOnReturn verifies that returning tokens wakes up waiters
func TestWaiterWakeupOnReturn(t *testing.T) {
	h := New(10*1000*1000, 10*1000*1000) // 10ms capacity

	ctx := context.Background()

	// Take all tokens
	tokens1, err := h.Wait(ctx, "user1", 10*1000*1000)
	require.NoError(t, err)

	// Try to take more - should block
	waitDone := make(chan bool)
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		tokens2, err := h.Wait(ctx2, "user2", 5*1000*1000) // 5ms
		if err != nil {
			t.Error("Wait failed:", err)
			waitDone <- false
			return
		}
		h.Return(tokens2)
		waitDone <- true
	}()

	// Wait a bit to ensure goroutine is blocked
	time.Sleep(100 * time.Millisecond)

	// Return tokens - should wake up the waiter
	tokens1.Use(5 * 1000 * 1000) // Use 5ms
	h.Return(tokens1)            // Return 5ms

	// Waiter should now proceed
	select {
	case success := <-waitDone:
		if !success {
			t.Fatal("Waiter failed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Waiter was not woken up by Return()")
	}
}

// TestMultipleWaitersWakeup tests that multiple waiters can be woken up
func TestMultipleWaitersWakeup(t *testing.T) {
	h := New(30*1000*1000, 30*1000*1000) // 30ms capacity

	ctx := context.Background()

	// Take most tokens
	tokens1, err := h.Wait(ctx, "user1", 25*1000*1000) // 25ms
	require.NoError(t, err)

	// Launch multiple waiters
	numWaiters := 5
	waiters := make([]chan bool, numWaiters)
	for i := 0; i < numWaiters; i++ {
		waiters[i] = make(chan bool, 1)
		go func(id int, done chan bool) {
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			userID := "waiter" + string(rune('A'+id))
			tokens, err := h.Wait(ctx2, userID, 5*1000*1000) // 5ms each
			if err != nil {
				t.Errorf("Waiter %d failed: %v", id, err)
				done <- false
				return
			}
			h.Return(tokens)
			done <- true
		}(i, waiters[i])
	}

	// Wait for all waiters to be queued
	time.Sleep(100 * time.Millisecond)

	// Return tokens gradually
	tokens1.Use(10 * 1000 * 1000) // Use 10ms
	h.Return(tokens1)             // Return 15ms

	// All waiters should eventually proceed
	timeout := time.After(2 * time.Second)
	for i := 0; i < numWaiters; i++ {
		select {
		case success := <-waiters[i]:
			if !success {
				t.Fatalf("Waiter %d failed", i)
			}
		case <-timeout:
			t.Fatalf("Waiter %d timed out - not all waiters were woken up", i)
		}
	}
}

// TestReturnToParentWakesAllChildren tests that returning to parent processes all children
func TestReturnToParentWakesAllChildren(t *testing.T) {
	h := New(20*1000*1000, 20*1000*1000) // 20ms capacity

	ctx := context.Background()

	// Create multiple users and exhaust their tokens
	tokens1, _ := h.Wait(ctx, "user1", 7*1000*1000)
	tokens2, _ := h.Wait(ctx, "user2", 7*1000*1000)
	tokens3, _ := h.Wait(ctx, "user3", 6*1000*1000)

	// Now all children should have minimal tokens
	// Launch waiters for different users
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			userID := "user" + string(rune('1'+id))
			ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			tokens, err := h.Wait(ctx2, userID, 5*1000*1000) // 5ms
			if err != nil {
				t.Errorf("User %d wait failed: %v", id+1, err)
				return
			}
			h.Return(tokens)
		}(i)
	}

	// Wait for waiters to queue
	time.Sleep(100 * time.Millisecond)

	// Return tokens from user1 - with overflow, should go to parent
	// and wake up waiters for all users
	tokens1.Use(2 * 1000 * 1000)
	h.Return(tokens1) // Returns 5ms, should overflow to parent

	tokens2.Use(2 * 1000 * 1000)
	h.Return(tokens2)

	tokens3.Use(2 * 1000 * 1000)
	h.Return(tokens3)

	// All waiters should complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Not all waiters were woken up when tokens returned to parent")
	}
}
