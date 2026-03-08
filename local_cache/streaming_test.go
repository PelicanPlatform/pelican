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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNonBlockingDownload_CompletionTracking verifies the background completion
// mechanism used by non-blocking downloads: completionDone channel and completionErr
// atomic value correctly track background goroutine lifecycle.
func TestNonBlockingDownload_CompletionTracking(t *testing.T) {
	// Verify completionDone channel signals properly
	dl := &persistentDownload{
		completionDone: make(chan struct{}),
	}

	done := make(chan bool, 1)
	go func() {
		select {
		case <-dl.completionDone:
			done <- true
		case <-time.After(2 * time.Second):
			done <- false
		}
	}()

	// Should not be done yet
	select {
	case <-dl.completionDone:
		t.Fatal("completionDone should not be closed yet")
	default:
		// expected
	}

	// Simulate background completion
	close(dl.completionDone)

	result := <-done
	assert.True(t, result, "completionDone should signal after close")

	// Verify completionErr stores and returns errors
	dl2 := &persistentDownload{
		completionDone: make(chan struct{}),
	}
	assert.Nil(t, dl2.completionErr.Load(), "completionErr should be nil initially")

	testErr := "simulated transfer failure"
	dl2.completionErr.Store(testErr)
	assert.Equal(t, testErr, dl2.completionErr.Load(), "completionErr should store error")
}

// TestNonBlockingDownload_CompletionDoneIsNonBlocking verifies that callers can
// poll completionDone without blocking, and that multiple goroutines can wait
// on the same channel simultaneously.
func TestNonBlockingDownload_CompletionDoneIsNonBlocking(t *testing.T) {
	dl := &persistentDownload{
		completionDone: make(chan struct{}),
	}

	const numWaiters = 5
	results := make([]atomic.Bool, numWaiters)

	// Launch multiple waiters
	for i := 0; i < numWaiters; i++ {
		i := i
		go func() {
			<-dl.completionDone
			results[i].Store(true)
		}()
	}

	// Give goroutines time to start waiting
	time.Sleep(50 * time.Millisecond)

	// None should be done yet
	for i := 0; i < numWaiters; i++ {
		assert.False(t, results[i].Load(), "Waiter %d should not be done yet", i)
	}

	// Signal completion
	close(dl.completionDone)

	// All should complete within a reasonable time
	require.Eventually(t, func() bool {
		for i := 0; i < numWaiters; i++ {
			if !results[i].Load() {
				return false
			}
		}
		return true
	}, 2*time.Second, 10*time.Millisecond, "All waiters should be notified")
}

// Integration-level tests for streaming / non-blocking downloads live in
// e2e_fed_tests/cache_streaming_test.go where a full federation is available.
