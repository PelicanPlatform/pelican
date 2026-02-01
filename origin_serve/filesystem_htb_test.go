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

package origin_serve

import (
	"context"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/htb"
)

// slowFs wraps an afero.Fs and adds configurable delays to operations for testing
type slowFs struct {
	afero.Fs
	statDelay time.Duration
	readReady chan struct{} // Signals when Read should proceed
}

func (s *slowFs) Stat(name string) (fs.FileInfo, error) {
	if s.statDelay > 0 {
		time.Sleep(s.statDelay)
	}
	return s.Fs.Stat(name)
}

func (s *slowFs) Open(name string) (afero.File, error) {
	f, err := s.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &slowFile{File: f, readReady: s.readReady}, nil
}

func (s *slowFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := s.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &slowFile{File: f, readReady: s.readReady}, nil
}

// slowFile wraps an afero.File and adds synchronization for testing
type slowFile struct {
	afero.File
	readReady chan struct{}
	readDelay time.Duration // Fixed delay per read
}

func (s *slowFile) Read(p []byte) (int, error) {
	if s.readReady != nil {
		<-s.readReady // Wait for signal to proceed
	}
	if s.readDelay > 0 {
		time.Sleep(s.readDelay)
	}
	return s.File.Read(p)
}

// delayedFs wraps an afero.Fs and adds per-file configurable delays
type delayedFs struct {
	afero.Fs
	fileDelays map[string]time.Duration // Map of filename to read delay
}

func (d *delayedFs) Open(name string) (afero.File, error) {
	f, err := d.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	delay := d.fileDelays[name]
	return &slowFile{File: f, readDelay: delay}, nil
}

func (d *delayedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := d.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	delay := d.fileDelays[name]
	return &slowFile{File: f, readDelay: delay}, nil
}

// Test the rate limiter filesystem; simply ensures that it delivers data
// as expected and the HTB rate limiter is invoked.
func TestAferoFileSystemWithRateLimiter(t *testing.T) {
	// Create an in-memory filesystem
	memFs := afero.NewMemMapFs()

	// Create HTB with reasonable capacity
	limiter := htb.New(1000*1000*1000, 1000*1000*1000) // 1 second capacity

	// Create filesystem with rate limiter
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)
	require.NotNil(t, fs)
	assert.NotNil(t, fs.rateLimiter, "Rate limiter should be set")

	// Create a test file
	ctx := context.Background()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "testuser"})
	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Write some data - should leverage the rate limiter but not block
	testData := []byte("Hello, World!")
	n, err := file.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Verify the rate limiter was actually used by checking HTB stats
	stats := limiter.GetStats()
	assert.Equal(t, 1, stats.NumChildren, "Rate limiter should have one user")
	assert.Contains(t, stats.ChildrenStats, "testuser", "User should be tracked in rate limiter")
}

func TestAferoFileSystemExtractsUserInfo(t *testing.T) {
	memFs := afero.NewMemMapFs()
	limiter := htb.New(1000*1000*1000, 1000*1000*1000)
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	// Test with authenticated user
	ctx := context.Background()
	userInfo := &userInfo{User: "testuser"}
	ctx = context.WithValue(ctx, userInfoKey, userInfo)
	ctx = context.WithValue(ctx, issuerContextKey{}, "https://issuer.example.com")

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Check that userID was set correctly
	afFile, ok := file.(*aferoFile)
	require.True(t, ok)
	assert.Contains(t, afFile.userID, "testuser")
	assert.Contains(t, afFile.userID, "issuer.example.com")
}

func TestAferoFileSystemUnauthenticated(t *testing.T) {
	memFs := afero.NewMemMapFs()
	limiter := htb.New(1000*1000*1000, 1000*1000*1000)
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	// Test without user info
	ctx := context.Background()
	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Check that userID defaults to "unauthenticated"
	afFile, ok := file.(*aferoFile)
	require.True(t, ok)
	assert.Equal(t, "unauthenticated", afFile.userID)
}

func TestAferoFileRateLimitedRead(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create a test file with data
	testData := []byte(strings.Repeat("Test data for reading!", 100))
	err := afero.WriteFile(memFs, "/test.txt", testData, 0644)
	require.NoError(t, err)

	// Wrap with slow filesystem that blocks on Read until readReady channel is closed
	readReady := make(chan struct{})
	slowFs := &slowFs{Fs: memFs, readReady: readReady}

	// Create HTB with reasonable capacity and refill rate
	// Rate limiter pre-allocates time tokens (50ms initially, 100ms chunks during operation)
	// When the operation completes, it reports actual elapsed wall-clock time consumed
	// 500ms/s refill rate, 500ms capacity (enough for both reads to complete)
	limiter := htb.New(500*1000*1000, 500*1000*1000)
	fs := newAferoFileSystemWithRateLimiter(slowFs, "", nil, limiter)

	ctx := context.Background()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "reader"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	// Start a goroutine that will request tokens and then block on filesystem I/O
	slowReadStarted := make(chan struct{})
	slowReadBlocked := make(chan struct{})
	slowReadCompleted := make(chan struct{})

	go func() {
		buf := make([]byte, 150*1000) // Buffer size is irrelevant for rate limiting
		close(slowReadStarted)
		// This will:
		// 1. Request 50ms of time tokens from rate limiter (initialWaitNs)
		// 2. Start the Read() operation which blocks on readReady channel
		// 3. While blocked, the operation is consuming wall-clock time
		// 4. Periodically request more tokens (100ms chunks) to keep operation alive
		// 5. When completed, report actual elapsed time back to rate limiter
		_, err := file.Read(buf)
		require.NoError(t, err)
		close(slowReadCompleted)
	}()

	<-slowReadStarted
	// Wait for slow read to consume some time (and tokens) while blocked
	time.Sleep(60 * time.Millisecond)
	close(slowReadBlocked)

	// Now try a second read - should be blocked waiting for tokens
	// (the slow read consumed most available tokens)
	ctx2 := context.Background()
	ctx2 = context.WithValue(ctx2, userInfoKey, &userInfo{User: "reader"})
	file2, err := fs.OpenFile(ctx2, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file2.Close()

	fastReadStarted := make(chan struct{})
	fastReadCompleted := make(chan struct{})

	go func() {
		buf := make([]byte, 100*1000) // Buffer size is irrelevant
		close(fastReadStarted)
		// This will try to get tokens from rate limiter, but should be blocked
		// because the slow read already has tokens allocated and is still running
		_, err := file2.Read(buf)
		require.NoError(t, err)
		close(fastReadCompleted)
	}()

	<-fastReadStarted
	<-slowReadBlocked

	// Fast read should NOT complete yet - it's waiting for rate limiter tokens
	// The slow read is holding tokens while blocked on filesystem
	select {
	case <-fastReadCompleted:
		t.Fatal("Fast read completed too early - should be blocked waiting for tokens")
	case <-time.After(100 * time.Millisecond):
		// Good - fast read is blocked waiting for tokens
	}

	// Unblock the slow read so it can complete and return its tokens
	close(readReady)

	// Now both should complete
	select {
	case <-slowReadCompleted:
		// Good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Slow read didn't complete after unblocking")
	}

	select {
	case <-fastReadCompleted:
		// Good - completed after tokens freed
	case <-time.After(1 * time.Second):
		t.Fatal("Fast read didn't complete after slow read finished")
	}
}

func TestAferoFileRateLimitedWrite(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create HTB with reasonable capacity
	limiter := htb.New(1000*1000*1000, 1000*1000*1000) // 1 second capacity
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	ctx := context.Background()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "writer"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Write data - should go through rate limiter
	testData := []byte("Test data!")
	n, err := file.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Verify the rate limiter was actually used by checking HTB stats
	stats := limiter.GetStats()
	assert.Equal(t, 1, stats.NumChildren, "Rate limiter should have one user")
	assert.Contains(t, stats.ChildrenStats, "writer", "User should be tracked in rate limiter")
}

func TestAferoFileWithoutRateLimiter(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create filesystem without rate limiter
	fs := newAferoFileSystem(memFs, "", nil)
	require.NotNil(t, fs)
	assert.Nil(t, fs.rateLimiter)

	// Create a test file
	ctx := context.Background()
	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Write should work without rate limiting
	testData := []byte("Hello, World!")
	n, err := file.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Read should work without rate limiting
	file.Close()
	file, err = fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	buf := make([]byte, len(testData))
	n, err = file.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buf)
}

func TestAferoFileConcurrentUsersShareFairly(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create test files with substantial data
	testData := []byte(strings.Repeat("X", 1024)) // 1KB chunks
	err := afero.WriteFile(memFs, "/slow.txt", testData, 0644)
	require.NoError(t, err)
	err = afero.WriteFile(memFs, "/fast.txt", testData, 0644)
	require.NoError(t, err)

	// Wrap with filesystem that has per-file delays
	// User1 reads from slow.txt: 100ms per read
	// User2 reads from fast.txt: 45ms per read
	delayedFs := &delayedFs{
		Fs: memFs,
		fileDelays: map[string]time.Duration{
			"/slow.txt": 100 * time.Millisecond,
			"/fast.txt": 45 * time.Millisecond,
		},
	}

	// Create HTB with rate limiting
	// Allow 1 second of I/O time per wall-clock second, shared between users
	// This means if both users are active, each gets ~100ms per second
	limiter := htb.New(200*1000*1000, 200*1000*1000) // 200ms/sec rate, 200ms capacity
	fs := newAferoFileSystemWithRateLimiter(delayedFs, "", nil, limiter)

	// Track how much time each user actually got
	type userResult struct {
		user           string
		readsCompleted int
		totalTime      time.Duration
	}
	results := make(chan userResult, 2)
	startBarrier := make(chan struct{}) // Ensure both goroutines start at same time

	// User 1 reads from slow file (100ms per read)
	ctx1 := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "user1"})
	go func() {
		<-startBarrier // Wait for both goroutines to be ready
		start := time.Now()
		file, err := fs.OpenFile(ctx1, "/slow.txt", os.O_RDONLY, 0)
		if err != nil {
			results <- userResult{"user1", 0, 0}
			return
		}
		defer file.Close()

		buf := make([]byte, len(testData))
		reads := 0
		// Read as many times as possible for 10 seconds
		for time.Since(start) < 10*time.Second {
			_, err = file.Read(buf)
			if err != nil && err != io.EOF {
				break
			}
			reads++
			// Reset file position for next read
			if _, err := file.Seek(0, 0); err != nil {
				break
			}
		}
		results <- userResult{"user1", reads, time.Since(start)}
	}()

	// User 2 reads from fast file (45ms per read)
	ctx2 := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "user2"})
	go func() {
		<-startBarrier // Wait for both goroutines to be ready
		start := time.Now()
		file, err := fs.OpenFile(ctx2, "/fast.txt", os.O_RDONLY, 0)
		if err != nil {
			results <- userResult{"user2", 0, 0}
			return
		}
		defer file.Close()

		buf := make([]byte, len(testData))
		reads := 0
		// Read as many times as possible for 10 seconds
		for time.Since(start) < 10*time.Second {
			_, err = file.Read(buf)
			if err != nil && err != io.EOF {
				break
			}
			reads++
			// Reset file position for next read
			if _, err := file.Seek(0, 0); err != nil {
				break
			}
		}
		results <- userResult{"user2", reads, time.Since(start)}
	}()

	// Give goroutines time to start, then release them simultaneously
	time.Sleep(50 * time.Millisecond)
	close(startBarrier)

	// Collect results
	result1 := <-results
	result2 := <-results

	// Determine which result belongs to which user
	var user1Result, user2Result userResult
	if result1.user == "user1" {
		user1Result = result1
		user2Result = result2
	} else {
		user1Result = result2
		user2Result = result1
	}

	t.Logf("User1 (200ms/read): %d reads, total time: %v", user1Result.readsCompleted, user1Result.totalTime)
	t.Logf("User2 (90ms/read): %d reads, total time: %v", user2Result.readsCompleted, user2Result.totalTime)

	// Calculate actual I/O time (reads * delay per read)
	user1IOTime := time.Duration(user1Result.readsCompleted) * 100 * time.Millisecond
	user2IOTime := time.Duration(user2Result.readsCompleted) * 45 * time.Millisecond
	t.Logf("User1 actual I/O time: %v", user1IOTime)
	t.Logf("User2 actual I/O time: %v", user2IOTime)

	// Verify both users completed some reads
	assert.Greater(t, user1Result.readsCompleted, 0, "User1 should complete at least one read")
	assert.Greater(t, user2Result.readsCompleted, 0, "User2 should complete at least one read")

	ratio := float64(user1IOTime) / float64(user2IOTime)
	t.Logf("I/O time ratio (user1/user2): %.2f", ratio)

	// Require ratio between 0.7 and 1.3 for acceptable fairness
	assert.InDelta(t, 1.0, ratio, 0.3, "Users should get similar total I/O time for fair sharing")
}

func TestAferoFileContextCancellation(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create test file
	testData := []byte(strings.Repeat("Test data!", 1000))
	err := afero.WriteFile(memFs, "/test.txt", testData, 0644)
	require.NoError(t, err)

	// Wrap with filesystem that has slow reads to force token consumption
	delayedFs := &delayedFs{
		Fs: memFs,
		fileDelays: map[string]time.Duration{
			"/test.txt": 150 * time.Millisecond, // Each read takes 150ms
		},
	}

	// Create HTB with limited capacity
	limiter := htb.New(100*1000*1000, 200*1000*1000) // 100ms/s rate, 200ms capacity
	fs := newAferoFileSystemWithRateLimiter(delayedFs, "", nil, limiter)

	// Create context that will timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "reader"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	// Start reading - first read will work (requests 50ms, has 200ms capacity)
	// Second read will consume tokens (150ms each)
	// Eventually context should timeout while waiting for tokens
	buf := make([]byte, len(testData))
	readsCompleted := 0
	for i := 0; i < 10; i++ {
		if _, err := file.Seek(0, 0); err != nil { // Reset to read same data
			break
		}
		_, err = file.Read(buf)
		if err != nil {
			break
		}
		readsCompleted++
	}

	// Should have completed at least one read but eventually hit context timeout
	assert.Greater(t, readsCompleted, 0, "Should complete at least one read")
	assert.Error(t, err, "Should eventually hit context timeout or rate limit")
	if err != nil {
		t.Logf("Failed after %d reads with error: %v", readsCompleted, err)
	}
}
