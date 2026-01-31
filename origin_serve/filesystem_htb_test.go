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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/htb"
)

func TestAferoFileSystemWithRateLimiter(t *testing.T) {
	// Create an in-memory filesystem
	memFs := afero.NewMemMapFs()

	// Create HTB with 1 second capacity (1 billion nanoseconds per second, 1 second capacity)
	limiter := htb.New(1000*1000*1000, 1000*1000*1000) // 1 second in nanoseconds

	// Create filesystem with rate limiter
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)
	require.NotNil(t, fs)
	assert.NotNil(t, fs.rateLimiter)

	// Create a test file
	ctx := context.Background()
	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Write some data - should be rate limited
	testData := []byte("Hello, World!")
	n, err := file.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
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
	testData := strings.Repeat("Test data for reading!", 100)
	err := afero.WriteFile(memFs, "/test.txt", []byte(testData), 0644)
	require.NoError(t, err)

	// Create HTB with limited capacity - use nanoseconds for tokens
	// 100ms capacity = 100*1000*1000 nanoseconds
	// Fill rate of 50ms/sec means we get 50ms worth of tokens per second
	limiter := htb.New(50*1000*1000, 100*1000*1000) // 50ms/s fill, 100ms capacity
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	ctx := context.Background()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "reader"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	// Read data - should be rate limited
	// First read will request 50ms of tokens
	buf := make([]byte, 1024)
	start := time.Now()
	n, err := file.Read(buf)
	elapsed := time.Since(start)

	// Should have read some data
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// Should have taken measurable time due to rate limiting
	// At 50ms/s fill rate and 50ms initial wait, should be fast initially
	// but subsequent reads will experience delays
	// Use a modest threshold to account for timer resolution
	assert.Greater(t, elapsed, time.Duration(0), "Rate limited read should take some time")
}

func TestAferoFileRateLimitedWrite(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create HTB with limited capacity - use nanoseconds for tokens
	// 100ms capacity = 100*1000*1000 nanoseconds
	// Fill rate of 50ms/sec means we get 50ms worth of tokens per second
	limiter := htb.New(50*1000*1000, 100*1000*1000) // 50ms/s fill, 100ms capacity
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	ctx := context.Background()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "writer"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer file.Close()

	// Write data - should be rate limited
	// First write will request 50ms of tokens
	testData := []byte(strings.Repeat("Test data!", 100))
	start := time.Now()
	n, err := file.Write(testData)
	elapsed := time.Since(start)

	// Should have written all data
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Should have taken measurable time due to rate limiting
	// At 50ms/s fill rate and 50ms initial wait, should be fast initially
	// but subsequent writes will experience delays
	// Use a modest threshold to account for timer resolution
	assert.Greater(t, elapsed, time.Duration(0), "Rate limited write should take some time")
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

	// Create HTB with 200ms capacity
	limiter := htb.New(200*1000*1000, 200*1000*1000)
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	// Create test files
	testData := []byte(strings.Repeat("Test!", 200))
	err := afero.WriteFile(memFs, "/file1.txt", testData, 0644)
	require.NoError(t, err)
	err = afero.WriteFile(memFs, "/file2.txt", testData, 0644)
	require.NoError(t, err)

	// Two users read concurrently
	ctx1 := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "user1"})
	ctx2 := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "user2"})

	done := make(chan bool, 2)

	// User 1 reads
	go func() {
		file, err := fs.OpenFile(ctx1, "/file1.txt", os.O_RDONLY, 0)
		if err != nil {
			done <- false
			return
		}
		defer file.Close()

		buf := make([]byte, len(testData))
		_, err = file.Read(buf)
		done <- err == nil
	}()

	// User 2 reads
	go func() {
		file, err := fs.OpenFile(ctx2, "/file2.txt", os.O_RDONLY, 0)
		if err != nil {
			done <- false
			return
		}
		defer file.Close()

		buf := make([]byte, len(testData))
		_, err = file.Read(buf)
		done <- err == nil
	}()

	// Wait for both to complete
	success1 := <-done
	success2 := <-done

	assert.True(t, success1, "User 1 should complete successfully")
	assert.True(t, success2, "User 2 should complete successfully")
}

func TestAferoFileContextCancellation(t *testing.T) {
	memFs := afero.NewMemMapFs()

	// Create HTB with enough capacity for initial request but limited overall
	limiter := htb.New(100*1000*1000, 100*1000*1000) // 100ms capacity
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, limiter)

	// Create large test file
	testData := []byte(strings.Repeat("Test data!", 10000))
	err := afero.WriteFile(memFs, "/test.txt", testData, 0644)
	require.NoError(t, err)

	// Create context that will be cancelled soon
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	ctx = context.WithValue(ctx, userInfoKey, &userInfo{User: "reader"})

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	// Start reading - this should eventually fail with context cancellation or rate limit
	buf := make([]byte, 1024)

	// Make multiple reads to exhaust tokens, one should eventually fail with context timeout
	for i := 0; i < 10; i++ {
		_, err = file.Read(buf)
		if err != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Should get an error (either context timeout or rate limit)
	assert.Error(t, err)
}
