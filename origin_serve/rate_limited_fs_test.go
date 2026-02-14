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
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/byte_rate"
)

// TestRateLimitedFs_ZeroDisabled verifies that a zero rate limit returns the
// underlying filesystem unmodified (no wrapper).
func TestRateLimitedFs_ZeroDisabled(t *testing.T) {
	base := afero.NewMemMapFs()
	result := newRateLimitedFs(base, 0)
	assert.Equal(t, base, result, "zero rate should return the unwrapped fs")

	result = newRateLimitedFs(base, -1)
	assert.Equal(t, base, result, "negative rate should return the unwrapped fs")
}

// TestRateLimitedFs_ReadThroughput verifies that reads are throttled to
// approximately the configured rate.
//
// We use a generous tolerance (±50 %) because the token-bucket limiter
// allows a one-burst spike at the start and timing jitter is expected in
// CI environments.
func TestRateLimitedFs_ReadThroughput(t *testing.T) {
	const (
		rateBytes = 50_000           // 50 KB/s
		fileSize  = 100_000          // 100 KB — should take ~2 s at the limit
		bufSize   = 4096             // typical read size
		tolerance = 0.50             // allow ±50 % of expected rate
		minTime   = 1 * time.Second  // at least this long (accounting for burst)
		maxTime   = 10 * time.Second // never this long
	)

	dir := t.TempDir()
	fpath := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(fpath, make([]byte, fileSize), 0644))

	base := afero.NewBasePathFs(afero.NewOsFs(), dir)
	fs := newRateLimitedFs(base, byte_rate.ByteRate(rateBytes))

	f, err := fs.Open("data.bin")
	require.NoError(t, err)
	defer f.Close()

	start := time.Now()
	buf := make([]byte, bufSize)
	var totalRead int64
	for {
		n, err := f.Read(buf)
		totalRead += int64(n)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	require.Equal(t, int64(fileSize), totalRead, "should read exactly the file size")

	// The limiter allows one burst (= rateBytes) up front, so effective
	// throttled bytes = fileSize - rateBytes.  Expected time ≈ throttled / rate.
	throttledBytes := float64(fileSize - rateBytes)
	expectedTime := time.Duration(float64(time.Second) * throttledBytes / float64(rateBytes))

	t.Logf("Read %d bytes in %v (expected ~%v, min %v)", totalRead, elapsed, expectedTime, minTime)

	assert.GreaterOrEqual(t, elapsed, minTime,
		"Transfer should take at least %v to confirm throttling is active", minTime)
	assert.Less(t, elapsed, maxTime,
		"Transfer should finish well within %v", maxTime)

	// Verify measured rate is in the right ballpark.
	measuredRate := float64(totalRead) / elapsed.Seconds()
	t.Logf("Measured rate: %.0f B/s (target: %d B/s)", measuredRate, rateBytes)

	lowerBound := float64(rateBytes) * (1 - tolerance)
	upperBound := float64(rateBytes) * (1 + tolerance) * 2 // generous for burst
	assert.Greater(t, measuredRate, lowerBound,
		"Measured rate %.0f B/s should be above %.0f B/s", measuredRate, lowerBound)
	assert.Less(t, measuredRate, upperBound,
		"Measured rate %.0f B/s should be below %.0f B/s", measuredRate, upperBound)
}

// TestRateLimitedFs_ReadAt verifies that ReadAt is also rate-limited.
func TestRateLimitedFs_ReadAt(t *testing.T) {
	const (
		rateBytes = 50_000
		fileSize  = 80_000
		chunkSize = 8192
	)

	dir := t.TempDir()
	fpath := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(fpath, make([]byte, fileSize), 0644))

	base := afero.NewBasePathFs(afero.NewOsFs(), dir)
	fs := newRateLimitedFs(base, byte_rate.ByteRate(rateBytes))

	f, err := fs.Open("data.bin")
	require.NoError(t, err)
	defer f.Close()

	// Interface assert: the file must support ReadAt for WebDAV range serving.
	ra, ok := f.(io.ReaderAt)
	require.True(t, ok, "rateLimitedFile should implement io.ReaderAt")

	start := time.Now()
	buf := make([]byte, chunkSize)
	var totalRead int64
	for off := int64(0); off < fileSize; off += chunkSize {
		n, err := ra.ReadAt(buf, off)
		totalRead += int64(n)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	t.Logf("ReadAt %d bytes in %v", totalRead, elapsed)
	require.Equal(t, int64(fileSize), totalRead)

	// Should take at least a bit of time to demonstrate throttling.
	// With burst = rateBytes, the first rateBytes are free, so throttled
	// portion = fileSize - rateBytes = 30000 bytes → ~0.6 s.
	assert.Greater(t, elapsed, 400*time.Millisecond,
		"ReadAt should show measurable throttling")
}

// TestRateLimitedFs_FirstBurstIsUnthrottled characterizes the burst behavior:
// the very first read of up to `burst` bytes completes almost instantly.
func TestRateLimitedFs_FirstBurstIsUnthrottled(t *testing.T) {
	const (
		rateBytes = 10_000 // 10 KB/s — burst is also 10 KB
		fileSize  = 20_000
	)

	dir := t.TempDir()
	fpath := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(fpath, make([]byte, fileSize), 0644))

	base := afero.NewBasePathFs(afero.NewOsFs(), dir)
	fs := newRateLimitedFs(base, byte_rate.ByteRate(rateBytes))

	f, err := fs.Open("data.bin")
	require.NoError(t, err)
	defer f.Close()

	// Read exactly one burst worth of data.
	buf := make([]byte, rateBytes)
	start := time.Now()
	n, err := f.Read(buf)
	firstReadTime := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, rateBytes, n)

	// The first burst should be essentially instant (< 100 ms) because the
	// token bucket starts full.
	t.Logf("First burst (%d bytes) took %v", n, firstReadTime)
	assert.Less(t, firstReadTime, 200*time.Millisecond,
		"First burst should be near-instant")

	// A second read of the same size should take ~1 second (refilling the bucket).
	start = time.Now()
	n, err = f.Read(buf)
	secondReadTime := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, rateBytes, n)

	t.Logf("Second burst (%d bytes) took %v", n, secondReadTime)
	assert.Greater(t, secondReadTime, 500*time.Millisecond,
		"Second burst should wait for token refill")
}

// TestRateLimitedFs_OpenFileAlsoWrapped confirms that OpenFile (not just Open)
// produces a rate-limited file.
func TestRateLimitedFs_OpenFileAlsoWrapped(t *testing.T) {
	const rateBytes = 100_000

	dir := t.TempDir()
	fpath := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(fpath, make([]byte, 1024), 0644))

	base := afero.NewBasePathFs(afero.NewOsFs(), dir)
	fs := newRateLimitedFs(base, byte_rate.ByteRate(rateBytes))

	f, err := fs.OpenFile("data.bin", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	_, isWrapped := f.(*rateLimitedFile)
	assert.True(t, isWrapped, "OpenFile should return a rateLimitedFile")
}

// TestRateLimitedFs_WriteThroughput verifies that writes are also throttled.
func TestRateLimitedFs_WriteThroughput(t *testing.T) {
	const (
		rateBytes = 50_000
		writeSize = 80_000
		chunkSize = 4096
	)

	dir := t.TempDir()
	base := afero.NewBasePathFs(afero.NewOsFs(), dir)
	fs := newRateLimitedFs(base, byte_rate.ByteRate(rateBytes))

	f, err := fs.OpenFile("out.bin", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer f.Close()

	data := make([]byte, chunkSize)
	start := time.Now()
	var totalWritten int64
	for totalWritten < writeSize {
		n, err := f.Write(data)
		require.NoError(t, err)
		totalWritten += int64(n)
	}
	elapsed := time.Since(start)

	t.Logf("Wrote %d bytes in %v", totalWritten, elapsed)

	// Similar logic: burst absorbs first rateBytes, rest is throttled.
	assert.Greater(t, elapsed, 400*time.Millisecond,
		"Write should show measurable throttling")
}
