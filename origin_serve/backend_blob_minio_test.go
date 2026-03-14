//go:build !windows

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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfNoMinio skips the test if the minio binary is not available on PATH.
func skipIfNoMinio(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("minio"); err != nil {
		t.Skip("minio not found on PATH; skipping S3 integration test")
	}
}

// startMinio launches a minio server bound to 127.0.0.1:0 (OS-assigned port),
// parses the actual listening port from minio's log output, and returns the
// endpoint URL, access key, and secret key. The server is killed when the test
// completes.
//
// This avoids the TOCTOU race inherent in picking a free port first and then
// passing it to minio.
func startMinio(t *testing.T) (endpoint, accessKey, secretKey string) {
	t.Helper()
	skipIfNoMinio(t)

	dataDir := t.TempDir()

	accessKey = "minioadmin"
	secretKey = "minioadmin"

	cmd := exec.Command("minio", "server",
		"--address", "127.0.0.1:0",
		dataDir,
	)
	cmd.Env = append(os.Environ(),
		"MINIO_ROOT_USER="+accessKey,
		"MINIO_ROOT_PASSWORD="+secretKey,
		// Disable the web console so we don't need --console-address.
		// Using 127.0.0.2 for the console fails on macOS (only 127.0.0.1
		// is configured), and using 127.0.0.1:0 is rejected by minio
		// because it matches --address.
		"MINIO_BROWSER=off",
	)

	// Capture stdout so we can parse the "S3-API:" line for the real port.
	// Minio writes its banner to stderr, so merge stderr into stdout.
	logPath := filepath.Join(t.TempDir(), "minio.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	t.Cleanup(func() { logFile.Close() })
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	require.NoError(t, cmd.Start(), "failed to start minio")

	// Monitor for early exit so we fail fast with diagnostics.
	var minioDone atomic.Bool
	var minioErr error
	go func() {
		minioErr = cmd.Wait()
		minioDone.Store(true)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		for !minioDone.Load() {
			time.Sleep(10 * time.Millisecond)
		}
	})

	// Minio prints a line like:
	//   S3-API: http://127.0.0.1:43219
	// Poll the log file until we find it (with a 30-second deadline).
	// Use assert (not require) so we can print minio's log on failure.
	apiRe := regexp.MustCompile(`S3-API:\s+(https?://\S+)`)
	ok := assert.Eventually(t, func() bool {
		if minioDone.Load() {
			return false
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			return false
		}
		if m := apiRe.FindSubmatch(data); m != nil {
			endpoint = string(m[1])
			return true
		}
		return false
	}, 30*time.Second, 200*time.Millisecond)
	if !ok {
		logData, _ := os.ReadFile(logPath)
		if minioDone.Load() {
			t.Fatalf("minio exited early (err=%v); log output:\n%s", minioErr, logData)
		}
		t.Fatalf("minio never printed an S3-API endpoint; log output:\n%s", logData)
	}

	// Pre-create the bucket directory on disk so it's available immediately.
	bucketDir := filepath.Join(dataDir, "test-bucket")
	require.NoError(t, os.Mkdir(bucketDir, 0755))

	return endpoint, accessKey, secretKey
}

// ---------------------------------------------------------------------------
// TestBlobBackend_MinioS3 — full integration test using a real minio server.
// Tests the complete S3 flow: build URL, open bucket, write, read, stat,
// rename, delete, directory listing.
// Skipped if minio is not installed.
// ---------------------------------------------------------------------------

func TestBlobBackend_MinioS3(t *testing.T) {
	skipIfNoMinio(t)

	endpoint, accessKey, secretKey := startMinio(t)

	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: endpoint,
		Region:     "us-east-1",
		Bucket:     "test-bucket",
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		URLStyle:   "path",
	})
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("CheckAvailability", func(t *testing.T) {
		require.NoError(t, backend.CheckAvailability())
	})

	t.Run("WriteAndRead", func(t *testing.T) {
		content := []byte("Hello from MinIO integration test!")

		wf, err := backend.FileSystem().OpenFile(ctx, "/greeting.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		n, err := wf.Write(content)
		require.NoError(t, err)
		assert.Equal(t, len(content), n)
		require.NoError(t, wf.Close())

		rf, err := backend.FileSystem().OpenFile(ctx, "/greeting.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got, err := io.ReadAll(rf)
		require.NoError(t, err)
		assert.Equal(t, content, got)
		rf.Close()
	})

	t.Run("Stat", func(t *testing.T) {
		// Write an object directly
		wf, err := backend.FileSystem().OpenFile(ctx, "/statfile.bin", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("0123456789"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		info, err := backend.FileSystem().Stat(ctx, "/statfile.bin")
		require.NoError(t, err)
		assert.Equal(t, int64(10), info.Size())
		assert.Equal(t, "statfile.bin", info.Name())
		assert.False(t, info.IsDir())
	})

	t.Run("StatNonExistent", func(t *testing.T) {
		_, err := backend.FileSystem().Stat(ctx, "/nonexistent.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("ReadNonExistent", func(t *testing.T) {
		_, err := backend.FileSystem().OpenFile(ctx, "/does-not-exist.txt", os.O_RDONLY, 0)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("Rename", func(t *testing.T) {
		wf, err := backend.FileSystem().OpenFile(ctx, "/rename-src.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("rename me"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		require.NoError(t, backend.FileSystem().Rename(ctx, "/rename-src.txt", "/rename-dst.txt"))

		_, err = backend.FileSystem().Stat(ctx, "/rename-src.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)

		info, err := backend.FileSystem().Stat(ctx, "/rename-dst.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(9), info.Size())
	})

	t.Run("RemoveAll", func(t *testing.T) {
		wf, err := backend.FileSystem().OpenFile(ctx, "/delete-me.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("gone"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		require.NoError(t, backend.FileSystem().RemoveAll(ctx, "/delete-me.txt"))

		_, err = backend.FileSystem().Stat(ctx, "/delete-me.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("DirectoryListing", func(t *testing.T) {
		// Write multiple objects under a "directory"
		for _, name := range []string{"/listing/a.txt", "/listing/b.txt", "/listing/c.txt"} {
			wf, err := backend.FileSystem().OpenFile(ctx, name, os.O_CREATE|os.O_WRONLY, 0644)
			require.NoError(t, err)
			_, err = wf.Write([]byte(name))
			require.NoError(t, err)
			require.NoError(t, wf.Close())
		}

		f, err := backend.FileSystem().OpenFile(ctx, "/listing", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		entries, err := f.Readdir(-1)
		require.NoError(t, err)
		assert.Len(t, entries, 3)

		names := make(map[string]bool)
		for _, e := range entries {
			names[e.Name()] = true
		}
		assert.True(t, names["a.txt"])
		assert.True(t, names["b.txt"])
		assert.True(t, names["c.txt"])
	})

	t.Run("SeekOnRead", func(t *testing.T) {
		content := []byte("0123456789ABCDEF")
		wf, err := backend.FileSystem().OpenFile(ctx, "/seekable.bin", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write(content)
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		rf, err := backend.FileSystem().OpenFile(ctx, "/seekable.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer rf.Close()

		pos, err := rf.Seek(10, io.SeekStart)
		require.NoError(t, err)
		assert.Equal(t, int64(10), pos)

		buf := make([]byte, 6)
		n, err := rf.Read(buf)
		// Read may return io.EOF along with the final data — that's valid
		if err != nil {
			assert.ErrorIs(t, err, io.EOF)
		}
		assert.Equal(t, 6, n)
		assert.Equal(t, "ABCDEF", string(buf))
	})

	t.Run("WriteEmptyObject", func(t *testing.T) {
		wf, err := backend.FileSystem().OpenFile(ctx, "/empty.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		info, err := backend.FileSystem().Stat(ctx, "/empty.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(0), info.Size())
	})

	t.Run("StoragePrefix", func(t *testing.T) {
		prefixedBackend, err := newBlobBackend(BlobBackendOptions{
			ServiceURL:    endpoint,
			Region:        "us-east-1",
			Bucket:        "test-bucket",
			AccessKey:     accessKey,
			SecretKey:     secretKey,
			URLStyle:      "path",
			StoragePrefix: "/prefixed",
		})
		require.NoError(t, err)
		defer prefixedBackend.Close()

		wf, err := prefixedBackend.FileSystem().OpenFile(ctx, "/scoped.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("scoped content"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		// Read back via the prefixed backend
		rf, err := prefixedBackend.FileSystem().OpenFile(ctx, "/scoped.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got, err := io.ReadAll(rf)
		require.NoError(t, err)
		assert.Equal(t, "scoped content", string(got))
		rf.Close()

		// The un-prefixed backend should see it at /prefixed/scoped.txt
		rf2, err := backend.FileSystem().OpenFile(ctx, "/prefixed/scoped.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got2, err := io.ReadAll(rf2)
		require.NoError(t, err)
		assert.Equal(t, "scoped content", string(got2))
		rf2.Close()
	})
}
