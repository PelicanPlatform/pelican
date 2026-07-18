//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package test_utils

import (
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

// SkipIfNoMinio skips the test if the minio binary is not available on PATH.
func SkipIfNoMinio(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("minio"); err != nil {
		t.Skip("minio not found on PATH; skipping minio-backed test")
	}
}

// StartMinio launches a minio server bound to 127.0.0.1:0 (OS-assigned port),
// parses the actual listening port from minio's log output, and returns the
// endpoint URL, access key, and secret key. The server is killed when the test
// completes.
//
// This avoids the TOCTOU race inherent in picking a free port first and then
// passing it to minio.
func StartMinio(t *testing.T, bucket string) (endpoint, accessKey, secretKey string) {
	t.Helper()
	SkipIfNoMinio(t)

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
	//   S3-API: http://127.0.0.1:43219   (older versions)
	//   API: http://127.0.0.1:43219       (newer versions)
	// Poll the log file until we find it (with a 30-second deadline).
	// Use assert (not require) so we can print minio's log on failure.
	apiRe := regexp.MustCompile(`(?:S3-)?API:\s+(https?://\S+)`)
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
		t.Fatalf("minio never printed an API endpoint; log output:\n%s", logData)
	}

	// Pre-create the bucket directory on disk so it's available immediately.
	bucketDir := filepath.Join(dataDir, bucket)
	require.NoError(t, os.Mkdir(bucketDir, 0755))

	return endpoint, accessKey, secretKey
}
