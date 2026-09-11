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

package test_utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	pelicanBinaryOnce sync.Once
	pelicanBinaryPath string
	pelicanBinaryDir  string
	pelicanBinaryErr  error
)

// PelicanBinaryEnvVar names a prebuilt pelican CLI for the tests to use instead of building
// their own.  Several packages need the binary and each test process would otherwise pay for
// its own build, so CI builds it once up front and points the whole run at it.
const PelicanBinaryEnvVar = "PELICAN_TEST_BINARY"

// PelicanBinary returns a path to the pelican CLI, building it once per test process.
//
// If PELICAN_TEST_BINARY names an executable, that is used and nothing is built.  Otherwise
// the CLI is built into a temp directory and shared by every caller in the package; pair
// that with CleanupPelicanBinary in the package's TestMain to remove it afterwards.
func PelicanBinary(t *testing.T) string {
	t.Helper()
	pelicanBinaryOnce.Do(func() {
		if prebuilt := os.Getenv(PelicanBinaryEnvVar); prebuilt != "" {
			info, err := os.Stat(prebuilt)
			if err != nil {
				pelicanBinaryErr = fmt.Errorf("%s is set to %q, which cannot be read: %w",
					PelicanBinaryEnvVar, prebuilt, err)
				return
			}
			if info.IsDir() || info.Mode()&0111 == 0 {
				pelicanBinaryErr = fmt.Errorf("%s is set to %q, which is not an executable file",
					PelicanBinaryEnvVar, prebuilt)
				return
			}
			pelicanBinaryPath = prebuilt
			return
		}

		pelicanBinaryDir, pelicanBinaryErr = os.MkdirTemp("", "pelican-e2e-binary-*")
		if pelicanBinaryErr != nil {
			pelicanBinaryErr = fmt.Errorf("failed to create temp directory for the pelican binary: %w", pelicanBinaryErr)
			return
		}

		binaryName := "pelican"
		if runtime.GOOS == "windows" {
			binaryName = "pelican.exe"
		}
		pelicanBinaryPath = filepath.Join(pelicanBinaryDir, binaryName)

		// Build by import path rather than a relative one so this works from any
		// package's directory.  -buildvcs=false keeps the build from failing on CI
		// checkouts owned by a different user than the test process.
		buildCmd := exec.Command("go", "build", "-tags", "client,server", "-buildvcs=false",
			"-o", pelicanBinaryPath, "github.com/pelicanplatform/pelican/cmd")
		buildCmd.Env = os.Environ()
		if output, err := buildCmd.CombinedOutput(); err != nil {
			pelicanBinaryErr = fmt.Errorf("failed to build pelican binary: %w\nOutput: %s", err, string(output))
		}
	})

	if pelicanBinaryErr != nil {
		t.Fatalf("Failed to build pelican binary: %v", pelicanBinaryErr)
	}
	return pelicanBinaryPath
}

// CleanupPelicanBinary removes the binary built by PelicanBinary, if any.  Call it from
// TestMain after m.Run returns.
func CleanupPelicanBinary() {
	if pelicanBinaryDir != "" {
		_ = os.RemoveAll(pelicanBinaryDir)
	}
}
