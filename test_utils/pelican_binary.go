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

// PelicanBinary builds the pelican CLI once per test process and returns its path.
//
// The build is expensive, so callers within a package share a single binary.  Note that
// this is per test *process*: each package that needs the CLI pays for its own build.
//
// Pair this with CleanupPelicanBinary in the package's TestMain to remove the binary once
// the package's tests are done.
func PelicanBinary(t *testing.T) string {
	t.Helper()
	pelicanBinaryOnce.Do(func() {
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
