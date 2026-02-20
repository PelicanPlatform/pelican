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

package fed_tests

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
	// testPelicanBinary holds the path to the built pelican binary for tests
	testPelicanBinary string
	// testTempDir holds the temp directory for the test binary
	testTempDir string
	// buildOnce ensures we only build the binary once across all tests
	buildOnce sync.Once
	// buildErr stores any error from building the binary
	buildErr error
)

// getPelicanBinary builds the pelican binary once and returns its path.
func getPelicanBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binaryName := "pelican"
		if runtime.GOOS == "windows" {
			binaryName = "pelican.exe"
		}
		testPelicanBinary = filepath.Join(testTempDir, binaryName)

		buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", testPelicanBinary, "../cmd")
		buildCmd.Env = os.Environ()
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("failed to build pelican binary: %w\nOutput: %s", err, string(buildOutput))
		}
	})

	if buildErr != nil {
		t.Fatalf("Failed to build pelican binary: %v", buildErr)
	}

	return testPelicanBinary
}

// TestMain handles test setup and cleanup for the e2e_fed_tests package.
func TestMain(m *testing.M) {
	var err error
	testTempDir, err = os.MkdirTemp("", "pelican-e2e-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if testTempDir != "" {
		os.RemoveAll(testTempDir)
	}

	os.Exit(code)
}
