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

// testBinary describes a binary that tests run as a subprocess. It is
// built at most once per test process, unless its environment variable
// names a prebuilt copy to use instead.
//
// The environment variables deliberately do not start with "PELICAN_",
// which Pelican would treat as setting (unknown) configuration keys.
type testBinary struct {
	envVar string
	pkg    string
	tags   string
	name   string

	once sync.Once
	path string
	err  error
}

var (
	pelicanBinary = &testBinary{
		envVar: "TEST_PELICAN_BINARY",
		pkg:    "github.com/pelicanplatform/pelican/cmd",
		tags:   "client",
		name:   "pelican",
	}
	pelicanServerBinary = &testBinary{
		envVar: "TEST_PELICAN_SERVER_BINARY",
		pkg:    "github.com/pelicanplatform/pelican/cmd",
		tags:   "server",
		name:   "pelican-server",
	}
	sampleMetadataServerBinary = &testBinary{
		envVar: "TEST_PELICAN_SAMPLE_METADATA_SERVER_BINARY",
		pkg:    "github.com/pelicanplatform/pelican/cmd/sample_metadata_server",
		name:   "sample_metadata_server",
	}

	// binariesDir holds the binaries built by this test process.
	binariesDir   string
	binariesDirMu sync.Mutex
)

// GetPelicanBinary returns the path to a `pelican` binary.
// If $TEST_PELICAN_BINARY is set,
// it must be the absolute path to an existing binary, which is used as is.
func GetPelicanBinary(t testing.TB) string {
	t.Helper()
	return pelicanBinary.get(t)
}

// GetPelicanServerBinary returns the path to a `pelican-server` binary.
// If $TEST_PELICAN_SERVER_BINARY is set,
// it must be the absolute path to an existing binary, which is used as is.
func GetPelicanServerBinary(t testing.TB) string {
	t.Helper()
	return pelicanServerBinary.get(t)
}

// GetSampleMetadataServerBinary returns the path to a `sample_metadata_server` binary.
// If $TEST_PELICAN_SAMPLE_METADATA_SERVER_BINARY is set,
// it must be the absolute path to an existing binary, which is used as is.
func GetSampleMetadataServerBinary(t testing.TB) string {
	t.Helper()
	return sampleMetadataServerBinary.get(t)
}

// RemoveTestBinaries removes the binaries built by this test process.
// Call it from TestMain after m.Run returns.
func RemoveTestBinaries() {
	binariesDirMu.Lock()
	defer binariesDirMu.Unlock()
	if binariesDir != "" {
		os.RemoveAll(binariesDir)
		binariesDir = ""
	}
}

func (b *testBinary) get(t testing.TB) string {
	t.Helper()
	b.once.Do(func() {
		var ok bool
		if b.path, ok, b.err = lookupPrebuiltBinary(b.envVar); !ok && b.err == nil {
			b.path, b.err = b.build()
		}
	})
	if b.err != nil {
		t.Fatalf("Failed to get the %s binary: %v", b.name, b.err)
	}
	return b.path
}

// lookupPrebuiltBinary returns the path named by envVar, if it is set.
// It is an error for the path to be relative
// (tests run from their package's directory) or to not exist.
func lookupPrebuiltBinary(envVar string) (path string, ok bool, err error) {
	path, ok = os.LookupEnv(envVar)
	if !ok {
		return "", false, nil
	}
	if !filepath.IsAbs(path) {
		return "", true, fmt.Errorf("$%s is not an absolute path: %q", envVar, path)
	}
	if _, err := os.Stat(path); err != nil {
		return "", true, fmt.Errorf("$%s does not name a usable file: %w", envVar, err)
	}
	return path, true, nil
}

func (b *testBinary) build() (string, error) {
	dir, err := getBinariesDir()
	if err != nil {
		return "", err
	}
	name := b.name
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)

	// -buildvcs=false: the CI test container checks out the repo
	// as a different owner than the build user,
	// so git refuses to run ("dubious ownership", exit 128)
	// and VCS stamping fails.
	// No version stamp is needed on a throwaway test binary.
	args := []string{"build", "-buildvcs=false", "-o", path}
	if b.tags != "" {
		args = append(args, "-tags", b.tags)
	}
	args = append(args, b.pkg)
	if output, err := exec.Command("go", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w\nOutput: %s", err, output)
	}
	return path, nil
}

func getBinariesDir() (string, error) {
	binariesDirMu.Lock()
	defer binariesDirMu.Unlock()
	if binariesDir == "" {
		dir, err := os.MkdirTemp("", "pelican-test-binaries-*")
		if err != nil {
			return "", err
		}
		binariesDir = dir
	}
	return binariesDir, nil
}
