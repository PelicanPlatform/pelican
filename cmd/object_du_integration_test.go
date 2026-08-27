//go:build client && !windows

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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestObjectDuCLI drives the compiled `pelican object du` binary against a
// POSIXv2 fed so both the client-side listing plumbing and the du command's
// aggregation are exercised end-to-end. POSIXv2 is used deliberately: the CI
// worker doesn't need XRootD to run this test.
func TestObjectDuCLI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	cliPath := getPelicanBinary(t)

	// Bring up a POSIXv2 fed with a public export at /test that supports
	// recursive listings (required for du to walk anything at all).
	ft := fed_test_utils.NewFedTest(t, walkStreamingOriginConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// Populate a tree with known sizes so the arithmetic is deterministic.
	// Layout under storage/:
	//   file_a.txt          10 bytes
	//   sub/nested.txt      40 bytes
	//   sub/deeper/deep.txt 100 bytes
	//
	// Root total = 150. sub/ total = 140. sub/deeper/ total = 100.
	// NewFedTest also drops a hello_world.txt (13 bytes) at the storage root
	// which the totals below account for.
	storage := ft.Exports[0].StoragePrefix
	require.NoError(t, os.WriteFile(filepath.Join(storage, "file_a.txt"),
		[]byte("aaaaaaaaaa"), 0o644))
	sub := filepath.Join(storage, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.txt"),
		[]byte(strings.Repeat("n", 40)), 0o644))
	deeper := filepath.Join(sub, "deeper")
	require.NoError(t, os.Mkdir(deeper, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(deeper, "deep.txt"),
		[]byte(strings.Repeat("d", 100)), 0o644))

	// hello_world.txt exists at storage root by NewFedTest convention.
	const helloBytes = int64(len("Hello, World!"))
	wantRoot := int64(10+40+100) + helloBytes
	wantSub := int64(40 + 100)
	wantDeeper := int64(100)

	// Persist the current in-process config for the child pelican binary so it
	// resolves the same federation / discovery / TLS material we're serving.
	configPath := filepath.Join(t.TempDir(), "pelican.yaml")
	require.NoError(t, viper.WriteConfigAs(configPath), "write child config")

	rootURL := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	runDu := func(t *testing.T, extraArgs ...string) (stdout, stderr string) {
		t.Helper()
		args := append([]string{"object", "du"}, extraArgs...)
		args = append(args, rootURL)
		cmd := exec.CommandContext(ft.Ctx, cliPath, args...)
		cmd.Env = append(os.Environ(), "PELICAN_CONFIG="+configPath)
		var out, errBuf strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		require.NoError(t, cmd.Run(), "pelican object du failed:\nstdout: %s\nstderr: %s", out.String(), errBuf.String())
		return out.String(), errBuf.String()
	}

	// findDuRow returns the size column for the row whose trailing path
	// matches want. tabwriter expands the intra-row tab into spaces before
	// output reaches us, so instead of splitting on tabs we take everything
	// before the trailing path as the size column -- which also tolerates
	// sizes that themselves contain a space (e.g. "163 B" from -h).
	findDuRow := func(out, want string) (size string, ok bool) {
		for _, raw := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			line := strings.TrimSpace(raw)
			if !strings.HasSuffix(line, want) {
				continue
			}
			return strings.TrimRight(strings.TrimSuffix(line, want), " \t"), true
		}
		return "", false
	}
	requireDuRow := func(t *testing.T, out, want string) string {
		t.Helper()
		size, ok := findDuRow(out, want)
		require.True(t, ok, "du row for %q missing from stdout:\n%s", want, out)
		return size
	}

	t.Run("default-recursive-breakdown", func(t *testing.T) {
		stdout, _ := runDu(t)
		// Numeric totals against paths we planted.
		gotBytes, err := strconv.ParseInt(requireDuRow(t, stdout, rootURL), 10, 64)
		require.NoError(t, err)
		assert.Equal(t, wantRoot, gotBytes)

		gotBytes, err = strconv.ParseInt(requireDuRow(t, stdout, "/test/sub"), 10, 64)
		require.NoError(t, err)
		assert.Equal(t, wantSub, gotBytes)

		gotBytes, err = strconv.ParseInt(requireDuRow(t, stdout, "/test/sub/deeper"), 10, 64)
		require.NoError(t, err)
		assert.Equal(t, wantDeeper, gotBytes)
	})

	t.Run("summarize-prints-only-the-argument-total", func(t *testing.T) {
		stdout, _ := runDu(t, "-s")
		size := requireDuRow(t, stdout, rootURL)
		gotBytes, err := strconv.ParseInt(size, 10, 64)
		require.NoError(t, err)
		assert.Equal(t, wantRoot, gotBytes)

		for _, p := range []string{"/test/sub", "/test/sub/deeper"} {
			_, present := findDuRow(stdout, p)
			assert.False(t, present, "-s output must not include interior row %q", p)
		}
	})

	t.Run("human-readable-formats-bytes", func(t *testing.T) {
		stdout, _ := runDu(t, "-s", "-h")
		size := requireDuRow(t, stdout, rootURL)
		// Root is 163 bytes; humanize.IBytes yields something like "163 B".
		// Verify the size column no longer parses as a plain integer, which
		// is the observable difference from the default output.
		_, err := strconv.ParseInt(size, 10, 64)
		assert.Error(t, err, "with -h the size column must not be a plain integer, got %q", size)
		assert.NotEmpty(t, size)
	})

	t.Run("json-output-round-trips", func(t *testing.T) {
		stdout, _ := runDu(t, "--json")
		// The JSON payload is a single-line array printed by
		// object_du.duMain. Extract it from the surrounding stdout noise.
		var payload []byte
		for _, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				payload = []byte(trimmed)
				break
			}
		}
		require.NotEmpty(t, payload, "could not locate du JSON payload in stdout:\n%s", stdout)

		var reports []struct {
			Path        string `json:"path"`
			Bytes       int64  `json:"bytes"`
			Objects     int64  `json:"objects,omitempty"`
			Collections int64  `json:"collections,omitempty"`
		}
		require.NoError(t, json.Unmarshal(payload, &reports))
		byPath := map[string]int64{}
		for _, r := range reports {
			byPath[r.Path] = r.Bytes
		}
		assert.Equal(t, wantRoot, byPath[rootURL])
		assert.Equal(t, wantSub, byPath["/test/sub"])
		assert.Equal(t, wantDeeper, byPath["/test/sub/deeper"])
	})
}
