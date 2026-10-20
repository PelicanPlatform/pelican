//go:build client || server

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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cmd/config_printer"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestMain handles test setup and cleanup
func TestMain(m *testing.M) {
	code := m.Run()
	test_utils.RemoveTestBinaries()
	os.Exit(code)
}

func TestHandleCLIVersionFlag(t *testing.T) {
	// Save the current version to reset this variable
	currentVersion := config.GetVersion()
	currentDate := config.GetBuiltDate()
	currentCommit := config.GetBuiltCommit()
	currentBuiltBy := config.GetBuiltBy()
	// Reset os.Args to ensure Windows doesn't do weird things to the test
	oldArgs := os.Args

	config.SetVersion("0.0.1")
	config.SetBuiltDate("2023-10-06T15:26:50Z")
	config.SetBuiltCommit("f0f94a3edf6641c2472345819a0d5453fc9e68d1")
	config.SetBuiltBy("goreleaser")

	t.Cleanup(func() {
		// Restore the args back when test finished
		os.Args = oldArgs

		// Set the version back to what it was
		config.SetVersion(currentVersion)
		config.SetBuiltDate(currentDate)
		config.SetBuiltCommit(currentCommit)
		config.SetBuiltBy(currentBuiltBy)
	})

	os.Args = []string{os.Args[0]}

	mockVersionOutput := fmt.Sprintf(
		"Version: %s\nBuild Date: %s\nBuild Commit: %s\nBuilt By: %s",
		config.GetVersion(), config.GetBuiltDate(), config.GetBuiltCommit(), config.GetBuiltBy(),
	)

	testCases := []struct {
		name     string
		args     []string
		expected string
	}{
		// The choice of Long and Short is based on the current pattern we have
		// that only root command has Long description and Short description
		// for the rest of the subcommands
		{
			"no-flag-on-root-command",
			[]string{"pelican"},
			rootCmd.Long,
		},
		{
			"flag-on-root-command",
			[]string{"pelican", "--version"},
			mockVersionOutput,
		},
		{
			"other-flag-on-root-command",
			[]string{"pelican", "--help"},
			rootCmd.Long,
		},
		{
			"no-flag-on-subcommand",
			[]string{"pelican", "config"},
			config_printer.ConfigCmd.Short,
		},
		{
			"flag-on-subcommand",
			[]string{"pelican", "config", "--version"},
			mockVersionOutput,
		},
		{
			"flag-on-second-layer-subcommand",
			[]string{"pelican", "config", "get", "--version"},
			mockVersionOutput,
		},
	}

	batchTest := func(t *testing.T, arguments []string, expected string) {
		got := ""

		// Redirect output to a pipe
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := handleCLI(arguments)
		require.NoError(t, err)

		// Close the write of pipe and redirect output back to Stderr
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stdout = oldStdout

		got = strings.TrimSpace(string(out))

		if expected != mockVersionOutput {
			// If the expected string is not the version output, use Contains to check
			// This is mainly for checking against command help output
			assert.Contains(t, got, expected, "Output does not match expectation")
		} else {
			assert.Equal(t, expected, got, "Output does not match expectation")
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			batchTest(t, tc.args, tc.expected)
		})
	}
}

// copyExecutable copies the executable at src to dst, which must not exist.
func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	require.NoError(t, err)
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	require.NoError(t, copyErr)
	require.NoError(t, closeErr)
}

func TestHandleCLIExecutableAlias(t *testing.T) {
	// Isolate the test from system config
	t.Setenv("PELICAN_CONFIGDIR", t.TempDir())

	testCases := []struct {
		name     string
		execName string
		expected string
	}{
		{
			"no-alias",
			"pelican",
			rootCmd.Long,
		},
		{
			"stashcp",
			"stashcp",
			"No Source or Destination", // slightly different error message, good for testing though
		},
		{
			"stash_plugin",
			"stash_plugin",
			"No source or destination specified",
		},
		{
			"osdf_plugin",
			"osdf_plugin",
			"No source or destination specified",
		},
		{
			"pelican_xfer_plugin",
			"pelican_xfer_plugin",
			"No source or destination specified",
		},
		{
			"pelican_plugin",
			"pelican_plugin",
			"No source or destination specified",
		},
	}

	batchTest := func(t *testing.T, execName string, expected string) {
		// Alias dispatch looks only at the base name of the executable,
		// so run the copy from a directory of its own.
		// On Windows, removing the copy can fail for a short while,
		// likely because an antivirus scanner has it open.
		// TempDir's cleanup retries the removal for ~2 seconds.
		binary := filepath.Join(t.TempDir(), execName)
		copyExecutable(t, test_utils.GetPelicanBinary(t), binary)

		cmd := exec.Command(binary)

		// Set up pipes to capture stdout and stderr.
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		// Read stdout and stderr CONCURRENTLY. Reading one stream fully before
		// the other can deadlock: if the child fills the unread stream's pipe
		// buffer it blocks on write, while we block reading the first stream
		// that never reaches EOF. The stashcp/plugin aliases emit help text and
		// init logs to stderr, which on Windows (smaller pipe buffers) easily
		// exceeds the buffer and previously hung the test until the CI timeout.
		var gotBytes, errBytes []byte
		var readWg sync.WaitGroup
		readWg.Add(2)
		go func() {
			defer readWg.Done()
			gotBytes, _ = io.ReadAll(stdout)
		}()
		go func() {
			defer readWg.Done()
			errBytes, _ = io.ReadAll(stderr)
		}()
		readWg.Wait()

		// Wait for the command to finish.
		err := cmd.Wait()

		got := strings.TrimSpace(string(gotBytes))
		errString := strings.TrimSpace(string(errBytes))

		// Now you can check the output and the error against your expectations.
		// If the command exited with a non-zero status, 'err' will be non-nil.
		if err != nil {
			_, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("Failed to cast error as *exec.ExitError")
			}
		}
		// Apparently both stashcp and *_plug will trigger Exit(1) with error if
		// the arguments are not enough/solid
		if strings.ToLower(strings.TrimSuffix(execName, ".exe")) != "pelican" {
			assert.Contains(t, errString, expected, "Output does not match expectation")
		} else {
			assert.NoError(t, err, "Should not have error running the function: "+errString)
			assert.Contains(t, got, expected, "Output does not match expectation")
		}
	}
	for _, tc := range testCases {
		t.Run(tc.name+"-windows", func(t *testing.T) {
			batchTest(t, tc.execName+".exe", tc.expected)
		})
		if runtime.GOOS == "windows" {
			// On Windows, you can only do *.exe
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			batchTest(t, tc.execName, tc.expected)
		})
		t.Run(tc.name+"-mixedCase", func(t *testing.T) {
			batchTest(t, strings.ToUpper(tc.execName), tc.expected)
		})
	}
}
