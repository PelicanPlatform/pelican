/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"runtime"
	"strings"
	"sync"
	"time"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

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
			"no-flag-on-subcommand",
			[]string{"pelican", "origin"},
			originCmd.Short,
		},
		{
			"flag-on-root-command",
			[]string{"pelican", "--version"},
			mockVersionOutput,
		},
		{
			"flag-on-subcommand",
			[]string{"pelican", "origin", "--version"},
			mockVersionOutput,
		},
		{
			"flag-on-second-layer-subcommand",
			[]string{"pelican", "origin", "get", "--version"},
			mockVersionOutput,
		},
		{
			"other-flag-on-root-command",
			[]string{"pelican", "--help"},
			rootCmd.Long,
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

func TestHandleCLIExecutableAlias(t *testing.T) {
	aliasTestMutex := sync.Mutex{} // Lock to ensure each t.Run goroutine have consistent access to binary

	// If we're in the process started by exec.Command, run the handleCLI function.
	if os.Getenv("BE_CRASHER") == "1" {
		err := handleCLI(os.Args[1:])
		if err != nil {
			t.Fatalf("Function returns error")
		}
		return
	} else {
		// Compile the test binary.
		if runningOS := runtime.GOOS; runningOS == "windows" {
			cmd := exec.Command("go", "build", "-o", "pelican.exe", ".")
			err := cmd.Run()
			if err != nil {
				t.Fatal(err, "Error copying the binary to pelican.exe")
			}
			defer os.Remove("pelican.exe") // Clean up the test binary when done.
		} else {
			cmd := exec.Command("go", "build", "-o", "pelican", ".")
			err := cmd.Run()
			if err != nil {
				t.Fatal(err, "Error copying the binary to pelican")
			}
			defer os.Remove("pelican") // Clean up the test binary when done.
		}
	}

	oldArgs := os.Args
	os.Args = []string{}
	defer func() {
		os.Args = oldArgs
	}()
	testCases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			"no-alias",
			[]string{"pelican"},
			rootCmd.Long,
		},
		{
			"stashcp",
			[]string{"stashcp"},
			"No Source or Destination", // slightly different error message, good for testing though
		},
		{
			"stash_plugin",
			[]string{"stash_plugin"},
			"No source or destination specified",
		},
		{
			"osdf_plugin",
			[]string{"stash_plugin"},
			"No source or destination specified",
		},
		{
			"pelican_xfer_plugin",
			[]string{"stash_plugin"},
			"No source or destination specified",
		},
	}

	cleanupBinary := func(name string) {
		err := os.Remove(name) // Clean up the test binary when done.
		assert.NoError(t, err, "No binary to remove for "+name)
		waitDuration := time.Tick(100 * time.Millisecond)
		times := 3
		for times > 0 {
			<-waitDuration
			_, err := os.Stat(name)
			if err != nil { // Ensure that the binary was successfully removed
				return
			} else {
				times--
			}
		}
		t.Error("Failed to remove binary after 300ms for ", name)
	}

	batchTest := func(t *testing.T, arguments []string, expected string) {
		aliasTestMutex.Lock()
		defer aliasTestMutex.Unlock()

		if _, err := os.Stat(arguments[0]); err != nil { // Binary not found, copy it
			if runningOS := runtime.GOOS; runningOS == "windows" {
				if err := exec.Command("cp", "pelican.exe", arguments[0]).Run(); err != nil {
					t.Fatal(err, "Error copying the binary to "+arguments[0])
				}
				defer cleanupBinary(arguments[0])
			} else {
				if err := exec.Command("cp", "pelican", arguments[0]).Run(); err != nil {
					t.Fatal(err, "Error copying the binary to "+arguments[0])
				}
				defer cleanupBinary(arguments[0])
			}
		}

		// Run the test binary with the BE_CRASHER environment variable set.
		cmd := exec.Command("./"+arguments[0], arguments[1:]...)
		cmd.Env = append(os.Environ(), "BE_CRASHER=1")

		// Set up pipes to capture stdout and stderr.
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		// Read and capture stdout and stderr.
		gotBytes, _ := io.ReadAll(stdout)
		errBytes, _ := io.ReadAll(stderr)

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
		if strings.ToLower(strings.TrimSuffix(arguments[0], ".exe")) != "pelican" {
			assert.Contains(t, errString, expected, "Output does not match expectation")
		} else {
			assert.NoError(t, err, "Should not have error running the function: "+errString)
			assert.Contains(t, got, expected, "Output does not match expectation")
		}
	}
	for _, tc := range testCases {
		if os := runtime.GOOS; os == "windows" {
			// On Windows, you can only do *.exe
			t.Run(tc.name+"-windows", func(t *testing.T) {
				preserve := tc.args[0]
				tc.args[0] = preserve + ".exe"
				batchTest(t, tc.args, tc.expected)
				tc.args[0] = preserve
			})
		} else {
			t.Run(tc.name, func(t *testing.T) {
				batchTest(t, tc.args, tc.expected)
			})
			t.Run(tc.name+"-windows", func(t *testing.T) {
				preserve := tc.args[0]
				tc.args[0] = preserve + ".exe"
				batchTest(t, tc.args, tc.expected)
				tc.args[0] = preserve
			})
			t.Run(tc.name+"-mixedCase", func(t *testing.T) {
				preserve := tc.args[0]
				tc.args[0] = strings.ToUpper(preserve)
				batchTest(t, tc.args, tc.expected)
				tc.args[0] = preserve
			})
		}
	}
}
