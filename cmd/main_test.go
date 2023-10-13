package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleCLIVersionFlag(t *testing.T) {
	version = "0.0.1"
	date = "2023-10-06T15:26:50Z"
	commit = "f0f94a3edf6641c2472345819a0d5453fc9e68d1"
	builtBy = "goreleaser"

	// Reset os.Args to ensure Windows doesn't do weird things to the test
	oldArgs := os.Args
	os.Args = []string{os.Args[0]}

	mockVersionOutput := fmt.Sprintf(
		"Version: %s\nBuild Date: %s\nBuild Commit: %s\nBuilt By: %s",
		version, date, commit, builtBy,
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
		// Redirect output to a pip
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := handleCLI(arguments)

		// Close the write of pip and redirect output back to stdout
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stdout = oldStdout

		got := strings.TrimSpace(string(out))
		assert.NoError(t, err, "Should not have error running the function")
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

	// Restore the args back when test finished
	os.Args = oldArgs
}

func TestHandleCLIExecutableAlias(t *testing.T) {
	// If we're in the process started by exec.Command, run the handleCLI function.
	if os.Getenv("BE_CRASHER") == "1" {
		handleCLI(os.Args[1:])
		return
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

	batchTest := func(t *testing.T, arguments []string, expected string) {
		// Compile the test binary.
		cmd := exec.Command("go", "build", "-o", arguments[0], ".")
		err := cmd.Run()
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(arguments[0]) // Clean up the test binary when done.

		// Run the test binary with the BE_CRASHER environment variable set.
		cmd = exec.Command("./"+arguments[0], arguments[1:]...)
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
		err = cmd.Wait()

		got := strings.TrimSpace(string(gotBytes))
		errString := strings.TrimSpace(string(errBytes))

		// Now you can check the output and the error against your expectations.
		// If the command exited with a non-zero status, 'err' will be non-nil.
		if err != nil {
			_, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("Failed to cast error as *exec.ExitError")
			}
			// Here you might want to check the exit code if it's relevant to your test.
			// exitCode := exitError.ExitCode()
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
