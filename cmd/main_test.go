package main

import (
	"fmt"
	"io"
	"os"
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
}
