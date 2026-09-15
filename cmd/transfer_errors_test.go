//go:build client

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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/error_codes"
)

// TestClassifyTransferFailureExitCodes pins the exit code each error class
// maps to. Before this was fixed the commands recovered the PelicanError with
// errors.Is against a freshly declared value, which never matched, so every
// classified failure exited 1 -- a permission denial was indistinguishable
// from a usage error.
func TestClassifyTransferFailureExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantMsg  string
	}{
		{
			name:     "authorization error keeps its own exit code",
			err:      errors.Wrap(error_codes.NewAuthorizationError(errors.New("Permission denied: not authorized")), "failed download"),
			wantCode: 7,
			wantMsg:  "Authorization Error: Error code 4000: Permission denied: not authorized",
		},
		{
			name:     "director contact error keeps its own exit code",
			err:      errors.Wrap(error_codes.NewContact_DirectorError(errors.New("404: no sources found")), "failed download"),
			wantCode: 6,
			wantMsg:  "Contact.Director Error: Error code 3001: 404: no sources found",
		},
		{
			name:     "specification error keeps its own exit code",
			err:      error_codes.NewSpecification_FileNotFoundError(errors.New("no such object")),
			wantCode: 8,
			wantMsg:  "Specification.FileNotFound Error: Error code 5011: no such object",
		},
		{
			name:     "unclassified error falls back to 1",
			err:      errors.New("something went sideways"),
			wantCode: 1,
			wantMsg:  "something went sideways",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := classifyTransferFailure(tc.err)
			assert.Equal(t, tc.wantCode, code)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

// TestPelicanErrorRequiresAs guards the reason classifyTransferFailure uses
// errors.As. If someone gives PelicanError an Is method to make the old
// comparison work, the target stays the zero value and its ExitCode() is 0 --
// the command would report success for a failed transfer.
func TestPelicanErrorRequiresAs(t *testing.T) {
	wrapped := errors.Wrap(error_codes.NewAuthorizationError(errors.New("Permission denied")), "failed download")

	var peVal error_codes.PelicanError
	require.False(t, errors.Is(wrapped, &peVal),
		"errors.Is cannot recover a PelicanError; use errors.As")
	assert.Equal(t, 0, peVal.ExitCode(),
		"a zero-value PelicanError exits 0, which is why Is must not be made to match here")

	var pePtr *error_codes.PelicanError
	require.True(t, errors.As(wrapped, &pePtr))
	assert.Equal(t, 7, pePtr.ExitCode())
}

// TestFatalErrorReachesUser covers the other half of a silent failure: with
// Logging.LogLocation set, log output is redirected to the file, so a fatal
// error reached neither the terminal nor -- because os.Exit runs no defers and
// the async log writer never drained -- the log file itself.
func TestFatalErrorReachesUser(t *testing.T) {
	binaryPath := getPelicanBinary(t)
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "pelican.log")

	// "object get" with a single argument is a usage failure: it exits through
	// the same reporting path as a transfer failure without needing a network.
	cmd := exec.Command(binaryPath, "object", "get", "onearg")
	cmd.Env = append(os.Environ(),
		"PELICAN_LOGGING_LOGLOCATION="+logFile,
		"PELICAN_CONFIGDIR="+filepath.Join(tempDir, "config"),
	)
	stderr, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "expected a non-zero exit")
	assert.NotEqual(t, 0, exitErr.ExitCode())

	assert.Contains(t, string(stderr), "No Source or Destination",
		"the reason for the exit must reach the terminal even when logs go to a file")

	logData, readErr := os.ReadFile(logFile)
	require.NoError(t, readErr, "the log file should exist")
	assert.Contains(t, string(logData), "No Source or Destination",
		"the log writer must drain before the process exits")
}
