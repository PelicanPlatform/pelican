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
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDryRunFlagExists verifies that the --dry-run flag is available for object commands
func TestDryRunFlagExists(t *testing.T) {
	// Check object get
	cmd := getCmd
	flag := cmd.Flags().Lookup("dry-run")
	assert.NotNil(t, flag, "object get should have --dry-run flag")
	assert.Equal(t, "bool", flag.Value.Type(), "--dry-run should be a boolean flag")

	// Check object put
	cmd = putCmd
	flag = cmd.Flags().Lookup("dry-run")
	assert.NotNil(t, flag, "object put should have --dry-run flag")
	assert.Equal(t, "bool", flag.Value.Type(), "--dry-run should be a boolean flag")

	// Check object sync
	cmd = syncCmd
	flag = cmd.Flags().Lookup("dry-run")
	assert.NotNil(t, flag, "object sync should have --dry-run flag")
	assert.Equal(t, "bool", flag.Value.Type(), "--dry-run should be a boolean flag")
}

// TestDryRunHelpText verifies that the --dry-run flag appears in help text
func TestDryRunHelpText(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		helpCmd func(t *testing.T) string
	}{
		{
			name: "object get",
			cmd:  "object get",
			helpCmd: func(t *testing.T) string {
				old := os.Stdout
				r, w, err := os.Pipe()
				require.NoError(t, err)
				os.Stdout = w
				defer func() { os.Stdout = old }()

				require.NoError(t, getCmd.Help())

				require.NoError(t, w.Close())
				var buf bytes.Buffer
				_, err = io.Copy(&buf, r)
				require.NoError(t, err)
				require.NoError(t, r.Close())
				return buf.String()
			},
		},
		{
			name: "object put",
			cmd:  "object put",
			helpCmd: func(t *testing.T) string {
				old := os.Stdout
				r, w, err := os.Pipe()
				require.NoError(t, err)
				os.Stdout = w
				defer func() { os.Stdout = old }()

				require.NoError(t, putCmd.Help())

				require.NoError(t, w.Close())
				var buf bytes.Buffer
				_, err = io.Copy(&buf, r)
				require.NoError(t, err)
				require.NoError(t, r.Close())
				return buf.String()
			},
		},
		{
			name: "object sync",
			cmd:  "object sync",
			helpCmd: func(t *testing.T) string {
				old := os.Stdout
				r, w, err := os.Pipe()
				require.NoError(t, err)
				os.Stdout = w
				defer func() { os.Stdout = old }()

				require.NoError(t, syncCmd.Help())

				require.NoError(t, w.Close())
				var buf bytes.Buffer
				_, err = io.Copy(&buf, r)
				require.NoError(t, err)
				require.NoError(t, r.Close())
				return buf.String()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helpText := tt.helpCmd(t)
			assert.Contains(t, helpText, "--dry-run", "%s help should mention --dry-run flag", tt.cmd)
			// Verify the help text describes what dry-run does
			lowerHelp := strings.ToLower(helpText)
			assert.True(t,
				strings.Contains(lowerHelp, "without actually") ||
					strings.Contains(lowerHelp, "show what") ||
					strings.Contains(lowerHelp, "preview"),
				"%s --dry-run help should describe what it does", tt.cmd)
		})
	}
}
