/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/config"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestReadMultiTransfer test if we can read multiple transfers from stdin
func TestReadMultiTransfer(t *testing.T) {
	t.Parallel()

	// Test with multiple transfers
	stdin := "[ LocalFileName = \"/path/to/local/copy/of/foo\"; Url = \"url://server/some/directory//foo\" ]\n[ LocalFileName = \"/path/to/local/copy/of/bar\"; Url = \"url://server/some/directory//bar\" ]\n[ LocalFileName = \"/path/to/local/copy/of/qux\"; Url = \"url://server/some/directory//qux\" ]"
	transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(transfers))
	assert.Equal(t, "/path/to/local/copy/of/foo", transfers[0].localFile)
	assert.Equal(t, "url://server/some/directory//foo", transfers[0].url)
	assert.Equal(t, "/path/to/local/copy/of/bar", transfers[1].localFile)
	assert.Equal(t, "url://server/some/directory//bar", transfers[1].url)
	assert.Equal(t, "/path/to/local/copy/of/qux", transfers[2].localFile)
	assert.Equal(t, "url://server/some/directory//qux", transfers[2].url)

	// Test with single transfers
	stdin = "[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
	transfers, err = readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "url://server/some/directory//blah", transfers[0].url)
	assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].localFile)
}

func TestStashPluginMain(t *testing.T) {
	viper.Reset()
	config.SetPreferredPrefix("STASH")

	// Temp dir for downloads
	tempDir := os.TempDir()
	defer os.Remove(tempDir)

	// Parts of test adapted from: https://stackoverflow.com/questions/26225513/how-to-test-os-exit-scenarios-in-go
	if os.Getenv("RUN_STASHPLUGIN") == "1" {
		// Download a test file
		args := []string{"osdf:///osgconnect/public/osg/testfile.txt", tempDir}
		stashPluginMain(args)
		os.Unsetenv("STASH_LOGGING_LEVEL")
		os.Unsetenv("RUN_STASHPLUGIN")
		return
	}

	// Create a process to run the command (since stashPluginMain calls os.Exit(0))
	cmd := exec.Command(os.Args[0], "-test.run=TestStashPluginMain")
	cmd.Env = append(os.Environ(), "RUN_STASHPLUGIN=1", "STASH_LOGGING_LEVEL=debug")

	// Create buffers for stderr (the output we want for test)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	assert.NoError(t, err, stderr.String())

	// changing output for "\\" since in windows there are excess "\" printed in debug logs
	output := strings.Replace(stderr.String(), "\\\\", "\\", -1)

	expectedOutput := "Downloading: osdf:///osgconnect/public/osg/testfile.txt to " + tempDir
	assert.Contains(t, output, expectedOutput)
}
