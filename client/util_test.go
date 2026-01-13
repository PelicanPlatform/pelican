/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package client

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomSuffix(t *testing.T) {
	suffix := generateRandomSuffix(6)

	// Test that it produces exactly 6 characters
	assert.Equal(t, 6, len(suffix), "Suffix should be 6 characters long")

	// Test that it only contains alphanumeric characters
	alphanumericPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	assert.True(t, alphanumericPattern.MatchString(suffix), "Suffix should only contain alphanumeric characters")
}

func TestGenerateRandomSuffixOnlyAlphanumeric(t *testing.T) {
	// Generate multiple suffixes to ensure consistency
	for i := 0; i < 100; i++ {
		suffix := generateRandomSuffix(6)
		for _, char := range suffix {
			assert.True(t,
				(char >= 'a' && char <= 'z') ||
					(char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9'),
				"Character '%c' should be alphanumeric", char)
		}
	}
}

func TestGenerateRandomSuffixDifferentLengths(t *testing.T) {
	testCases := []int{1, 6, 10, 20}

	for _, length := range testCases {
		suffix := generateRandomSuffix(length)
		assert.Equal(t, length, len(suffix), "Suffix should be %d characters long", length)
	}
}

func TestGenerateTempPath(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedDir    string
		expectedPrefix string
	}{
		{
			name:           "simple filename",
			input:          "/tmp/testfile.txt",
			expectedDir:    "/tmp",
			expectedPrefix: ".testfile.txt.",
		},
		{
			name:           "filename without extension",
			input:          "/var/data/myfile",
			expectedDir:    "/var/data",
			expectedPrefix: ".myfile.",
		},
		{
			name:           "filename with multiple dots",
			input:          "/home/user/archive.tar.gz",
			expectedDir:    "/home/user",
			expectedPrefix: ".archive.tar.gz.",
		},
		{
			name:           "current directory",
			input:          "localfile.dat",
			expectedDir:    ".",
			expectedPrefix: ".localfile.dat.",
		},
		{
			name:           "nested directories",
			input:          "/very/deep/nested/path/file.bin",
			expectedDir:    "/very/deep/nested/path",
			expectedPrefix: ".file.bin.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert paths to platform-specific format (handles Windows)
			input := filepath.FromSlash(tt.input)
			expectedDir := filepath.FromSlash(tt.expectedDir)

			tempPath := generateTempPath(input)

			// Verify the directory part is correct
			dir := filepath.Dir(tempPath)
			assert.Equal(t, expectedDir, dir, "Directory should match")

			// Verify the base name follows rsync pattern: .filename.XXXXXX
			base := filepath.Base(tempPath)
			assert.True(t, strings.HasPrefix(base, tt.expectedPrefix),
				"Base name should start with '%s', got '%s'", tt.expectedPrefix, base)

			// Verify the suffix is 6 characters
			parts := strings.Split(base, ".")
			require.GreaterOrEqual(t, len(parts), 2, "Should have at least 2 parts after splitting by '.'")
			suffix := parts[len(parts)-1]
			assert.Equal(t, 6, len(suffix), "Random suffix should be 6 characters")

			// Verify suffix is alphanumeric
			alphanumericPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
			assert.True(t, alphanumericPattern.MatchString(suffix),
				"Suffix should only contain alphanumeric characters")
		})
	}
}

func TestGenerateTempPathUniqueness(t *testing.T) {
	// Generate multiple temp paths for the same file and verify they're unique
	input := "/tmp/testfile.txt"
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		tempPath := generateTempPath(input)
		assert.False(t, seen[tempPath], "Generated path should be unique")
		seen[tempPath] = true
	}
}

func TestGenerateTempPathFormat(t *testing.T) {
	input := filepath.FromSlash("/data/myfile.dat")
	tempPath := generateTempPath(input)

	// Expected format: {separator}data{separator}.myfile.dat.XXXXXX
	// Where XXXXXX is 6 alphanumeric characters
	// Use filepath to construct platform-specific pattern
	expectedDir := filepath.FromSlash("/data")
	expectedBase := `.myfile\.dat\.[a-zA-Z0-9]{6}`
	pattern := regexp.MustCompile(fmt.Sprintf(`^%s%c%s$`, regexp.QuoteMeta(expectedDir), filepath.Separator, expectedBase))
	assert.True(t, pattern.MatchString(tempPath),
		"Temp path should match rsync pattern, got: %s", tempPath)
}
