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

//go:build !windows

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFilesystemUsage(t *testing.T) {
	// Test with /tmp which should always exist
	usage, totalBytes, usedBytes, err := getFilesystemUsage("/tmp")
	
	require.NoError(t, err, "Should successfully get filesystem usage for /tmp")
	assert.GreaterOrEqual(t, usage, 0.0, "Usage percentage should be non-negative")
	assert.LessOrEqual(t, usage, 100.0, "Usage percentage should not exceed 100")
	assert.Greater(t, totalBytes, uint64(0), "Total bytes should be positive")
	assert.LessOrEqual(t, usedBytes, totalBytes, "Used bytes should not exceed total bytes")
	
	t.Logf("Filesystem usage for /tmp: %.2f%% (%d/%d bytes)", usage, usedBytes, totalBytes)
}

func TestGetFilesystemUsageInvalidPath(t *testing.T) {
	_, _, _, err := getFilesystemUsage("/nonexistent/path/that/does/not/exist")
	assert.Error(t, err, "Should return error for non-existent path")
}
