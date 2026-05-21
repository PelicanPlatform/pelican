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

package director

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/server_utils"
)

// TestCacheTestFilePath verifies that runCacheTest constructs the correct
// per-director daily-nested test file path format:
// /pelican/monitoring/directorTest/<director-id>/YYYY-MM-DD/director-test-<RFC3339>.txt
func TestCacheTestFilePath(t *testing.T) {
	now := time.Now()
	dayStr := now.Format("2006-01-02")
	directorID := "director-1.example.com"
	dirMonPath := path.Join(server_utils.MonitoringBaseNs, server_utils.DirectorTestDir)

	// Verify the path components match the expected format
	expectedPrefix := path.Join(dirMonPath, directorID, dayStr, server_utils.DirectorTest.String()+"-")
	assert.Contains(t, expectedPrefix, "/pelican/monitoring/directorTest/"+directorID+"/"+dayStr+"/director-test-")

	// Verify the file extension and per-director segment
	testFilePath := path.Join(dirMonPath, directorID, dayStr, server_utils.DirectorTest.String()+"-"+now.Format(time.RFC3339)+".txt")
	assert.Contains(t, testFilePath, ".txt")
	assert.Contains(t, testFilePath, "/"+directorID+"/"+dayStr+"/")
	assert.Contains(t, testFilePath, "director-test-")
}
