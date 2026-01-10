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

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeUploadDestPath(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string
		basePath   string
		expected   string
	}{
		{
			name:       "No base path from director",
			remotePath: "/test/file.txt",
			basePath:   "/",
			expected:   "/test/file.txt",
		},
		{
			name:       "Director returns full object path (POSIXv2 case)",
			remotePath: "/test/large_file.bin",
			basePath:   "/api/v1.0/origin/data/test/large_file.bin",
			expected:   "/api/v1.0/origin/data/test/large_file.bin",
		},
		{
			name:       "Remote path already contains base path (sync upload case)",
			remotePath: "/first/namespace/sync_upload_none/008/test1.txt",
			basePath:   "/first/namespace/sync_upload_none/008",
			expected:   "/first/namespace/sync_upload_none/008/test1.txt",
		},
		{
			name:       "Remote path in subdirectory already contains base path",
			remotePath: "/first/namespace/sync_upload_none/008/InnerDir/test.txt",
			basePath:   "/first/namespace/sync_upload_none/008",
			expected:   "/first/namespace/sync_upload_none/008/InnerDir/test.txt",
		},
		{
			name:       "Base path needs to be prepended",
			remotePath: "/object.txt",
			basePath:   "/api/v1.0/origin/data",
			expected:   "/api/v1.0/origin/data/object.txt",
		},
		{
			name:       "Empty base path",
			remotePath: "/test/file.txt",
			basePath:   "",
			expected:   "/test/file.txt",
		},
		{
			name:       "Base path with trailing slash",
			remotePath: "/file.txt",
			basePath:   "/prefix/",
			expected:   "/prefix/file.txt",
		},
		{
			name:       "Remote path without leading slash",
			remotePath: "file.txt",
			basePath:   "/prefix",
			expected:   "/prefix/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeUploadDestPath(tt.remotePath, tt.basePath)
			assert.Equal(t, tt.expected, result)
		})
	}
}
