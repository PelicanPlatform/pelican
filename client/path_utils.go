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
	"path"
	"strings"
)

// computeUploadDestPath determines the final upload destination path based on:
// - remotePath: the per-file object path from the client request
// - basePath: the base path returned by the director (may include API prefix)
//
// The function handles several cases:
// 1. Director returns no base path (just "/"): use remotePath as-is
// 2. Director returns a full object path (basePath ends with remotePath): use basePath
// 3. Director returns a namespace root that remotePath already contains: use remotePath
// 4. Director returns a base that needs to be prepended to remotePath
func computeUploadDestPath(remotePath, basePath string) string {
	// Normalize paths
	remotePath = path.Clean("/" + strings.TrimPrefix(remotePath, "/"))
	basePath = path.Clean("/" + strings.Trim(strings.TrimSuffix(basePath, "/"), "/"))

	switch {
	case basePath == "/":
		// No base path from the director; just use the per-file path.
		return remotePath
	case strings.HasSuffix(basePath, remotePath):
		// The director already returned a fully qualified path (including the object);
		// use it as-is to avoid duplicating the remote path.
		return basePath
	case strings.HasPrefix(remotePath, basePath+"/"):
		// The per-file path already contains the director's base path; avoid re-appending.
		return remotePath
	case basePath != "" && basePath != "/":
		// Director provided a base path that is not present in the per-file path; prepend it.
		return path.Join(basePath, strings.TrimPrefix(remotePath, "/"))
	default:
		return remotePath
	}
}
