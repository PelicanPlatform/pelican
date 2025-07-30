//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package config

import (
	"os"
	"syscall"
)

func fixRootDirectory(p string) string {
	return p
}

// Check if the given path has the correct ownership on Unix systems
func checkOwnership(info os.FileInfo, expectedUid int, expectedGid int) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid) == expectedUid && int(stat.Gid) == expectedGid
	}
	// If we can't get ownership info, assume we need to set it
	return false
}
