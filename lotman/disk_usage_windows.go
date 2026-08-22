//go:build windows

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

package lotman

import "golang.org/x/sys/windows"

// getDiskUsage reports total and free bytes for the volume backing path, using
// the Win32 GetDiskFreeSpaceEx call.
func getDiskUsage(path string) (total uint64, free uint64, err error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	// freeToCaller accounts for per-user quotas; totalFree is the raw volume
	// free space. Lot accounting wants the actual free bytes, so use totalFree.
	var freeToCaller, totalBytes, totalFree uint64
	if err = windows.GetDiskFreeSpaceEx(pathPtr, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, err
	}
	return totalBytes, totalFree, nil
}
