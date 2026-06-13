//go:build !unix

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

import "github.com/pkg/errors"

// getDiskUsage is unsupported on non-unix platforms. The Pelican cache (the
// only consumer of lot disk-space discovery) runs on unix; this stub lets the
// package compile elsewhere so the lot engine and REST API remain available.
func getDiskUsage(path string) (total uint64, free uint64, err error) {
	return 0, 0, errors.New("disk usage discovery is not supported on this platform")
}
