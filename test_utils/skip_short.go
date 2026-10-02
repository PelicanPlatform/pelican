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

package test_utils

import "testing"

// SkipIfShort skips the calling test when "go test -short" is in effect.
//
// Reserve this for tests that take tens of seconds on their own or that need
// resources (sshd, minio, condor, multi-gigabyte uploads, child pelican
// processes), so that a -short run covers the quick tier only. Call it as the
// first statement of the test, before any setup starts.
func SkipIfShort(t testing.TB, reason string) {
	t.Helper()
	if testing.Short() {
		t.Skipf("skipped under -short (runs nightly): %s", reason)
	}
}
