//go:build linux

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

import (
	"os/user"
	"testing"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// SkipUnlessPrivileged skips the test if the process lacks CAP_SETUID or
// CAP_SETGID in its effective capability set.
func SkipUnlessPrivileged(t *testing.T) {
	t.Helper()

	curSet := cap.GetProc()
	if curSet == nil {
		t.Skip("cannot query process capabilities")
	}

	for _, c := range []cap.Value{cap.SETUID, cap.SETGID} {
		enabled, err := curSet.GetFlag(cap.Effective, c)
		if err != nil || !enabled {
			t.Skipf("missing capability %v in effective set", c)
		}
	}
}

// SkipUnlessTestUsers skips the test if any of the given usernames cannot
// be resolved via the system user database.
func SkipUnlessTestUsers(t *testing.T, usernames ...string) {
	t.Helper()
	for _, name := range usernames {
		if _, err := user.Lookup(name); err != nil {
			t.Skipf("test user %q not found: %v", name, err)
		}
	}
}
