//go:build !windows

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
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// FileOwner returns the UID and GID of the file at path.
func FileOwner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err, "stat %s", path)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok, "Sys() did not return *syscall.Stat_t for %s", path)
	return st.Uid, st.Gid
}
