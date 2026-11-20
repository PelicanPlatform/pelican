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

package server_structs

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileTargetRoundTrip: a directory's path survives the header whatever
// it contains, and a value that does not name one is refused.
func TestFileTargetRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file targets name POSIX paths")
	}
	for _, root := range []string{
		"/mnt/shared/pelican-cache",
		"/mnt/a dir/with&an=odd;name,and%25more",
		"/",
	} {
		want := FileTarget{Root: root, Inode: 1835012, ID: "0b1e6c1a-4a8e-4d47-9a51-3f3f5b1c2d10"}
		got, err := ParseFileTarget(want.String())
		require.NoError(t, err, root)
		assert.Equal(t, want, got)
	}

	for name, value := range map[string]string{
		"empty":         "",
		"relative root": "root=mnt%2Fshared&inode=1&id=x",
		"unclean root":  "root=%2Fmnt%2F..%2Fetc&inode=1&id=x",
		"no inode":      "root=%2Fmnt&id=x",
		"zero inode":    "root=%2Fmnt&inode=0&id=x",
		"bad inode":     "root=%2Fmnt&inode=-1&id=x",
		"no ID":         "root=%2Fmnt&inode=1",
		"not a query":   "root=%zz",
	} {
		_, err := ParseFileTarget(value)
		assert.Error(t, err, name)
	}
}
