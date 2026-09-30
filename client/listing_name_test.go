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
	"github.com/stretchr/testify/require"
)

func TestValidateListingName(t *testing.T) {
	t.Parallel()

	accept := []string{"file.txt", "..hidden", "a..b", ".hidden", "with space", "unicode-é"}
	for _, name := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			assert.NoError(t, validateListingName(name))
		})
	}

	reject := map[string]string{
		"empty":     "",
		"dot":       ".",
		"dot-dot":   "..",
		"slash":     "a/b",
		"backslash": `a\b`,
		"nul":       "a\x00b",
		"leading":   "/abs",
		"traversal": "../../canary",
	}
	for label, name := range reject {
		t.Run("reject/"+label, func(t *testing.T) {
			assert.Error(t, validateListingName(name), "name %q must be rejected", name)
		})
	}
}

func TestRemoteObjectBaseName(t *testing.T) {
	t.Parallel()

	t.Run("accept", func(t *testing.T) {
		for remote, want := range map[string]string{
			"/ns/dir/file.txt": "file.txt",
			"/ns/dir/..hidden": "..hidden",
			"/ns/dir/a..b":     "a..b",
			"/ns/dir/sub/":     "sub",
			"file":             "file",
		} {
			got, err := RemoteObjectBaseName(remote)
			require.NoError(t, err, "remote %q", remote)
			assert.Equal(t, want, got, "remote %q", remote)
		}
	})

	t.Run("reject", func(t *testing.T) {
		for _, remote := range []string{"/ns/dir/..", "/ns/dir/.", "/", "", "/ns/dir/../"} {
			_, err := RemoteObjectBaseName(remote)
			assert.Error(t, err, "remote %q must be rejected", remote)
		}
	})
}
