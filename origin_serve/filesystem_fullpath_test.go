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

package origin_serve

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// TestAferoFileSystem_FullPath locks down the sanitizer contract:
// any name containing ".." fails with errPathTraversal, everything
// else round-trips through path.Clean under the configured prefix.
func TestAferoFileSystem_FullPath(t *testing.T) {
	cases := []struct {
		name     string
		prefix   string
		in       string
		wantErr  bool
		wantPath string
	}{
		{"empty-prefix-simple", "", "/foo/bar", false, "/foo/bar"},
		{"empty-prefix-noslash", "", "foo/bar", false, "/foo/bar"},
		{"empty-prefix-root", "", "/", false, "/"},
		{"empty-prefix-empty", "", "", false, "/"},
		{"empty-prefix-double-slash", "", "//foo//bar", false, "/foo/bar"},
		{"empty-prefix-dot-segment", "", "/foo/./bar", false, "/foo/bar"},

		{"with-prefix-simple", "/exports/x", "/data.bin", false, "/exports/x/data.bin"},
		{"with-prefix-nested", "/exports/x", "/sub/data.bin", false, "/exports/x/sub/data.bin"},

		// Rooted ".." folds against "/" per path.Clean rule 4 and
		// resolves inside the export — safe, so we allow it.
		{"leading-slash-dotdot-folds", "", "/../etc/passwd", false, "/etc/passwd"},
		{"interior-dotdot-folds", "", "/foo/../etc", false, "/etc"},
		{"trailing-dotdot-folds", "", "/foo/..", false, "/"},
		{"with-prefix-rooted-dotdot", "/exports/x", "/../../etc", false, "/exports/x/etc"},

		// Genuine escape shapes: cleaned result retains a ".." at
		// the start (relative input trying to walk above the anchor).
		{"reject-dotdot-leading", "", "../etc", true, ""},
		{"reject-dotdot-only", "", "..", true, ""},
		{"reject-relative-double-dotdot", "", "foo/../../etc", true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			afs := &aferoFileSystem{prefix: tc.prefix}
			got, err := afs.fullPath(tc.in)
			if tc.wantErr {
				if !errors.Is(err, errPathTraversal) {
					t.Fatalf("fullPath(%q) err = %v, want errPathTraversal", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fullPath(%q) unexpected err: %v", tc.in, err)
			}
			if got != tc.wantPath {
				t.Fatalf("fullPath(%q) = %q, want %q", tc.in, got, tc.wantPath)
			}
		})
	}
}

// TestAferoFileSystem_TraversalRejectedByPublicMethods confirms
// that RemoveAll / OpenFile / Stat / Mkdir / Rename all short-circuit
// with errPathTraversal before touching the underlying afero.Fs.
// The MemMapFs receiver would happily accept "../etc" (no sandbox);
// this test proves the type refuses to hand it that name.
func TestAferoFileSystem_TraversalRejectedByPublicMethods(t *testing.T) {
	mem := afero.NewMemMapFs()
	afs := newAferoFileSystem(mem, "", nil)
	ctx := context.Background()

	assertRejected := func(t *testing.T, op string, err error) {
		t.Helper()
		if !errors.Is(err, errPathTraversal) {
			t.Fatalf("%s: err = %v, want errPathTraversal", op, err)
		}
	}

	// Use a purely-relative traversal that path.Clean cannot fold
	// against the root — the rejection path is what we're testing.
	const escape = "../../etc/passwd"

	if err := afs.Mkdir(ctx, escape, 0o755); true {
		assertRejected(t, "Mkdir", err)
	}
	if _, err := afs.OpenFile(ctx, escape, os.O_RDONLY, 0); true {
		assertRejected(t, "OpenFile", err)
	}
	if err := afs.RemoveAll(ctx, escape); true {
		assertRejected(t, "RemoveAll", err)
	}
	if err := afs.Rename(ctx, "/legit", escape); true {
		assertRejected(t, "Rename-new", err)
	}
	if err := afs.Rename(ctx, escape, "/legit"); true {
		assertRejected(t, "Rename-old", err)
	}
	if _, err := afs.Stat(ctx, escape); true {
		assertRejected(t, "Stat", err)
	}
}

// Compile-time proof that aferoFileSystem still implements the
// webdav.FileSystem interface after the signature refactor. If a
// caller ever forgets to propagate the error from fullPath, the
// return-types will diverge and this line will fail to compile.
var _ webdav.FileSystem = (*aferoFileSystem)(nil)
