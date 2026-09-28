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

package server_utils

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAferoFileSystemFullPathConfined(t *testing.T) {
	t.Parallel()

	afs := NewAferoFileSystem(afero.NewMemMapFs(), "/export/data", nil)

	t.Run("accepted", func(t *testing.T) {
		for name, want := range map[string]string{
			"/file.txt":       "/export/data/file.txt",
			"/":               "/export/data",
			"":                "/export/data",
			"/a/b/../c":       "/export/data/a/c",
			"/a/./b":          "/export/data/a/b",
			"/..hidden/a..b":  "/export/data/..hidden/a..b",
			"/data-other/x":   "/export/data/data-other/x",
			"/sub/../../data": "/export/data",
		} {
			got, err := afs.FullPath(name)
			require.NoError(t, err, "name %q", name)
			assert.Equal(t, want, got, "name %q", name)
		}
	})

	t.Run("escaping names are refused", func(t *testing.T) {
		for _, name := range []string{
			"/../etc/passwd",
			"../etc/passwd",
			"/a/../../etc/passwd",
			"/../data-other/x", // sibling sharing the prefix as a string prefix
			"/..",
		} {
			got, err := afs.FullPath(name)
			require.Error(t, err, "name %q", name)
			assert.Empty(t, got)
			assert.True(t, errors.Is(err, os.ErrPermission), "name %q: %v", name, err)
			var pathErr *os.PathError
			assert.True(t, errors.As(err, &pathErr), "name %q: %v", name, err)
		}
	})

	t.Run("empty prefix passes through", func(t *testing.T) {
		plain := NewAferoFileSystem(afero.NewMemMapFs(), "", nil)
		got, err := plain.FullPath("/../anything")
		require.NoError(t, err)
		assert.Equal(t, "/../anything", got)
	})
}

func TestAferoFileSystemOperationsRefuseEscape(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mem := afero.NewMemMapFs()
	require.NoError(t, mem.MkdirAll("/export/data", 0755))
	require.NoError(t, afero.WriteFile(mem, "/export/data/inside.txt", []byte("inside"), 0644))
	require.NoError(t, afero.WriteFile(mem, "/export/outside.txt", []byte("outside"), 0644))
	afs := NewAferoFileSystem(mem, "/export/data", nil)

	// In-bounds operations still work.
	info, err := afs.Stat(ctx, "/inside.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(6), info.Size())

	_, err = afs.Stat(ctx, "/../outside.txt")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))

	err = afs.RemoveAll(ctx, "/../outside.txt")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))
	_, statErr := mem.Stat("/export/outside.txt")
	assert.NoError(t, statErr, "outside file must survive")

	err = afs.Rename(ctx, "/inside.txt", "/../moved.txt")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))
	_, statErr = mem.Stat("/export/data/inside.txt")
	assert.NoError(t, statErr, "inside file must not be moved out")

	err = afs.Rename(ctx, "/../outside.txt", "/stolen.txt")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))

	err = afs.Mkdir(ctx, "/../newdir", 0755)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))
	_, statErr = mem.Stat("/export/newdir")
	assert.True(t, os.IsNotExist(statErr))

	_, err = afs.OpenFile(ctx, "/../outside.txt", os.O_RDONLY, 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))
}
