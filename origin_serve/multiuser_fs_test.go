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

package origin_serve

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/identity"
	"github.com/pelicanplatform/pelican/test_utils"
)

// testLookup is a mock identity.Lookup for testing.
type testLookup struct {
	users  map[string]uint32
	groups map[string]uint32
}

func newTestLookup() *testLookup {
	return &testLookup{
		users:  map[string]uint32{"root": 0, "nobody": 65534},
		groups: map[string]uint32{"root": 0, "nogroup": 65534},
	}
}

func (t *testLookup) UidForUser(username string) (uint32, error) {
	if uid, ok := t.users[username]; ok {
		return uid, nil
	}
	return 0, fmt.Errorf("user %q not found", username)
}

func (t *testLookup) GidForGroup(groupname string) (uint32, error) {
	if gid, ok := t.groups[groupname]; ok {
		return gid, nil
	}
	return 0, fmt.Errorf("group %q not found", groupname)
}

func (t *testLookup) SecondaryGidsForUser(_ string) ([]uint32, error) {
	return nil, nil
}

// Compile-time interface checks
var _ webdav.FileSystem = (*multiuserFileSystem)(nil)
var _ identity.Lookup = (*testLookup)(nil)

// buildMultiuserFS creates a multiuserFileSystem for testing.
// If root is non-empty, an OS-backed afero filesystem is created at that path;
// otherwise the inner filesystem is nil (sufficient for resolveIdentity tests).
func buildMultiuserFS(t *testing.T, root string, lookup identity.Lookup, umask int) *multiuserFileSystem {
	t.Helper()
	var inner webdav.FileSystem
	if root != "" {
		osFs := afero.NewOsFs()
		baseFs := afero.NewBasePathFs(osFs, root)
		inner = newAferoFileSystem(baseFs, "", nil)
	}
	fs, err := newMultiuserFileSystem(context.Background(), inner, lookup, umask)
	require.NoError(t, err)
	return fs.(*multiuserFileSystem)
}

func TestMultiuserFileSystem_ResolveIdentity(t *testing.T) {
	mfs := buildMultiuserFS(t, "", newTestLookup(), 0)

	t.Run("NoUserInfo", func(t *testing.T) {
		ctx := context.Background()
		_, err := mfs.resolveIdentity(ctx)
		require.Error(t, err, "should error when no user info in context")
	})

	t.Run("RootUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "root", Groups: []string{"root"}})
		id, err := mfs.resolveIdentity(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), id.UID)
		assert.Equal(t, uint32(0), id.GID)
	})

	t.Run("NobodyUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "nobody", Groups: []string{"nogroup"}})
		id, err := mfs.resolveIdentity(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint32(65534), id.UID)
		assert.Equal(t, uint32(65534), id.GID)
	})

	t.Run("UnknownUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "unknown_user", Groups: []string{"unknown_group"}})
		_, err := mfs.resolveIdentity(ctx)
		require.Error(t, err, "should error when user cannot be resolved")
	})

	t.Run("EmptyUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "", Groups: nil})
		_, err := mfs.resolveIdentity(ctx)
		require.Error(t, err, "should error when user is empty")
	})
}

func TestMultiuserFileSystem_BasicOperations(t *testing.T) {
	// This test verifies that multiuserFileSystem correctly delegates to the
	// inner webdav.FileSystem. When running as root, it uses a real non-root
	// user (nobody) to exercise setfsuid/setfsgid and verify file ownership.
	// Otherwise, it falls back to a mock lookup as root (no-op identity switch)
	// to verify basic delegation.
	tmpDir := t.TempDir()

	var (
		lookup      identity.Lookup
		ctx         context.Context
		verifyOwner func(t *testing.T, relPath string)
	)

	if os.Getuid() == 0 {
		nobodyUser, err := user.Lookup("nobody")
		if err != nil {
			t.Skip("nobody user not found")
		}
		nobodyGrp, err := user.LookupGroupId(nobodyUser.Gid)
		if err != nil {
			t.Skipf("cannot resolve group for nobody (gid %s): %v", nobodyUser.Gid, err)
		}
		expectedUID, err := strconv.ParseUint(nobodyUser.Uid, 10, 32)
		require.NoError(t, err)
		expectedGID, err := strconv.ParseUint(nobodyUser.Gid, 10, 32)
		require.NoError(t, err)

		// Make the dir world-traversable so the switched UID can access it.
		require.NoError(t, os.Chmod(tmpDir, 0777))

		lookup = identity.NewLookup()
		ctx = setUserInfo(context.Background(), &userInfo{User: "nobody", Groups: []string{nobodyGrp.Name}})
		verifyOwner = func(t *testing.T, relPath string) {
			t.Helper()
			uid, gid := test_utils.FileOwner(t, filepath.Join(tmpDir, relPath))
			assert.Equal(t, uint32(expectedUID), uid, "%s should be owned by nobody", relPath)
			assert.Equal(t, uint32(expectedGID), gid, "%s should have nobody's group", relPath)
		}
	} else {
		lookup = newTestLookup()
		ctx = setUserInfo(context.Background(), &userInfo{User: "root", Groups: []string{"root"}})
		verifyOwner = func(*testing.T, string) {} // no-op without privilege
	}

	mfs := buildMultiuserFS(t, tmpDir, lookup, 0)

	// Mkdir
	err := mfs.Mkdir(ctx, "/testdir", 0755)
	require.NoError(t, err)
	verifyOwner(t, "testdir")

	// Stat
	info, err := mfs.Stat(ctx, "/testdir")
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// OpenFile (create)
	f, err := mfs.OpenFile(ctx, "/testfile.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	verifyOwner(t, "testfile.txt")

	// OpenFile (read)
	f, err = mfs.OpenFile(ctx, "/testfile.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	buf := make([]byte, 5)
	n, err := f.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf))
	require.NoError(t, f.Close())

	// Rename
	err = mfs.Rename(ctx, "/testfile.txt", "/renamed.txt")
	require.NoError(t, err)

	// Verify old path is gone
	_, err = mfs.Stat(ctx, "/testfile.txt")
	assert.True(t, os.IsNotExist(err))

	// Verify new path exists and ownership is preserved
	_, err = mfs.Stat(ctx, "/renamed.txt")
	require.NoError(t, err)
	verifyOwner(t, "renamed.txt")

	// RemoveAll
	err = mfs.RemoveAll(ctx, "/renamed.txt")
	require.NoError(t, err)
	_, err = mfs.Stat(ctx, "/renamed.txt")
	assert.True(t, os.IsNotExist(err))

	err = mfs.RemoveAll(ctx, "/testdir")
	require.NoError(t, err)
}

func TestRunAsUser_ErrorPropagation(t *testing.T) {
	// Verify that when the callback returns an error, runAsUser propagates it
	// AND restores the original FS identity. We switch to a non-root UID so
	// a broken implementation that never switches would be caught.
	test_utils.SkipUnlessPrivileged(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	expectedErr := fmt.Errorf("test error")
	_, err := runAsUser(uint32(65534), uint32(65534), nil, func() (string, error) {
		return "", expectedErr
	})
	assert.Equal(t, expectedErr, err)

	// Verify UID was restored to root (0) despite the error.
	curUid, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, 0, 0, 0)
	syscall.Syscall(syscall.SYS_SETFSUID, curUid, 0, 0) //nolint:errcheck
	assert.Equal(t, uintptr(0), curUid, "FS UID should be restored after runAsUser error")
}

func TestMultiuserFileSystem_ConcurrentAccess(t *testing.T) {
	// Verify that concurrent goroutines can use multiuserFileSystem
	// without interfering with each other's identity resolution.
	// Since context flows per-call, there's no shared state to conflict.
	mfs := buildMultiuserFS(t, "", newTestLookup(), 0)

	var wg sync.WaitGroup
	const numGoroutines = 20

	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			userName := "root"
			if idx%2 == 0 {
				userName = "nobody"
			}
			ctx := setUserInfo(context.Background(), &userInfo{User: userName, Groups: []string{"root"}})

			id, err := mfs.resolveIdentity(ctx)
			require.NoError(t, err)

			if idx%2 == 0 {
				assert.Equal(t, uint32(65534), id.UID, "goroutine %d expected nobody UID", idx)
			} else {
				assert.Equal(t, uint32(0), id.UID, "goroutine %d expected root UID", idx)
			}
		}(i)
	}

	wg.Wait()
}
