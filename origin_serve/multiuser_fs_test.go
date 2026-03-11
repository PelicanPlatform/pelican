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
	"runtime"
	"sync"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/identity"
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

func TestMultiuserFileSystem_ImplementsWebdavFS(t *testing.T) {
	// Verify multiuserFileSystem implements webdav.FileSystem at compile time
	var _ webdav.FileSystem = (*multiuserFileSystem)(nil)
}

func TestMultiuserFileSystem_ResolveIdentity(t *testing.T) {
	lookup := newTestLookup()
	fs, err := newMultiuserFileSystem(context.Background(), nil, lookup, 0)
	require.NoError(t, err)
	mfs := fs.(*multiuserFileSystem)

	t.Run("NoUserInfo", func(t *testing.T) {
		ctx := context.Background()
		id := mfs.resolveIdentity(ctx)
		assert.Equal(t, uint32(0), id.UID)
		assert.Equal(t, uint32(0), id.GID)
	})

	t.Run("RootUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "root", Groups: []string{"root"}})
		id := mfs.resolveIdentity(ctx)
		assert.Equal(t, uint32(0), id.UID)
		assert.Equal(t, uint32(0), id.GID)
	})

	t.Run("NobodyUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "nobody", Groups: []string{"nogroup"}})
		id := mfs.resolveIdentity(ctx)
		assert.Equal(t, uint32(65534), id.UID)
		assert.Equal(t, uint32(65534), id.GID)
	})

	t.Run("UnknownUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "unknown_user", Groups: []string{"unknown_group"}})
		id := mfs.resolveIdentity(ctx)
		assert.Equal(t, uint32(0), id.UID)
		assert.Equal(t, uint32(0), id.GID)
	})

	t.Run("EmptyUser", func(t *testing.T) {
		ctx := setUserInfo(context.Background(), &userInfo{User: "", Groups: nil})
		id := mfs.resolveIdentity(ctx)
		assert.Equal(t, uint32(0), id.UID)
		assert.Equal(t, uint32(0), id.GID)
	})
}

func TestMultiuserFileSystem_BasicOperations(t *testing.T) {
	// This test verifies that multiuserFileSystem correctly delegates to the
	// inner webdav.FileSystem. Since we run as root in the dev container,
	// setfsuid/setfsgid to root is a no-op and operations should succeed normally.
	tmpDir := t.TempDir()

	// Build an inner webdav.FileSystem using the existing afero adapter
	osFs := afero.NewOsFs()
	baseFs := afero.NewBasePathFs(osFs, tmpDir)
	inner := newAferoFileSystem(baseFs, "", nil)

	lookup := newTestLookup()
	fs, err := newMultiuserFileSystem(context.Background(), inner, lookup, 0)
	require.NoError(t, err)
	mfs := fs.(*multiuserFileSystem)

	ctx := setUserInfo(context.Background(), &userInfo{User: "root", Groups: []string{"root"}})

	// Mkdir
	err = mfs.Mkdir(ctx, "/testdir", 0755)
	require.NoError(t, err)

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

	// Verify new path exists
	_, err = mfs.Stat(ctx, "/renamed.txt")
	require.NoError(t, err)

	// RemoveAll
	err = mfs.RemoveAll(ctx, "/renamed.txt")
	require.NoError(t, err)
	_, err = mfs.Stat(ctx, "/renamed.txt")
	assert.True(t, os.IsNotExist(err))

	err = mfs.RemoveAll(ctx, "/testdir")
	require.NoError(t, err)
}

func TestRunAsUser_RestoresIdentity(t *testing.T) {
	// Test that runAsUser properly restores the FS UID/GID after the operation
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current fsuid (should be 0 = root)
	origUid, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, 0, 0, 0)
	// Restore it
	syscall.Syscall(syscall.SYS_SETFSUID, origUid, 0, 0)

	result, err := runAsUser(uint32(0), uint32(0), nil, 0, func() (string, error) {
		return "ok", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", result)

	// Verify UID is restored
	curUid, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, 0, 0, 0)
	syscall.Syscall(syscall.SYS_SETFSUID, curUid, 0, 0)
	assert.Equal(t, origUid, curUid, "FS UID should be restored after runAsUser")
}

func TestRunAsUser_ErrorPropagation(t *testing.T) {
	expectedErr := fmt.Errorf("test error")
	_, err := runAsUser(uint32(0), uint32(0), nil, 0, func() (string, error) {
		return "", expectedErr
	})
	assert.Equal(t, expectedErr, err)
}

func TestMultiuserFileSystem_ConcurrentAccess(t *testing.T) {
	// Verify that concurrent goroutines can use multiuserFileSystem
	// without interfering with each other's identity resolution.
	// Since context flows per-call, there's no shared state to conflict.
	lookup := newTestLookup()
	fs, err := newMultiuserFileSystem(context.Background(), nil, lookup, 0) // inner not needed for resolveIdentity
	require.NoError(t, err)
	mfs := fs.(*multiuserFileSystem)

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

			id := mfs.resolveIdentity(ctx)

			if idx%2 == 0 {
				assert.Equal(t, uint32(65534), id.UID, "goroutine %d expected nobody UID", idx)
			} else {
				assert.Equal(t, uint32(0), id.UID, "goroutine %d expected root UID", idx)
			}
		}(i)
	}

	wg.Wait()
}

// Verify that the identity.Lookup interface is satisfied
func TestLookupInterfaceCompliance(t *testing.T) {
	var _ identity.Lookup = (*testLookup)(nil)
}
