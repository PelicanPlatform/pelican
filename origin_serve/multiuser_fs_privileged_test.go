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

// Privileged integration tests that verify real user switching via setfsuid/setfsgid.
// These tests require:
//   - Linux (setfsuid is Linux-specific)
//   - CAP_SETUID and CAP_SETGID capabilities
//   - Test users: alice, bob (present in the Pelican dev container)

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/pelicanplatform/pelican/identity"
)

// skipUnlessPrivileged skips the test if the process lacks CAP_SETUID or
// CAP_SETGID in its effective capability set.  setfsuid(2) requires
// CAP_SETUID to switch to an arbitrary UID.
func skipUnlessPrivileged(t *testing.T) {
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

// skipUnlessTestUsers skips the test if the expected dev-container users
// (alice, bob) are not present.
func skipUnlessTestUsers(t *testing.T, usernames ...string) {
	t.Helper()
	for _, name := range usernames {
		if _, err := user.Lookup(name); err != nil {
			t.Skipf("test user %q not found: %v", name, err)
		}
	}
}

// statOwner returns the UID and GID of a path.
func statOwner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	return stat.Uid, stat.Gid
}

// buildMultiuserFS creates a multiuserFileSystem backed by a real OS directory.
func buildMultiuserFS(t *testing.T, root string) *multiuserFileSystem {
	t.Helper()
	osFs := afero.NewOsFs()
	baseFs := afero.NewBasePathFs(osFs, root)
	inner := newAferoFileSystem(baseFs, "", nil)

	lookup := identity.NewLookup()
	fs, err := newMultiuserFileSystem(context.Background(), inner, lookup, 0)
	require.NoError(t, err)
	return fs.(*multiuserFileSystem)
}

// ctxForUser builds a context with userInfo for the given user/group.
func ctxForUser(username, groupname string) context.Context {
	return setUserInfo(context.Background(), &userInfo{
		User:   username,
		Groups: []string{groupname},
	})
}

// TestPrivileged_UserSwitching exercises real setfsuid/setfsgid-based user
// switching against the OS filesystem and verifies resulting ownership.
func TestPrivileged_UserSwitching(t *testing.T) {
	skipUnlessPrivileged(t)
	skipUnlessTestUsers(t, "alice", "bob")

	aliceInfo, err := user.Lookup("alice")
	require.NoError(t, err)
	bobInfo, err := user.Lookup("bob")
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "pelican-multiuser-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	// Make the dir world-traversable so switched UIDs can access it.
	require.NoError(t, os.Chmod(tmpDir, 0777))

	mfs := buildMultiuserFS(t, tmpDir)

	t.Run("MkdirOwnership", func(t *testing.T) {
		ctxAlice := ctxForUser("alice", "alice")
		ctxBob := ctxForUser("bob", "bob")

		require.NoError(t, mfs.Mkdir(ctxAlice, "/alice-dir", 0755))
		require.NoError(t, mfs.Mkdir(ctxBob, "/bob-dir", 0755))

		uid, gid := statOwner(t, filepath.Join(tmpDir, "alice-dir"))
		assert.Equal(t, aliceInfo.Uid, uidStr(uid), "alice-dir should be owned by alice")
		assert.Equal(t, aliceInfo.Gid, uidStr(gid), "alice-dir should have alice's group")

		uid, gid = statOwner(t, filepath.Join(tmpDir, "bob-dir"))
		assert.Equal(t, bobInfo.Uid, uidStr(uid), "bob-dir should be owned by bob")
		assert.Equal(t, bobInfo.Gid, uidStr(gid), "bob-dir should have bob's group")
	})

	t.Run("CreateFileOwnership", func(t *testing.T) {
		ctxAlice := ctxForUser("alice", "alice")
		ctxBob := ctxForUser("bob", "bob")

		// Create a file as alice
		f, err := mfs.OpenFile(ctxAlice, "/alice-file.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		_, err = f.Write([]byte("hello from alice"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		// Create a file as bob
		f, err = mfs.OpenFile(ctxBob, "/bob-file.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		_, err = f.Write([]byte("hello from bob"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		uid, gid := statOwner(t, filepath.Join(tmpDir, "alice-file.txt"))
		assert.Equal(t, aliceInfo.Uid, uidStr(uid), "alice-file.txt should be owned by alice")
		assert.Equal(t, aliceInfo.Gid, uidStr(gid))

		uid, gid = statOwner(t, filepath.Join(tmpDir, "bob-file.txt"))
		assert.Equal(t, bobInfo.Uid, uidStr(uid), "bob-file.txt should be owned by bob")
		assert.Equal(t, bobInfo.Gid, uidStr(gid))
	})

	t.Run("ReadBackFile", func(t *testing.T) {
		// Alice writes, then reads her own file
		ctxAlice := ctxForUser("alice", "alice")

		f, err := mfs.OpenFile(ctxAlice, "/alice-read.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		_, err = f.Write([]byte("round-trip"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		f, err = mfs.OpenFile(ctxAlice, "/alice-read.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		data, err := io.ReadAll(f)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		assert.Equal(t, "round-trip", string(data))
	})

	t.Run("StatReturnsCorrectInfo", func(t *testing.T) {
		ctxBob := ctxForUser("bob", "bob")

		require.NoError(t, mfs.Mkdir(ctxBob, "/bob-stat-dir", 0750))

		info, err := mfs.Stat(ctxBob, "/bob-stat-dir")
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, "bob-stat-dir", info.Name())
	})

	t.Run("ListDirectory", func(t *testing.T) {
		ctxAlice := ctxForUser("alice", "alice")

		require.NoError(t, mfs.Mkdir(ctxAlice, "/alice-list-dir", 0755))

		// Create two files inside the directory
		for _, name := range []string{"one.txt", "two.txt"} {
			f, err := mfs.OpenFile(ctxAlice, "/alice-list-dir/"+name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			require.NoError(t, err)
			require.NoError(t, f.Close())
		}

		// Open the directory and read entries
		dir, err := mfs.OpenFile(ctxAlice, "/alice-list-dir", os.O_RDONLY, 0)
		require.NoError(t, err)
		entries, err := dir.Readdir(-1)
		require.NoError(t, err)
		require.NoError(t, dir.Close())

		names := make(map[string]bool)
		for _, e := range entries {
			names[e.Name()] = true
		}
		assert.True(t, names["one.txt"], "should list one.txt")
		assert.True(t, names["two.txt"], "should list two.txt")

		// Verify ownership of files inside the directory
		for _, name := range []string{"one.txt", "two.txt"} {
			uid, gid := statOwner(t, filepath.Join(tmpDir, "alice-list-dir", name))
			assert.Equal(t, aliceInfo.Uid, uidStr(uid), "%s should be owned by alice", name)
			assert.Equal(t, aliceInfo.Gid, uidStr(gid))
		}
	})

	t.Run("RenamePreservesOwnership", func(t *testing.T) {
		ctxAlice := ctxForUser("alice", "alice")

		f, err := mfs.OpenFile(ctxAlice, "/alice-rename-src.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		require.NoError(t, mfs.Rename(ctxAlice, "/alice-rename-src.txt", "/alice-rename-dst.txt"))

		// Ownership shouldn't change after rename
		uid, gid := statOwner(t, filepath.Join(tmpDir, "alice-rename-dst.txt"))
		assert.Equal(t, aliceInfo.Uid, uidStr(uid))
		assert.Equal(t, aliceInfo.Gid, uidStr(gid))
	})

	t.Run("RemoveAll", func(t *testing.T) {
		ctxBob := ctxForUser("bob", "bob")

		require.NoError(t, mfs.Mkdir(ctxBob, "/bob-rm-dir", 0755))
		f, err := mfs.OpenFile(ctxBob, "/bob-rm-dir/child.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		require.NoError(t, mfs.RemoveAll(ctxBob, "/bob-rm-dir"))

		_, err = os.Stat(filepath.Join(tmpDir, "bob-rm-dir"))
		assert.True(t, os.IsNotExist(err), "directory should be removed")
	})

	t.Run("CrossUserIsolation", func(t *testing.T) {
		// Alice creates a private file; bob should not be able to
		// read it when permissions are restrictive.
		ctxAlice := ctxForUser("alice", "alice")
		ctxBob := ctxForUser("bob", "bob")

		require.NoError(t, mfs.Mkdir(ctxAlice, "/alice-private", 0700))
		f, err := mfs.OpenFile(ctxAlice, "/alice-private/secret.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		require.NoError(t, err)
		_, err = f.Write([]byte("secret"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		// Bob should get a permission error trying to open alice's file
		_, err = mfs.OpenFile(ctxBob, "/alice-private/secret.txt", os.O_RDONLY, 0)
		assert.True(t, os.IsPermission(err), "bob should not be able to read alice's private file, got: %v", err)
	})

	t.Run("NobodyUser", func(t *testing.T) {
		skipUnlessTestUsers(t, "nobody")
		nobodyInfo, err := user.Lookup("nobody")
		require.NoError(t, err)

		ctxNobody := ctxForUser("nobody", "nobody")

		f, err := mfs.OpenFile(ctxNobody, "/nobody-file.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		uid, _ := statOwner(t, filepath.Join(tmpDir, "nobody-file.txt"))
		assert.Equal(t, nobodyInfo.Uid, uidStr(uid), "file should be owned by nobody")
	})
}

// uidStr converts a uint32 UID/GID to the string form returned by os/user.
func uidStr(id uint32) string {
	return fmt.Sprintf("%d", id)
}

// TestPrivileged_SecondaryGroups verifies that the multiuser filesystem
// correctly sets supplementary groups so that group-based access to files
// works for users who belong to a secondary group.
//
// Prerequisites (in addition to those of TestPrivileged_UserSwitching):
//   - A shared group "pelican_shared" that alice belongs to as a secondary group.
//
// The test creates the group and membership if they don't exist, skipping
// if it cannot.
func TestPrivileged_SecondaryGroups(t *testing.T) {
	skipUnlessPrivileged(t)
	skipUnlessTestUsers(t, "alice", "bob")

	aliceInfo, err := user.Lookup("alice")
	require.NoError(t, err)
	bobInfo, err := user.Lookup("bob")
	require.NoError(t, err)

	// The shared group and membership are set up in the Dockerfile.
	// Skip the test if they're not present.
	sharedGroup := requireSharedGroup(t, "pelican_shared", "alice")

	tmpDir, err := os.MkdirTemp("", "pelican-secondary-groups-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	require.NoError(t, os.Chmod(tmpDir, 0777))

	mfs := buildMultiuserFS(t, tmpDir)

	t.Run("SecondaryGroupWrite", func(t *testing.T) {
		// Bob creates a directory owned by bob:pelican_shared with group-write.
		// Alice should be able to write to it because she's in pelican_shared
		// as a secondary group.
		ctxBob := ctxForUser("bob", "pelican_shared")
		require.NoError(t, mfs.Mkdir(ctxBob, "/shared-dir", 0770))

		bobUID, grpGID := statOwner(t, filepath.Join(tmpDir, "shared-dir"))
		assert.Equal(t, bobInfo.Uid, uidStr(bobUID), "shared-dir should be owned by bob")
		assert.Equal(t, uidStr(sharedGroup.GID), uidStr(grpGID), "shared-dir should have pelican_shared group")

		// Alice writes into the shared directory.  This requires her
		// supplementary groups to include pelican_shared's GID.
		ctxAlice := ctxForUser("alice", "alice")
		f, err := mfs.OpenFile(ctxAlice, "/shared-dir/alice-via-secondary.txt",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0664)
		require.NoError(t, err, "alice should be able to write via secondary group")
		_, err = f.Write([]byte("secondary group access"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		uid, _ := statOwner(t, filepath.Join(tmpDir, "shared-dir", "alice-via-secondary.txt"))
		assert.Equal(t, aliceInfo.Uid, uidStr(uid), "file should be owned by alice")
	})

	t.Run("SecondaryGroupClearedForOtherUser", func(t *testing.T) {
		// Bob is NOT in pelican_shared (only alice is).  Bob should NOT be
		// able to write to a directory that is group-writable by
		// pelican_shared but not world-writable.

		// Create a directory as root that is owned by root:pelican_shared
		// with mode 0770, so only pelican_shared members can write.
		dirPath := filepath.Join(tmpDir, "shared-only")
		require.NoError(t, os.Mkdir(dirPath, 0770))
		require.NoError(t, os.Chmod(dirPath, 0770))
		require.NoError(t, os.Chown(dirPath, 0, int(sharedGroup.GID)))

		ctxBob := ctxForUser("bob", "bob")
		_, err := mfs.OpenFile(ctxBob, "/shared-only/bob-attempt.txt",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		assert.True(t, os.IsPermission(err),
			"bob should NOT be able to write to pelican_shared-only dir, got: %v", err)

		// Alice CAN write (she's in pelican_shared).
		ctxAlice := ctxForUser("alice", "alice")
		f, err := mfs.OpenFile(ctxAlice, "/shared-only/alice-ok.txt",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err, "alice should be able to write via secondary group")
		require.NoError(t, f.Close())
	})

	t.Run("GroupsRestoredAfterOperation", func(t *testing.T) {
		// Verify that secondary groups are properly restored after
		// an operation (the server process shouldn't retain the
		// user's supplementary groups).
		ctxAlice := ctxForUser("alice", "alice")

		f, err := mfs.OpenFile(ctxAlice, "/restore-test.txt",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		// After the operation, the current thread's groups should
		// be back to the process default (not alice's groups).
		// We verify by checking getgroups on a locked thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		currentGroups, err := threadGetgroups()
		require.NoError(t, err)

		// The server process (root) should not have alice's
		// pelican_shared group in its supplementary list after the
		// operation completes.
		for _, gid := range currentGroups {
			assert.NotEqual(t, sharedGroup.GID, gid,
				"server process should not retain alice's secondary group %d", sharedGroup.GID)
		}
	})
}

// sharedGroupInfo holds resolved info about the shared test group.
type sharedGroupInfo struct {
	Name string
	GID  uint32
}

// TestPrivileged_Umask exercises the umask configuration parameter by
// creating directories and files with different umask values and verifying
// the resulting permissions.
func TestPrivileged_Umask(t *testing.T) {
	skipUnlessPrivileged(t)
	skipUnlessTestUsers(t, "alice")

	t.Run("UmaskZeroPreservesPermissions", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "pelican-umask-zero-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })
		require.NoError(t, os.Chmod(tmpDir, 0777))

		mfs := buildMultiuserFS(t, tmpDir) // umask=0
		ctxAlice := ctxForUser("alice", "alice")

		// Mkdir with 0770 should produce exactly 0770
		require.NoError(t, mfs.Mkdir(ctxAlice, "/dir-0770", 0770))
		info, err := os.Stat(filepath.Join(tmpDir, "dir-0770"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0770), info.Mode().Perm(),
			"umask=0 should preserve directory permissions 0770 exactly")

		// File with 0664 should produce exactly 0664
		f, err := mfs.OpenFile(ctxAlice, "/file-0664", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0664)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		info, err = os.Stat(filepath.Join(tmpDir, "file-0664"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0664), info.Mode().Perm(),
			"umask=0 should preserve file permissions 0664 exactly")
	})

	t.Run("UmaskMasksPermissions", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "pelican-umask-0022-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })
		require.NoError(t, os.Chmod(tmpDir, 0777))

		// Build with umask=0022 (standard: removes group-write + other-write)
		osFs := afero.NewOsFs()
		baseFs := afero.NewBasePathFs(osFs, tmpDir)
		inner := newAferoFileSystem(baseFs, "", nil)
		lookup := identity.NewLookup()
		fs, err := newMultiuserFileSystem(context.Background(), inner, lookup, 0022)
		require.NoError(t, err)
		mfs := fs.(*multiuserFileSystem)

		ctxAlice := ctxForUser("alice", "alice")

		// Mkdir with 0770: umask 0022 should mask to 0750
		require.NoError(t, mfs.Mkdir(ctxAlice, "/dir-masked", 0770))
		info, err := os.Stat(filepath.Join(tmpDir, "dir-masked"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0750), info.Mode().Perm(),
			"umask=0022 should mask 0770 to 0750")

		// File with 0666: umask 0022 should mask to 0644
		f, err := mfs.OpenFile(ctxAlice, "/file-masked", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		info, err = os.Stat(filepath.Join(tmpDir, "file-masked"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm(),
			"umask=0022 should mask 0666 to 0644")
	})

	t.Run("RestrictiveUmask", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "pelican-umask-0077-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })
		require.NoError(t, os.Chmod(tmpDir, 0777))

		// Build with umask=0077 (removes all group + other bits)
		osFs := afero.NewOsFs()
		baseFs := afero.NewBasePathFs(osFs, tmpDir)
		inner := newAferoFileSystem(baseFs, "", nil)
		lookup := identity.NewLookup()
		fs, err := newMultiuserFileSystem(context.Background(), inner, lookup, 0077)
		require.NoError(t, err)
		mfs := fs.(*multiuserFileSystem)

		ctxAlice := ctxForUser("alice", "alice")

		// Mkdir with 0777: umask 0077 should mask to 0700
		require.NoError(t, mfs.Mkdir(ctxAlice, "/dir-private", 0777))
		info, err := os.Stat(filepath.Join(tmpDir, "dir-private"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm(),
			"umask=0077 should mask 0777 to 0700")
	})
}

// requireSharedGroup checks that the named group exists and that member
// belongs to it.  It skips the test if either condition is not met.
// Group setup is expected to happen in the Dockerfile, not at test time.
func requireSharedGroup(t *testing.T, groupname, member string) sharedGroupInfo {
	t.Helper()

	grp, err := user.LookupGroup(groupname)
	if err != nil {
		t.Skipf("shared group %q not found (set up in Dockerfile): %v", groupname, err)
	}

	var gid uint32
	_, err = fmt.Sscanf(grp.Gid, "%d", &gid)
	require.NoError(t, err)

	// Verify the member is actually in the group.
	u, err := user.Lookup(member)
	require.NoError(t, err)
	groupIDs, err := u.GroupIds()
	require.NoError(t, err)

	found := false
	for _, gidStr := range groupIDs {
		if gidStr == grp.Gid {
			found = true
			break
		}
	}
	if !found {
		t.Skipf("user %q is not in group %q (set up in Dockerfile)", member, groupname)
	}

	return sharedGroupInfo{Name: groupname, GID: gid}
}
