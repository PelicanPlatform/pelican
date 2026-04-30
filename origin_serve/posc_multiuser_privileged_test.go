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

// File posc_multiuser_privileged_test.go exercises the design's most
// load-bearing composition rule: POSC sits *beneath* the multiuser
// layer so staged temp files inherit the request user's uid/gid. This
// only runs in the Pelican dev container (Linux + CAP_SETUID/SETGID +
// pre-created test users); it's skipped everywhere else.

package origin_serve

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/identity"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestPrivileged_PoscBeneathMultiuser_OwnershipFollowsUser PUTs a
// file as a synthetic "alice" via the (multiuser→posc→osfs) chain
// and asserts the final on-disk file is owned by alice. This locks
// down the layering — a future refactor that swaps the wrapping
// order would silently regress to "every uploaded object is owned by
// the origin process," which this test catches.
func TestPrivileged_PoscBeneathMultiuser_OwnershipFollowsUser(t *testing.T) {
	test_utils.SkipUnlessPrivileged(t)
	test_utils.SkipUnlessTestUsers(t, "alice")

	aliceInfo, err := user.Lookup("alice")
	require.NoError(t, err)
	aliceUID, err := strconv.ParseUint(aliceInfo.Uid, 10, 32)
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "pelican-posc-multiuser-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	require.NoError(t, os.Chmod(tmpDir, 0777))

	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
	autoFs := newAutoCreateDirFs(osFs)
	var fs webdav.FileSystem = newAferoFileSystem(autoFs, "", nil)

	// Layer order: webdav → multiuser → posc → afero. This is what
	// InitializeHandlers builds at runtime.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	posc := newPoscFileSystem(ctx, fs, ".pelican-posc", time.Hour, 19*time.Minute)
	posc.SetTouchFS(autoFs)
	defer posc.Stop()
	fs = posc

	multifs, err := newMultiuserFileSystem(ctx, fs, identity.NewLookup(), 0)
	require.NoError(t, err)

	uctx := setUserInfo(ctx, &userInfo{User: "alice", Groups: []string{"alice"}})
	f, err := multifs.OpenFile(uctx, "/data/owned-by-alice.bin", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("hi from alice"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Stat directly on disk (not through any of our layers) so the
	// uid we observe is the real on-disk uid, not anything filtered
	// by the wrapping FS.
	info, err := os.Stat(tmpDir + "/data/owned-by-alice.bin")
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	assert.Equal(t, uint32(aliceUID), stat.Uid, "final object should be owned by alice")
}
