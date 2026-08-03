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

package lotman

import (
	"os"
	"syscall"

	"github.com/pkg/errors"
)

// lotDBFileMode is the mode of the shared V1 lot database and its SQLite
// sidecars: owner and group read/write, nothing for other. The group is the
// daemon's, so the xrootd-user purge plugin can open the database while it stays
// unreadable to every other local account. Combined with lotDBDirMode's setgid
// bit, sidecars SQLite creates later inherit the same group automatically.
const lotDBFileMode os.FileMode = 0o660

// lotDBDirMode is the mode of Lotman.LotHome. Setgid so that the -wal and -shm
// files SQLite creates on demand are group-owned by the daemon group without a
// second ownership pass (and therefore without a window in which the plugin
// cannot open them).
const lotDBDirMode os.FileMode = 0o770 | os.ModeSetgid

// openSharedLotDBFile opens (creating if absent) one file belonging to the
// shared lot database and applies ownership and permissions *through the
// descriptor*.
//
// Path-based os.Chown/os.Chmod follow symlinks. pelican-server usually runs as
// root and Lotman.LotHome is a directory the daemon user can write, so a
// path-based chmod/chown there is an invitation: replace lots.sqlite (or one of
// its sidecars, which do not exist yet at first start) with a symlink to any
// file on the system and root will hand it to the daemon user, or to a mode of
// our choosing. O_NOFOLLOW makes the open itself fail on a symlink, and fchown/
// fchmod on the resulting descriptor cannot be redirected afterwards.
func openSharedLotDBFile(path string, create bool, uid, gid int) error {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if create {
		flags = os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, lotDBFileMode)
	if err != nil {
		if !create && os.IsNotExist(err) {
			// SQLite creates -wal/-shm lazily; nothing to secure yet.
			return nil
		}
		return errors.Wrapf(err, "unable to open lot database file %s (it must be a regular file, not a symlink)", path)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return errors.Wrapf(err, "unable to stat lot database file %s", path)
	}
	if !fi.Mode().IsRegular() {
		return errors.Errorf("lot database file %s is not a regular file (mode %v); refusing to change its ownership", path, fi.Mode())
	}

	if err := f.Chown(uid, gid); err != nil {
		return errors.Wrapf(err, "unable to give lot database file %s to uid %d / gid %d so the storage daemon can open it", path, uid, gid)
	}
	if err := f.Chmod(lotDBFileMode); err != nil {
		return errors.Wrapf(err, "unable to set mode %v on lot database file %s", lotDBFileMode, path)
	}
	return nil
}

// secureSharedLotDB applies openSharedLotDBFile to the database and its SQLite
// sidecars. It is called both before opening the database (so the file is
// created with the right mode and is provably not a symlink) and after, once
// SQLite has had the chance to create -wal/-shm.
func secureSharedLotDB(dbPath string, uid, gid int) error {
	// Only the main database is created here; the sidecars are SQLite's to make.
	if err := openSharedLotDBFile(dbPath, true, uid, gid); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := openSharedLotDBFile(dbPath+suffix, false, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
