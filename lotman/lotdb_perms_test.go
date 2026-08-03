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
	"path/filepath"
	"testing"
)

// TestSecureSharedLotDBRefusesSymlink is the regression test for the reason the
// ownership pass is descriptor-based. Lotman.LotHome is writable by the storage
// daemon and pelican-server usually runs as root, so a path-based chown/chmod
// there can be redirected at any file on the system by planting a symlink --
// including at one of the -wal/-shm sidecars, which do not exist at first start
// and are therefore free for the taking. O_NOFOLLOW must make the open fail
// before any ownership change happens.
func TestSecureSharedLotDBRefusesSymlink(t *testing.T) {
	lotHome := t.TempDir()
	dbPath := filepath.Join(lotHome, "lots.sqlite")

	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("sensitive"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}

	uid, gid := os.Getuid(), os.Getgid()

	t.Run("database itself", func(t *testing.T) {
		if err := os.Symlink(victim, dbPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		defer func() { _ = os.Remove(dbPath) }()

		if err := secureSharedLotDB(dbPath, uid, gid); err == nil {
			t.Error("secureSharedLotDB followed a symlink at the database path; want an error")
		}
		after, err := os.Stat(victim)
		if err != nil {
			t.Fatalf("stat victim: %v", err)
		}
		if after.Mode() != before.Mode() {
			t.Errorf("victim mode changed %v -> %v through the symlink", before.Mode(), after.Mode())
		}
	})

	t.Run("wal sidecar", func(t *testing.T) {
		// The sidecar case is the sharper one: SQLite creates -wal/-shm lazily,
		// so on a fresh deployment those names are unclaimed.
		if err := os.WriteFile(dbPath, nil, lotDBFileMode); err != nil {
			t.Fatalf("create db: %v", err)
		}
		defer func() { _ = os.Remove(dbPath) }()
		wal := dbPath + "-wal"
		if err := os.Symlink(victim, wal); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		defer func() { _ = os.Remove(wal) }()

		if err := secureSharedLotDB(dbPath, uid, gid); err == nil {
			t.Error("secureSharedLotDB followed a symlink at the -wal sidecar; want an error")
		}
		after, err := os.Stat(victim)
		if err != nil {
			t.Fatalf("stat victim: %v", err)
		}
		if after.Mode() != before.Mode() {
			t.Errorf("victim mode changed %v -> %v through the symlink", before.Mode(), after.Mode())
		}
	})
}

// TestSecureSharedLotDBCreatesGroupSharedFile covers the happy path: the file is
// created if absent and left group-readable/writable (and no wider) so the
// storage daemon can open it while other local accounts cannot.
func TestSecureSharedLotDBCreatesGroupSharedFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lots.sqlite")

	if err := secureSharedLotDB(dbPath, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("secureSharedLotDB: %v", err)
	}

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("database was not created: %v", err)
	}
	if got := fi.Mode().Perm(); got != lotDBFileMode.Perm() {
		t.Errorf("database mode = %v, want %v", got, lotDBFileMode.Perm())
	}
	if fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("database mode %v grants access to other; the lot database must stay owner+group only", fi.Mode().Perm())
	}
	// Absent sidecars are not an error -- SQLite makes them on demand.
	if err := secureSharedLotDB(dbPath, os.Getuid(), os.Getgid()); err != nil {
		t.Errorf("second call (sidecars absent) failed: %v", err)
	}
}
