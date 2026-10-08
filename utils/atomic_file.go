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

package utils

import (
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
)

type (
	// AtomicWriteOption adjusts how WriteFileAtomic and WriteFileAtomicFrom
	// create the file.
	AtomicWriteOption func(*atomicWriteOptions)

	atomicWriteOptions struct {
		chown    bool
		uid, gid int
	}
)

// WithOwner sets the file's owner before it is renamed into place, so the file
// never appears under its final name owned by the wrong user. As with os.Chown,
// an id of -1 leaves that id unchanged.
func WithOwner(uid, gid int) AtomicWriteOption {
	return func(o *atomicWriteOptions) {
		o.chown = true
		o.uid = uid
		o.gid = gid
	}
}

// WriteFileAtomic is os.WriteFile for files that something else may be reading:
// a concurrent reader sees either the old contents or the new ones, never the
// empty or half-written file os.WriteFile exposes between truncating and
// writing. See WriteFileAtomicFrom for the details.
func WriteFileAtomic(path string, data []byte, perm os.FileMode, opts ...AtomicWriteOption) error {
	return WriteFileAtomicFrom(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}, opts...)
}

// WriteFileAtomicFrom replaces the file at path with whatever write produces.
//
// The contents go to a temporary file in the same directory, which is given
// mode perm (exactly; the umask does not apply) and any requested owner,
// flushed to stable storage, and only then renamed over path. A reader
// therefore never sees a partial file, and a crash or power cut cannot leave
// path naming a file whose contents were never written. If write or any other
// step fails, path is left untouched and the temporary file is removed.
//
// The directory is opened once, as an os.Root, and every later step (creating
// the temporary file, the rename, syncing the directory) is relative to that
// handle. If the directory is moved or replaced partway through, the steps
// cannot end up split across two directories. Opening the directory does
// follow symlinks in its path, so path must not be in a directory that a
// less-privileged user can swap out from under us.
//
// On Windows the final rename fails if another process has path open, since
// Go opens files there without FILE_SHARE_DELETE; callers that rewrite a file
// periodically simply get an error for that cycle.
func WriteFileAtomicFrom(path string, perm os.FileMode, write func(w io.Writer) error, opts ...AtomicWriteOption) (err error) {
	var o atomicWriteOptions
	for _, opt := range opts {
		opt(&o)
	}

	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	base := filepath.Base(path)

	tmp, tmpName, err := createTempInRoot(root, "."+base+".tmp-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = root.Remove(tmpName)
		}
	}()

	// Mode and owner are set through the open handle, never by name: unlike
	// os.Root.Chmod/Chown, that cannot be redirected through a symlink.
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if o.chown {
		if err = tmp.Chown(o.uid, o.gid); err != nil {
			return err
		}
	}
	if err = write(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = root.Rename(tmpName, base); err != nil {
		return err
	}

	// Make the rename itself durable. Best effort: some platforms (notably
	// Windows) cannot sync a directory, and there the rename's durability is
	// up to the filesystem.
	if d, dErr := root.Open("."); dErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// createTempInRoot is os.CreateTemp for an os.Root, which has no equivalent:
// it creates a new file named prefix plus a random suffix, failing rather than
// reusing a file that already exists.
func createTempInRoot(root *os.Root, prefix string) (*os.File, string, error) {
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, name, err
	}
	return nil, "", &fs.PathError{Op: "createtemp", Path: filepath.Join(root.Name(), prefix+"*"), Err: fs.ErrExist}
}
