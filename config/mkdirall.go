/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/pkg/errors"
)

// This is the pelican version of `MkdirAll`; ensures that any created directory
// is owned by a given uid/gid.  This allows the created directory to be owned by
// the xrootd user.
// The base implementation is taken from the go std library, here:
// - https://cs.opensource.google/go/go/+/refs/tags/go1.21.0:src/os/path.go;l=18
// The BSD license for go is compatible with pelican's
func MkdirAll(path string, perm os.FileMode, uid int, gid int) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = MkdirAll(fixRootDirectory(path[:j-1]), perm, uid, gid)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}

	user, err := GetDaemonUser()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}

	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", path, "/grant", user+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown directory %v to groupname %v: %s",
				path, groupname, string(output))
		}
		return nil
	} else { // Else we are running on linux/mac
		if err = os.Chown(path, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown directory %v to groupname %v",
				path, groupname)
		}
	}
	return nil
}

func setFileAndDirPerms(paths []string, dirPerm os.FileMode, perm os.FileMode, uid int, gid int, recursive bool) error {
	dirs := map[string]bool{}
	for _, path := range paths {
		// Create the parent directory if it doesn't exist
		dir := filepath.Dir(path)
		err := MkdirAll(dir, dirPerm, uid, gid)
		if err != nil {
			return errors.Wrapf(err, "Failed to create directory %v", dir)
		}
		// Set the permissions on the parent directory
		err = os.Chmod(dir, dirPerm)
		if err != nil {
			return errors.Wrapf(err, "Failed to set permissions on directory %v", dir)
		}
		if err = os.Chown(dir, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown directory %v", dir)
		}
		if recursive {
			dirs[dir] = true
		}
		// Skip the file if it doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		// Set the permissions on the file
		if err = os.Chmod(path, perm); err != nil {
			return errors.Wrapf(err, "Failed to set permissions on file %v", path)
		}
		if err = os.Chown(path, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown file %v", path)
		}
	}
	// Set the permissions on all sub-directories, when recursive is set to true
	for dir := range dirs {
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			itemPerm := perm
			if d.IsDir() {
				itemPerm = dirPerm
			}
			if err = os.Chmod(path, itemPerm); err != nil {
				return errors.Wrapf(err, "Failed to set permissions on directory %v", path)
			}
			if err = os.Chown(path, uid, gid); err != nil {
				return errors.Wrapf(err, "Failed to chown directory %v", path)
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "Failed to walk directory %v", dir)
		}
	}
	return nil
}

func setDirPerms(paths []string, dirPerm os.FileMode, perm os.FileMode, uid int, gid int, recursive bool) error {
	dirs := map[string]bool{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		dirs[path] = true
	}
	for dir := range dirs {
		err := MkdirAll(dir, dirPerm, uid, gid)
		if err != nil {
			return errors.Wrapf(err, "Failed to create directory %v", dir)
		}
		err = os.Chmod(dir, dirPerm)
		if err != nil {
			return errors.Wrapf(err, "Failed to set permissions on directory %v", dir)
		}
		if err = os.Chown(dir, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown directory %v", dir)
		}
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			itemPerm := perm
			if d.IsDir() {
				itemPerm = dirPerm
			}
			if err = os.Chmod(path, itemPerm); err != nil {
				return errors.Wrapf(err, "Failed to set permissions on directory %v", path)
			}
			if err = os.Chown(path, uid, gid); err != nil {
				return errors.Wrapf(err, "Failed to chown directory %v", path)
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "Failed to walk directory %v", dir)
		}
	}
	return nil
}
