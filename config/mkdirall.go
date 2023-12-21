/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
