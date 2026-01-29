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

package config

import (
	"os"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// checkFileReadableByUser checks if the given user can read the file on Unix systems.
// It examines the file's uid/gid/mode to determine readability.
func checkFileReadableByUser(filePath string, fileInfo os.FileInfo, puser User) error {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		// Fallback for any platform where Stat_t isn't available
		log.Warnf("Cannot verify ownership of %s on this platform; ensure the pelican user (%s) can read it", filePath, puser.Username)
		return nil
	}

	fileUid := int(stat.Uid)
	fileGid := int(stat.Gid)
	fileMode := fileInfo.Mode().Perm()

	// Check if the pelican user can read the file:
	// 1. If pelican user owns the file and has read permission (owner read bit)
	// 2. If pelican user's group matches file's group and group has read permission
	// 3. If others have read permission
	canRead := false

	if fileUid == puser.Uid {
		// Pelican user owns the file, check owner read permission
		if fileMode&0400 != 0 {
			canRead = true
		}
	} else if fileGid == puser.Gid || fileGid == 0 {
		// Pelican user's group matches file's group (or root group), check group read permission
		if fileMode&0040 != 0 {
			canRead = true
		}
	} else {
		// Check others read permission
		if fileMode&0004 != 0 {
			canRead = true
		}
	}

	if !canRead {
		return errors.Errorf("TLS file %s is not readable by the pelican user (%s, uid=%d, gid=%d). "+
			"File has owner uid=%d, gid=%d, mode=%04o. "+
			"Please ensure the pelican user can read this file when Server.DropPrivileges is enabled",
			filePath, puser.Username, puser.Uid, puser.Gid, fileUid, fileGid, fileMode)
	}

	return nil
}
