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
	"fmt"
	"os"
	"os/user"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// checkFileReadableByUser checks if the given user can read the file on Unix systems.
// It examines the file's uid/gid/mode to determine readability.
//
// Note: This is a best-effort check performed at startup. It is subject to a TOCTOU
// (time-of-check-time-of-use) race: file permissions could change between this check and
// when the file is actually read. This is acceptable because the check is intended as an
// early diagnostic to catch common misconfiguration, not as a security gate.
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
	// 2. If pelican user's primary or supplementary group matches file's group and group has read permission
	// 3. If others have read permission
	canRead := false

	if fileUid == puser.Uid {
		// Pelican user owns the file, check owner read permission
		if fileMode&0400 != 0 {
			canRead = true
		}
	} else if fileMode&0040 != 0 && userInGroup(puser, fileGid) {
		// File has group read permission and the pelican user is in the file's group
		// (either via primary GID or supplementary groups)
		canRead = true
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

// userInGroup returns true if the user's primary GID matches fileGid, or if
// fileGid appears in the user's supplementary group list.
func userInGroup(puser User, fileGid int) bool {
	if fileGid == puser.Gid {
		return true
	}

	// Look up supplementary groups for the user
	u, err := user.Lookup(puser.Username)
	if err != nil {
		log.Debugf("Could not look up supplementary groups for user %s: %v", puser.Username, err)
		return false
	}
	groupIds, err := u.GroupIds()
	if err != nil {
		log.Debugf("Could not retrieve supplementary groups for user %s: %v", puser.Username, err)
		return false
	}

	fileGidStr := fmt.Sprintf("%d", fileGid)
	for _, gidStr := range groupIds {
		if gidStr == fileGidStr {
			return true
		}
	}

	return false
}
