//go:build !windows

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package server_utils

import (
	"os"
	"syscall"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type PosixOrigin struct {
	BaseOrigin
}

func (o *PosixOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStoragePosix
}

func (o *PosixOrigin) validateStoragePrefix(prefix string) error {
	// For posix origins, the storage prefix is validated the same we we validate
	// the federation prefix.
	return validateFederationPrefix(prefix)
}

// validateExtra checks that the daemon user (xrootd user) has the necessary filesystem
// permissions to perform the operations specified by the export's capabilities.
// This prevents hard-to-diagnose runtime errors by catching permission mismatches at startup.
func (o *PosixOrigin) validateExtra(e *OriginExport, _ int) error {
	return ValidatePosixPermissions(e.StoragePrefix, e.Capabilities, e.FederationPrefix)
}

// ValidatePosixPermissions checks if the daemon user has the required filesystem permissions
// on the given path to support the specified capabilities.
func ValidatePosixPermissions(storagePath string, caps server_structs.Capabilities, federationPrefix string) error {
	// Get XRootD daemon user info
	uid, err := config.GetDaemonUID()
	if err != nil {
		return errors.Wrap(err, "failed to get XRootD daemon UID for permission validation")
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to get XRootD daemon GID for permission validation")
	}
	username, err := config.GetDaemonUser()
	if err != nil {
		username = "username-unknown"
	}

	// Check if the storage prefix exists
	info, err := os.Stat(storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Wrapf(ErrInvalidOriginConfig,
				"storage prefix %q for export %q does not exist",
				storagePath, federationPrefix)
		}
		return errors.Wrapf(err, "failed to stat storage prefix %q for export %q",
			storagePath, federationPrefix)
	}

	// The storage prefix should be a directory
	if !info.IsDir() {
		return errors.Wrapf(ErrInvalidOriginConfig,
			"storage prefix %q for export %q is not a directory",
			storagePath, federationPrefix)
	}

	// Get the directory's owner and group
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.Errorf("failed to get system stat info for %q", storagePath)
	}
	dirUID := int(stat.Uid)
	dirGID := int(stat.Gid)
	mode := info.Mode()

	// Determine which permission bits apply to XRootD daemon user
	var canRead, canWrite, canExecute bool
	if uid == dirUID {
		// User is owner - check owner bits
		canRead = mode&0400 != 0
		canWrite = mode&0200 != 0
		canExecute = mode&0100 != 0
	} else if gid == dirGID {
		// User is in group - check group bits
		canRead = mode&0040 != 0
		canWrite = mode&0020 != 0
		canExecute = mode&0010 != 0
	} else {
		// User is neither owner nor in group - check others bits
		canRead = mode&0004 != 0
		canWrite = mode&0002 != 0
		canExecute = mode&0001 != 0
	}

	// Helper to format permission error message
	formatPermError := func(capability, requiredPerms string) error {
		return errors.Wrapf(ErrInvalidOriginConfig,
			"storage prefix %q for export %q requires %q permissions for the %q user (uid=%d, gid=%d) "+
				"to support the %q capability, but the current permissions are %q (owner uid=%d, gid=%d). "+
				"Please adjust the ownership or permissions of the directory",
			storagePath, federationPrefix, requiredPerms, username, uid, gid,
			capability, mode.Perm().String(), dirUID, dirGID)
	}

	// Check permissions based on capabilities

	// Check reads (PublicReads or Reads) - needs read and execute
	if caps.Reads || caps.PublicReads {
		if !canRead || !canExecute {
			return formatPermError("Reads/PublicReads", "read and execute (r-x)")
		}
	}

	// Check writes - needs write and execute
	if caps.Writes {
		if !canWrite || !canExecute {
			return formatPermError("Writes", "write and execute (-wx)")
		}
	}

	// Check listings - needs read and execute
	if caps.Listings {
		if !canRead || !canExecute {
			return formatPermError("Listings", "read and execute (r-x)")
		}
	}

	return nil
}
