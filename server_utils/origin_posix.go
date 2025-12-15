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
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
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

// validateStoragePrefixNotRoot rejects StoragePrefix values that resolve to "/".
// Exporting the entire root filesystem is dangerous: anyone with write access could
// overwrite security-policy files (e.g. auth/scitokens configuration), and every
// absolute path on the system becomes reachable through the federation namespace.
func (o *PosixOrigin) validateStoragePrefixNotRoot(e *OriginExport) error {
	storageAbs, err := filepath.Abs(e.StoragePrefix)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for StoragePrefix '%s'", e.StoragePrefix)
	}

	if storageAbs == "/" {
		return errors.Errorf("StoragePrefix '%s' resolves to the root filesystem '/' "+
			"(export for federation prefix '%s'). Exporting '/' would make the entire filesystem accessible "+
			"through the federation namespace, allowing overwrites of security-policy files and other sensitive data. "+
			"Please use a more specific StoragePrefix.",
			e.StoragePrefix, e.FederationPrefix)
	}

	return nil
}

// validateTempUploadLocation ensures that Origin.UploadTempLocation does not fall
// under any export's StoragePrefix. If it did, in-progress upload files would be
// reachable via the federation namespace, bypassing POSC's path-based isolation.
func (o *PosixOrigin) validateTempUploadLocation(e *OriginExport) error {
	uploadTempLocation := param.Origin_UploadTempLocation.GetString()
	if uploadTempLocation == "" {
		// If not set, it will use the default which is under RunLocation, so no conflict
		return nil
	}

	// Normalize paths for comparison
	uploadTempAbs, err := filepath.Abs(uploadTempLocation)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for %s '%s'", param.Origin_UploadTempLocation.GetName(), uploadTempLocation)
	}

	storageAbs, err := filepath.Abs(e.StoragePrefix)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for StoragePrefix '%s'", e.StoragePrefix)
	}

	// Check if UploadTempLocation is equal to or under StoragePrefix
	rel, err := filepath.Rel(storageAbs, uploadTempAbs)
	if err != nil {
		// This shouldn't happen if both paths are absolute, but handle it gracefully
		return errors.Wrapf(err, "unable to determine relationship between StoragePrefix '%s' and UploadTempLocation '%s'", e.StoragePrefix, uploadTempLocation)
	}

	// If rel doesn't start with "..", then uploadTempLocation is equal to or under storagePrefix
	// rel == "." means they're equal, and rel without ".." prefix means uploadTempLocation is under storagePrefix
	if !strings.HasPrefix(rel, "..") {
		return errors.Errorf("%s '%s' cannot be equal to or under StoragePrefix '%s' (export for federation prefix '%s'). "+
			"This would make temporary upload files accessible via the federation namespace, which is a security risk. "+
			"Please configure UploadTempLocation to be outside of all StoragePrefix directories.",
			param.Origin_UploadTempLocation.GetName(), uploadTempLocation, e.StoragePrefix, e.FederationPrefix)
	}

	return nil
}

func (o *PosixOrigin) validateExtra(e *OriginExport, _ int) error {
	if err := o.validateStoragePrefixNotRoot(e); err != nil {
		return err
	}
	if err := o.validateTempUploadLocation(e); err != nil {
		return err
	}
	if err := ValidatePosixPermissions(e.StoragePrefix, e.Capabilities, e.FederationPrefix); err != nil {
		return err
	}

	return nil
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
