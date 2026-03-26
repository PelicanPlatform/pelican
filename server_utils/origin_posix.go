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

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Inherit from the base origin
type PosixOrigin struct {
	BaseOrigin
}

func (o *PosixOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStoragePosix
}

func (o *PosixOrigin) validateStoragePrefix(prefix string) error {
	// Storage prefixes need basic path validation but not the federation-specific
	// reserved prefix checks (e.g. /pelican is reserved in the federation namespace
	// but is a valid local storage path).
	return validatePathLikePrefix(prefix)
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

// validateAtomicUploadFilesystem checks that, when atomic uploads are enabled,
// the UploadTempLocation resides on the same filesystem as the export's StoragePrefix.
// The POSC plugin relies on rename(2) to atomically move completed uploads into place,
// and rename(2) returns EXDEV when source and destination are on different filesystems.
func (o *PosixOrigin) validateAtomicUploadFilesystem(e *OriginExport) error {
	if !param.Origin_EnableAtomicUploads.GetBool() {
		return nil
	}

	uploadTempLocation := param.Origin_UploadTempLocation.GetString()
	if uploadTempLocation == "" {
		return errors.Errorf("%s is enabled but %s is empty",
			param.Origin_EnableAtomicUploads.GetName(), param.Origin_UploadTempLocation.GetName())
	}

	uploadTempAbs, err := filepath.Abs(uploadTempLocation)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for %s '%s'",
			param.Origin_UploadTempLocation.GetName(), uploadTempLocation)
	}

	storageAbs, err := filepath.Abs(e.StoragePrefix)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for StoragePrefix '%s'", e.StoragePrefix)
	}

	// Ensure the upload temp directory exists before comparing device IDs.
	if err := os.MkdirAll(uploadTempAbs, 0750); err != nil {
		return errors.Wrapf(err, "unable to create %s directory '%s'",
			param.Origin_UploadTempLocation.GetName(), uploadTempAbs)
	}

	same, err := utils.SameFilesystem(uploadTempAbs, storageAbs)
	if err != nil {
		return errors.Wrapf(err, "unable to determine whether %s '%s' and StoragePrefix '%s' are on the same filesystem",
			param.Origin_UploadTempLocation.GetName(), uploadTempAbs, storageAbs)
	}

	if !same {
		return errors.Errorf("%s '%s' and StoragePrefix '%s' (export for federation prefix '%s') are on different filesystems. "+
			"The atomic upload feature (POSC plugin) relies on rename(2) to move completed uploads into place, "+
			"which cannot work across filesystem boundaries. Please configure %s to be on the same filesystem "+
			"as the export's StoragePrefix, or disable atomic uploads by setting Origin.EnableAtomicUploads to false.",
			param.Origin_UploadTempLocation.GetName(), uploadTempAbs, storageAbs, e.FederationPrefix,
			param.Origin_UploadTempLocation.GetName())
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
	if err := o.validateAtomicUploadFilesystem(e); err != nil {
		return err
	}

	return nil
}
