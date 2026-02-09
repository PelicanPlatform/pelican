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
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

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

func (o *PosixOrigin) validateExtra(e *OriginExport, _ int) error {
	// Check that UploadTempLocation is not under any StoragePrefix
	// This prevents temporary upload files from being accessible via the federation namespace
	uploadTempLocation := param.Origin_UploadTempLocation.GetString()
	if uploadTempLocation == "" {
		// If not set, it will use the default which is under RunLocation, so no conflict
		return nil
	}

	// Normalize paths for comparison
	uploadTempAbs, err := filepath.Abs(uploadTempLocation)
	if err != nil {
		return errors.Wrapf(err, "unable to resolve absolute path for Origin.UploadTempLocation '%s'", uploadTempLocation)
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
		return errors.Errorf("Origin.UploadTempLocation '%s' cannot be equal to or under StoragePrefix '%s' (export for federation prefix '%s'). "+
			"This would make temporary upload files accessible via the federation namespace, which is a security risk. "+
			"Please configure UploadTempLocation to be outside of all StoragePrefix directories.",
			uploadTempLocation, e.StoragePrefix, e.FederationPrefix)
	}

	return nil
}
