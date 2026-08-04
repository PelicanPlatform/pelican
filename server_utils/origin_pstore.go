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

package server_utils

import (
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// PStoreOrigin is the Pelican store backend: an encrypted block store on
// local disk, served directly by the pelican process.  See
// docs/pstore-design.md.
type PStoreOrigin struct {
	BaseOrigin
}

func (o *PStoreOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStoragePStore
}

// validateStoragePrefix checks the export's storage prefix as a logical path
// inside the store.
//
// Unlike a POSIX origin's, this prefix is not a filesystem path and must not
// be resolved against the local filesystem: the store's namespace lives in the
// catalog, and the prefix names a subtree within it that need not exist yet.
func (o *PStoreOrigin) validateStoragePrefix(prefix string) error {
	return validatePathLikePrefix(prefix)
}

// validateExtra requires the store location to be configured, since unlike a
// POSIX origin there is no directory to fall back on.
func (o *PStoreOrigin) validateExtra(_ *OriginExport, _ int) error {
	if param.Origin_PStoreLocation.GetString() == "" && param.Origin_PStoreStorageDirs.GetRaw() == nil {
		return errors.Errorf("either %s or %s must be set when the origin storage type is 'pstore'",
			param.Origin_PStoreLocation.GetName(), param.Origin_PStoreStorageDirs.GetName())
	}
	return nil
}
