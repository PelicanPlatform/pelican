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
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type Posixv2Origin struct {
	BaseOrigin
}

func (o *Posixv2Origin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStoragePosixv2
}

func (o *Posixv2Origin) validateStoragePrefix(prefix string) error {
	// Storage prefixes need basic path validation but not the federation-specific
	// reserved prefix checks (e.g. /pelican is reserved in the federation namespace
	// but is a valid local storage path).
	return validatePathLikePrefix(prefix)
}
