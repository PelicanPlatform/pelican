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

import "github.com/pelicanplatform/pelican/server_structs"

// Globusv2Origin is the native (non-XRootD) Globus backend.
// It reuses the same configuration and validation as GlobusOrigin.
type Globusv2Origin struct {
	GlobusOrigin
}

func (o *Globusv2Origin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageGlobusv2
}
