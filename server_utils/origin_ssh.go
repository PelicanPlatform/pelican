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
	"github.com/pelicanplatform/pelican/server_structs"
)

// SSHOrigin represents an origin that uses SSH to access remote storage
type SSHOrigin struct {
	BaseOrigin
}

func (o *SSHOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageSSH
}

func (o *SSHOrigin) validateStoragePrefix(prefix string) error {
	// For SSH origins, the storage prefix is validated the same way we validate
	// the federation prefix (it's a remote path on the SSH host).
	return validateFederationPrefix(prefix)
}
