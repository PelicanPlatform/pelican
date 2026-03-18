//go:build windows

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

	"github.com/pelicanplatform/pelican/server_structs"
)

// PosixOrigin is a stub for Windows where POSIX filesystem origins are not supported.
type PosixOrigin struct {
	BaseOrigin
}

func (o *PosixOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStoragePosix
}

func (o *PosixOrigin) validateStoragePrefix(prefix string) error {
	return validateFederationPrefix(prefix)
}

func (o *PosixOrigin) validateExtra(_ *OriginExport, _ int) error {
	return errors.New("POSIX origins are not supported on Windows")
}
