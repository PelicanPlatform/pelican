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
	"net/url"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type XRootOrigin struct {
	BaseOrigin
}

func (o *XRootOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageXRoot
}

func (o *XRootOrigin) validateStoragePrefix(prefix string) error {
	// XRoot Origins will have posix-like storage prefixes
	return validateFederationPrefix(prefix)
}

func (o *XRootOrigin) validateExtra(e *OriginExport, numExports int) (err error) {
	if e.FederationPrefix != e.StoragePrefix {
		return errors.Errorf("FederationPrefix and StoragePrefix must be the same for XRoot origins, but you configured '%s' and '%s'", e.FederationPrefix, e.StoragePrefix)
	}

	xRootServiceUrl := param.Origin_XRootServiceUrl.GetString()
	if xRootServiceUrl == "" {
		return errors.New("Origin.XRootServiceUrl is required for XRoot origins")
	}
	if _, err = url.Parse(xRootServiceUrl); err != nil {
		return errors.Wrapf(err, "unable to parse Origin.XRootServiceUrl '%s'", xRootServiceUrl)
	}
	return
}
