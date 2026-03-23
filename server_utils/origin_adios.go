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
	"net/url"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// ADIOSOrigin is the native (non-XRootD) ADIOS HTTP backend.
type ADIOSOrigin struct {
	BaseOrigin
}

func (o *ADIOSOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageAdios
}

func (o *ADIOSOrigin) validateStoragePrefix(prefix string) error {
	// ADIOS storage prefixes represent URL-like paths.
	return validateFederationPrefix(prefix)
}

func (o *ADIOSOrigin) validateExtra(e *OriginExport, _ int) (err error) {
	adiosServiceURL := param.Origin_AdiosServiceUrl.GetString()
	if adiosServiceURL == "" {
		return errors.Errorf("%s is required for ADIOS origins", param.Origin_AdiosServiceUrl.GetName())
	}
	if _, err = url.Parse(adiosServiceURL); err != nil {
		return errors.Wrapf(err, "unable to parse %s value '%s'", param.Origin_AdiosServiceUrl.GetName(), adiosServiceURL)
	}
	if e.StoragePrefix == "" {
		return errors.New("StoragePrefix is required for ADIOS origins")
	}
	return nil
}
