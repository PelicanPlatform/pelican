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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type GlobusOrigin struct {
	BaseOrigin
}

func (o *GlobusOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageGlobus
}

func (o *GlobusOrigin) validateStoragePrefix(prefix string) error {
	// Globus Origins will have posix-like storage prefixes, owing to their prefixes being valid
	// URL paths.
	return validateFederationPrefix(prefix)
}

func (o *GlobusOrigin) validateExtra(e *OriginExport, numExports int) (err error) {
	if e.GlobusCollectionID == "" {
		return errors.Errorf("GlobusCollectionID is required for export '%s'", e.FederationPrefix)
	}

	if e.GlobusCollectionName == "" {
		return errors.Errorf("GlobusCollectionName is required for export '%s'", e.FederationPrefix)
	}

	if viper.GetString(param.OIDC_Issuer.GetName()) != "globus" {
		clientIDFile := param.Origin_GlobusClientIDFile.GetString()
		if clientIDFile == "" {
			return errors.Errorf("%s is a required parameter for Globus origins when 'OIDC.Issuer' is not Globus", param.Origin_GlobusClientIDFile.GetName())
		}
		if err = validateFile(filepath.Clean(clientIDFile)); err != nil {
			return errors.Wrapf(err, "unable to verify Origin.GlobusClientIDFile file '%s'", clientIDFile)
		}

		clientSecretFile := param.Origin_GlobusClientSecretFile.GetString()
		if clientSecretFile == "" {
			return errors.Errorf("%s is a required parameter for Globus origins when 'OIDC.Issuer' is not Globus", param.Origin_GlobusClientSecretFile.GetName())
		}
		if err = validateFile(filepath.Clean(clientSecretFile)); err != nil {
			return errors.Wrapf(err, "unable to verify Origin.GlobusClientSecretFile file '%s'", clientSecretFile)
		}
	}

	return
}

func (o *GlobusOrigin) mapSingleExtra() {
	if len(o.Exports) != 1 {
		return
	}

	e := o.Exports[0]
	if e.GlobusCollectionID != "" {
		if err := param.Set(param.Origin_GlobusCollectionID.GetName(), e.GlobusCollectionID); err != nil {
			log.Warningf("Failed to set %s: %v", param.Origin_GlobusCollectionID.GetName(), err)
		}
	}
	if e.GlobusCollectionName != "" {
		if err := param.Set(param.Origin_GlobusCollectionName.GetName(), e.GlobusCollectionName); err != nil {
			log.Warningf("Failed to set %s: %v", param.Origin_GlobusCollectionName.GetName(), err)
		}
	}
}
