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
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type HTTPSOrigin struct {
	BaseOrigin
}

func (o *HTTPSOrigin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageHTTPS
}

func (o *HTTPSOrigin) validateStoragePrefix(prefix string) error {
	// HTTPS Origins will have posix-like storage prefixes, owing to their prefixes being valid
	// URL paths.
	return validateFederationPrefix(prefix)
}

func (o *HTTPSOrigin) validateExtra(e *OriginExport, numExports int) (err error) {
	httpServiceUrl := param.Origin_HttpServiceUrl.GetString()
	if httpServiceUrl == "" {
		return errors.New("Origin.HTTPServiceUrl is required for HTTPS origins")
	}
	if _, err = url.Parse(httpServiceUrl); err != nil {
		return errors.Wrapf(err, "unable to parse Origin.HTTPServiceUrl '%s'", httpServiceUrl)
	}

	// trailing / isn't handled by the origin, so fix that here
	if strings.HasSuffix(httpServiceUrl, "/") {
		log.Warningln("Removing trailing '/' from http service URL")
		viper.Set(param.Origin_HttpServiceUrl.GetName(), strings.TrimSuffix(httpServiceUrl, "/"))
	}

	if strings.HasSuffix(e.StoragePrefix, "/") {
		log.Warningln("Removing trailing '/' from storage prefix", e.StoragePrefix)
		e.StoragePrefix = strings.TrimSuffix(e.StoragePrefix, "/")
	}

	if numExports > 1 {
		return errors.Errorf("https backend does not yet support multiple exports, but %d were provided", numExports)
	}

	tok := param.Origin_HttpAuthTokenFile.GetString()
	if tok != "" {
		if err = validateFile(filepath.Clean(tok)); err != nil {
			return errors.Wrapf(err, "unable to verify Origin.HTTPAuthTokenFile file '%s'", tok)
		}
	}

	return
}
