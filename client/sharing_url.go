/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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

package client

import (
	"net/url"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func CreateSharingUrl(path string, isWrite bool) (string, error) {
	OSDFDirectorUrl := param.Federation_DirectorUrl.GetString()
	dirResp, err := QueryDirector(path, OSDFDirectorUrl)
	if err != nil {
		log.Errorln("Error while querying the Director:", err)
		return "", errors.Wrapf(err, "Error while querying the director at %s", OSDFDirectorUrl)
	}
	namespace, err := CreateNsFromDirectorResp(dirResp)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to parse response from director at %s", OSDFDirectorUrl)
	}

	opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}
	if isWrite {
		opts.Operation = config.TokenSharedWrite
	}
	pathUrl := url.URL{Path: path}
	token, err := AcquireToken(&pathUrl, namespace, opts)
	if err != nil {
		err = errors.Wrap(err, "Failed to acquire token")
	}
	return token, err
}
