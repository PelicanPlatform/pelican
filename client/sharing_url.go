/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	"context"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

func CreateSharingUrl(ctx context.Context, objectUrl *url.URL, isWrite bool) (string, error) {
	pUrl, err := ParseRemoteAsPUrl(ctx, objectUrl.String())
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse remote path")
	}

	log.Debugln("Will query director for path", pUrl.Path)
	dirResp, err := queryDirector(ctx, "GET", pUrl, "")
	if err != nil {
		log.Errorln("Error while querying the Director:", err)
		return "", errors.Wrapf(err, "Error while querying the director at %s", pUrl.FedInfo.DirectorEndpoint)
	}
	parsedDirResp, err := ParseDirectorInfo(dirResp)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to parse response from director at %s", pUrl.FedInfo.DirectorEndpoint)
	}

	opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}
	if isWrite {
		opts.Operation = config.TokenSharedWrite
	}
	token, err := AcquireToken(pUrl.GetRawUrl(), parsedDirResp, opts)
	if err != nil {
		err = errors.Wrap(err, "Failed to acquire token")
	}
	return token, err
}
