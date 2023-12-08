/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
)

// For calling from within the server. Returns the server's issuer URL/port
func GetServerIssuerURL() (*url.URL, error) {
	if param.Server_IssuerUrl.GetString() == "" {
		return nil, errors.New("The server failed to determine its own issuer url. Something is wrong!")
	}

	issuerUrl, err := url.Parse(param.Server_IssuerUrl.GetString())
	if err != nil {
		return nil, errors.Wrapf(err, "The server's issuer URL is malformed: %s. Something is wrong!", param.Server_IssuerUrl.GetString())
	}

	return issuerUrl, nil
}
