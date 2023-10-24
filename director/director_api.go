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

package director

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// List all namespaces from origins registered at the director
func ListNamespacesFromOrigins() []NamespaceAd {

	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()

	serverAdItems := serverAds.Items()
	namespaces := make([]NamespaceAd, 0, len(serverAdItems))
	for _, item := range serverAdItems {
		if item.Key().Type == OriginType {
			namespaces = append(namespaces, item.Value()...)
		}
	}
	return namespaces
}

func LoadDirectorPublicKey() (*jwk.Key, error) {
	directorDiscoveryUrlStr := param.Federation_DirectorUrl.GetString()
	if len(directorDiscoveryUrlStr) == 0 {
		return nil, errors.Errorf("Director URL is unset; Can't load director's public key")
	}
	log.Debugln("Director's discovery URL:", directorDiscoveryUrlStr)
	directorDiscoveryUrl, err := url.Parse(directorDiscoveryUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Invalid director URL:", directorDiscoveryUrlStr))
	}
	directorDiscoveryUrl.Scheme = "https"
	directorDiscoveryUrl.Path = directorDiscoveryUrl.Path + "/.well-known/pelican-configuration"

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, directorDiscoveryUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when doing director metadata request creation for: ", directorDiscoveryUrl))
	}

	result, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when doing director metadata lookup to: ", directorDiscoveryUrl))
	}

	if result.Body != nil {
		defer result.Body.Close()
	}

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when doing director metadata read to: ", directorDiscoveryUrl))
	}

	metadata := DiscoveryResponse{}

	err = json.Unmarshal(body, &metadata)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when parsing director metadata at: ", directorDiscoveryUrl))
	}

	jwksUri := metadata.JwksUri

	response, err := client.Get(jwksUri)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when requesting director Jwks URI: ", jwksUri))
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when requesting director Jwks URI: ", jwksUri))
	}
	keys, err := jwk.Parse(contents)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when parsing director's jwks: ", jwksUri))
	}
	key, ok := keys.Key(0)
	if !ok {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when getting director's first public key: ", jwksUri))
	}

	return &key, nil
}
