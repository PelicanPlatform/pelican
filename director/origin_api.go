/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	// namespaceKeys caches jwks from various origins.
	// The cache key is jwks endpoint (e.g. https://example.com/path/to/issuer.jwks).
	// TTL cache is thread-safe
	namespaceKeys = ttlcache.New(ttlcache.WithTTL[string, jwk.Set](15 * time.Minute))

	adminApprovalErr error
)

func checkNamespaceStatus(prefix string, registryWebUrlStr string) (bool, error) {
	registryUrl, err := url.Parse(registryWebUrlStr)
	if err != nil {
		return false, err
	}
	reqUrl := registryUrl.JoinPath("/api/v1.0/registry/checkNamespaceStatus")

	reqBody := server_structs.CheckNamespaceStatusReq{Prefix: prefix}
	reqByte, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest(http.MethodPost, reqUrl.String(), bytes.NewBuffer(reqByte))
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	if res.StatusCode != 200 {
		if res.StatusCode == 404 {
			// This is when we hit a legacy OSDF registry (or Pelican registry <= 7.4.0) which doesn't have such endpoint
			log.Warningf("Request %q hit 404, either it's an OSDF registry or Pelican registry <= 7.4.0. Fallback to return true for approval status check", reqUrl.String())
			return true, nil
		} else {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				return false, errors.New(fmt.Sprintf("Registry returns error when checkNamespaceStatus %d and can't get the response body %v", res.StatusCode, err))
			} else {
				return false, errors.New(fmt.Sprintf("Registry returns error when checkNamespaceStatus %d with body %s", res.StatusCode, string(body)))
			}
		}
	}

	resBody := server_structs.CheckNamespaceStatusRes{}
	bodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(bodyByte, &resBody); err != nil {
		return false, err
	}

	return resBody.Approved, nil
}

// Given a token and a location in the namespace to advertise in,
// see if the entity is authorized to advertise an origin for the
// namespace
func verifyAdvertiseToken(ctx context.Context, token, namespace string) (bool, error) {
	issuerUrl, err := server_utils.GetNSIssuerURL(namespace)
	if err != nil {
		return false, errors.Wrap(err, "failed to get issuer for namespace "+namespace)
	}

	keyLoc, err := server_utils.GetJWKSURLFromIssuerURL(issuerUrl)
	if err != nil {
		return false, errors.Wrap(err, "failed to get JWKS URL from the issuer URL at "+issuerUrl)
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return false, err
	}
	regUrlStr := fedInfo.RegistryEndpoint

	approved, err := checkNamespaceStatus(namespace, regUrlStr)
	if err != nil {
		return false, errors.Wrap(err, "failed to check namespace approval status")
	}
	if !approved {
		adminApprovalErr = errors.New(namespace + " has not been approved by an administrator")
		return false, adminApprovalErr
	}

	log.Debugln("Attempting to fetch keys from ", keyLoc)
	var keyset jwk.Set

	item := namespaceKeys.Get(keyLoc)
	if item != nil {
		if !item.IsExpired() {
			keyset = item.Value()
		}
	}

	if keyset == nil {
		tr := config.GetTransport()
		keyset, err = utils.GetJwks(ctx, tr, keyLoc)
		if err != nil {
			return false, errors.Wrapf(err, "failed to get jwks at %s", keyLoc)
		}
		customTTL := param.Director_AdvertisementTTL.GetDuration()
		if customTTL == 0 {
			namespaceKeys.Set(keyLoc, keyset, ttlcache.DefaultTTL)
		} else {
			namespaceKeys.Set(keyLoc, keyset, customTTL)
		}
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(keyset), jwt.WithValidate(true))
	if err != nil {
		return false, err
	}

	scope_any, present := tok.Get("scope")
	if !present {
		return false, errors.New("no scope is present; required to advertise to director")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}

	scopes := strings.Split(scope, " ")

	for _, scope := range scopes {
		if scope == token_scopes.Pelican_Advertise.String() {
			return true, nil
		}
	}
	return false, nil
}
