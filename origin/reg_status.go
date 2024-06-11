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

package origin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (
	regStatusEnum string

	// For TTL cache to keep track of namespace registration status
	RegistrationStatus struct {
		Status  regStatusEnum
		EditUrl string
		Msg     string
	}

	// For API response to embed export with the registration status
	exportWithStatus struct {
		Status            regStatusEnum `json:"status"`
		StatusDescription string        `json:"statusDescription"` // detailed description of the current status
		EditUrl           string        `json:"editUrl"`
		server_utils.OriginExport
	}
)

// A TTL cache to save namespace registration status
// The TTL depends on the Status: For Status == StatusRegistrationError, the cache item won't expire,
// meaning a failure registration stays in the cache, until the registration is successful.
// For other Status, TTL is set to 15s, and we won't extend the TTL if there's a successful GET
var registrationsStatus = ttlcache.New(
	ttlcache.WithTTL[string, RegistrationStatus](15*time.Second),
	ttlcache.WithDisableTouchOnHit[string, RegistrationStatus](),
)

var RegistryNotImplErr = errors.New("the running version of the registry didn't implmenet this function")

const (
	RegStatusNotSupported regStatusEnum = "Not Supported"      // Registry does not support this function
	RegCompleted          regStatusEnum = "Completed"          // Registration is completed
	RegIncomplete         regStatusEnum = "Incomplete"         // Registered, but registration is incomplete
	RegError              regStatusEnum = "Registration Error" // Failed to register
)

func SetNamespacesStatus(key string, val RegistrationStatus, ttl time.Duration) {
	registrationsStatus.Set(key, val, ttl)
}

// Fetch the registration status for an array of namespace prefixes
// from the registry
func FetchRegStatus(prefixes []string) (*server_structs.CheckNamespaceCompleteRes, error) {
	fed, err := config.GetFederation(context.Background())
	if err != nil {
		return nil, err
	}
	regUrlStr := fed.NamespaceRegistrationEndpoint

	reqUrl, err := url.JoinPath(regUrlStr, "/api/v1.0/registry/namespaces/check/status")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to join path to registry URL at %s", regUrlStr)
	}
	reqBody := server_structs.CheckNamespaceCompleteReq{Prefixes: prefixes}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode request body")
	}
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest(http.MethodPost, reqUrl, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a request")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the response body")
	}
	if res.StatusCode == 404 || res.StatusCode == 405 {
		log.Warningf("Fetch namespace registration status returns %d, the Pelican registry version is likely < 7.8.0. Fall back to unknown status", res.StatusCode)
		return nil, RegistryNotImplErr
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("response returns %d with body: %s", res.StatusCode, string(resBody))
	}
	resStatus := server_structs.CheckNamespaceCompleteRes{}
	if err := json.Unmarshal(resBody, &resStatus); err != nil {
		return nil, errors.Wrap(err, "failed to decode the response body")
	}
	return &resStatus, nil
}

// Fetch the registration status, generate access token for editing the
// registration at the registry, and store the status to the TTL cache
func FetchAndSetRegStatus(prefixes ...string) error {
	res, err := FetchRegStatus(prefixes)
	if err == RegistryNotImplErr {
		for _, prefix := range prefixes {
			registrationsStatus.Set(
				prefix,
				RegistrationStatus{Status: RegStatusNotSupported, Msg: RegistryNotImplErr.Error()},
				ttlcache.DefaultTTL,
			)
		}
		return nil // If not implemented, we simply set the status to unknown and return
	} else if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		result, ok := res.Results[prefix]
		if !ok {
			return fmt.Errorf("registry response does not contain status for prefix %s", prefix)
		}
		internalStatus := RegIncomplete
		if result.Completed {
			internalStatus = RegCompleted
		}
		registrationsStatus.Set(
			prefix,
			RegistrationStatus{Status: internalStatus, EditUrl: result.EditUrl, Msg: result.Msg},
			ttlcache.DefaultTTL,
		)
	}
	return nil
}

func wrapExportsByStatus(exports []server_utils.OriginExport) ([]exportWithStatus, error) {
	wrappedExports := []exportWithStatus{}
	fetchQ := []server_utils.OriginExport{}
	prefixQ := []string{}

	for _, export := range exports {
		if registrationsStatus.Has(export.FederationPrefix) {
			regStatus := registrationsStatus.Get(export.FederationPrefix).Value()
			wrappedExport := exportWithStatus{
				Status:            regStatus.Status,
				EditUrl:           regStatus.EditUrl,
				StatusDescription: regStatus.Msg,
				OriginExport:      export,
			}
			wrappedExports = append(wrappedExports, wrappedExport)
		} else {
			// If DNE, attempt to fetch
			fetchQ = append(fetchQ, export)
			prefixQ = append(prefixQ, export.FederationPrefix)
		}
	}
	if len(fetchQ) == 0 {
		return wrappedExports, nil
	}

	// fetch and populate the cache with the result in a batch
	if err := FetchAndSetRegStatus(prefixQ...); err != nil {
		return nil, errors.Wrap(err, "failed to fetch registration status from the registry")
	}

	for _, export := range fetchQ {
		if cachedItem := registrationsStatus.Get(export.FederationPrefix); cachedItem != nil {
			regStatus := cachedItem.Value()
			wrappedExport := exportWithStatus{
				Status:            regStatus.Status,
				EditUrl:           regStatus.EditUrl,
				StatusDescription: regStatus.Msg,
				OriginExport:      export,
			}
			wrappedExports = append(wrappedExports, wrappedExport)
		} else {
			log.Errorf("failed to get the registration status from internal cache for %s", export.FederationPrefix)
		}
	}
	return wrappedExports, nil
}
