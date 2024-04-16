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
	"github.com/pelicanplatform/pelican/param"
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
		StatusDescription string        `json:"status_description"` // detailed description of the current status
		EditUrl           string        `json:"edit_url"`
		server_utils.OriginExport
	}
)

// A TTL cache to save namespace registration status
// The TTL depends on the Status: For Status == StatusRegistrationError, the cache item won't expire,
// meaning a failure registration stays in the cache, until the registration is successful.
// For other Status, TTL is set to 5min
var registrationsStatus = ttlcache.New(ttlcache.WithTTL[string, RegistrationStatus](5 * time.Minute))

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

func FetchNsStatus(prefixes []string) (*server_structs.CheckNamespaceCompleteRes, error) {
	regUrlStr := param.Federation_RegistryUrl.GetString()
	reqUrl, err := url.JoinPath(regUrlStr, "/api/v1.0/registry/checkNamespaceComplete")
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
	if res.StatusCode == 404 {
		log.Warningf("fetch namespace registration status returns 404, the Pelican registry version is likely < 7.8.0. Fall back to unknown status")
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

func FetchAndSetNsStatus(prefix string) error {
	res, err := FetchNsStatus([]string{prefix})
	if err == RegistryNotImplErr {
		registrationsStatus.Set(
			prefix,
			RegistrationStatus{Status: RegStatusNotSupported, Msg: RegistryNotImplErr.Error()},
			ttlcache.DefaultTTL,
		)
	} else if err != nil {
		return err
	}
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

	// fetch and populate the cache with the result
	resStatus, err := FetchNsStatus(prefixQ)
	// For registry <7.8, this function is not supported
	if err == RegistryNotImplErr {
		for _, export := range fetchQ {
			wrappedExport := exportWithStatus{
				Status:       RegStatusNotSupported,
				OriginExport: export,
			}
			wrappedExports = append(wrappedExports, wrappedExport)
			registrationsStatus.Set(
				export.FederationPrefix,
				RegistrationStatus{Status: RegStatusNotSupported, Msg: RegistryNotImplErr.Error()},
				ttlcache.DefaultTTL,
			)
		}
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to fetch registration status from the registry")
	}

	// Populate the fetched items
	for _, export := range fetchQ {
		status, ok := resStatus.Results[export.FederationPrefix]
		if !ok {
			statusErrMsg := fmt.Sprintf("status for the prefix %s was not found from registry response", export.FederationPrefix)
			wrappedExport := exportWithStatus{
				Status:            RegStatusNotSupported,
				StatusDescription: statusErrMsg,
				OriginExport:      export,
			}
			wrappedExports = append(wrappedExports, wrappedExport)
			registrationsStatus.Set(
				export.FederationPrefix,
				RegistrationStatus{Status: RegStatusNotSupported, Msg: statusErrMsg},
				ttlcache.DefaultTTL,
			)
		} else {
			internalStatus := RegIncomplete
			if status.Completed {
				internalStatus = RegCompleted
			}
			wrappedExport := exportWithStatus{
				Status:            internalStatus,
				EditUrl:           status.EditUrl,
				StatusDescription: status.Msg,
				OriginExport:      export,
			}
			wrappedExports = append(wrappedExports, wrappedExport)
			registrationsStatus.Set(
				export.FederationPrefix,
				RegistrationStatus{Status: internalStatus, EditUrl: status.EditUrl, Msg: status.Msg},
				ttlcache.DefaultTTL,
			)
		}
	}

	return wrappedExports, nil
}
