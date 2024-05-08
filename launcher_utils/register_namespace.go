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

package launcher_utils

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
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	keyStatus int
)

const (
	noKeyPresent keyStatus = iota
	keyMismatch
	keyMatch
)

// Check if a namespace private JWK with namespace prefix from the origin is registered at the given registry.
//
// registryUrlStr is the URL with base path to the registry's API. For Pelican registry,
// this should be https://<registry-host>/api/v1.0/registry
//
// If the prefix is not found in the registry, it returns noKeyPresent with error == nil
// If the prefix is found, but the public key of the private key doesn't match what's in the registry,
// it will return keyMismatch with error == nil. Otherwise, it returns keyMatch
//
// Note that this function will first send a POST request to /api/v1.0/registry/checkNamespaceExists,
// which is the current Pelican registry endpoint. However, OSDF registry and Pelican registry < v7.4.0 doesn't
// have this endpoint, so if calling it returns 404, we will then check using /api/v1.0/registry/<prefix>/.well-known/issuer.jwks,
// which should always give the jwks if it exists.
func keyIsRegistered(privkey jwk.Key, registryUrlStr string, prefix string) (keyStatus, error) {
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		return noKeyPresent, errors.Wrap(err, "Error parsing registryUrlStr")
	}
	keyId := privkey.KeyID()
	if keyId == "" {
		return noKeyPresent, errors.New("Provided key is missing a key ID")
	}
	key, err := privkey.PublicKey()
	if err != nil {
		return noKeyPresent, err
	}

	// We first check against Pelican's registry at /api/v1.0/registry/checkNamespaceExists
	// so that the registry won't give out the public key
	pelicanReqURL := registryUrl.JoinPath("/checkNamespaceExists")
	pubkeyStr, err := json.Marshal(key)
	if err != nil {
		return noKeyPresent, err
	}

	keyCheckReq := server_structs.CheckNamespaceExistsReq{Prefix: prefix, PubKey: string(pubkeyStr)}
	jsonData, err := json.Marshal(keyCheckReq)
	if err != nil {
		return noKeyPresent, errors.Wrap(err, "Error marshaling request to json string")
	}

	req, err := http.NewRequest(http.MethodPost, pelicanReqURL.String(), bytes.NewBuffer(jsonData))

	if err != nil {
		return noKeyPresent, err
	}

	req.Header.Set("Content-Type", "application/json")

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return noKeyPresent, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// For Pelican's registry at /api/v1.0/registry/checkNamespaceExists, it only returns 200, 400, and 500.
	// If it returns 404, that means we are not hitting Pelican's registry but OSDF's registry or Pelican registry < v7.4.0
	if resp.StatusCode != http.StatusNotFound {
		resData := server_structs.CheckNamespaceExistsRes{}
		if err := json.Unmarshal(body, &resData); err != nil {
			log.Warningln("Failed to unmarshal error message response from namespace registry", err)
		}
		switch resp.StatusCode {
		case http.StatusInternalServerError:
			return noKeyPresent, errors.Errorf("Failed to query registry for public key with server error (status code %v): %v", resp.StatusCode, resData.Error)
		case http.StatusBadRequest:
			return noKeyPresent, errors.Errorf("Failed to query registry for public key with a bad request (status code %v): %v", resp.StatusCode, resData.Error)
		case http.StatusOK:
			if !resData.PrefixExists {
				return noKeyPresent, nil
			}
			if !resData.KeyMatch {
				return keyMismatch, nil
			} else {
				return keyMatch, nil
			}
		default:
			return noKeyPresent, errors.Errorf("Failed to query registry for public key with unknown server response (status code %v)", resp.StatusCode)
		}
	}

	// In this case, we got 404 from the first request, so we will try to check against legacy OSDF endpoint at
	// "/api/v1.0/registry/<prefix>/.well-known/issuer.jwks"
	log.Warningf("Getting 404 from checking if key is registered at: %s Fall back to check issuer.jwks", pelicanReqURL.String())

	OSDFReqUrl := registryUrl.JoinPath(prefix, ".well-known", "issuer.jwks")

	OSDFReq, err := http.NewRequest(http.MethodGet, OSDFReqUrl.String(), nil)

	if err != nil {
		return noKeyPresent, err
	}

	req.Header.Set("Content-Type", "application/json")

	OSDFResp, err := client.Do(OSDFReq)
	if err != nil {
		return noKeyPresent, err
	}
	defer OSDFResp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	OSDFBody, _ := io.ReadAll(OSDFResp.Body)

	// 404 is from Pelican issuer.jwks endpoint while 500 is from OSDF endpoint
	if resp.StatusCode == 404 || resp.StatusCode == 500 {
		return noKeyPresent, nil
	} else if resp.StatusCode != 200 {
		resData := server_structs.CheckNamespaceExistsRes{}
		if err := json.Unmarshal(OSDFBody, &resData); err != nil {
			log.Warningln("Failed to unmarshal error message response from namespace registry", err)
		}
		if resData.Error != "" {
			return noKeyPresent, errors.Errorf("Failed to query registry for public key (status code %v): %v", resp.StatusCode, resData.Error)
		} else {
			return noKeyPresent, errors.Errorf("Failed to query registry for public key: status code %v", resp.StatusCode)
		}
	}

	var ns *server_structs.Namespace
	err = json.Unmarshal(OSDFBody, &ns)
	if err != nil {
		log.Error(fmt.Sprintf("Failed unmarshal namespace from response: %v, body: %v, response code: %v, URL: %v", err, OSDFBody, resp.StatusCode, registryUrl))
		return noKeyPresent, errors.Errorf("Failed unmarshal namespace from response")
	}

	registrySet, err := jwk.ParseString(ns.Pubkey)
	if err != nil {
		log.Debugln("Failed to parse registry response:", string(OSDFBody))
		return noKeyPresent, errors.Wrap(err, "Failed to parse registry response as a JWKS")
	}

	registryKey, isPresent := registrySet.LookupKeyID(keyId)
	if !isPresent {
		return keyMismatch, nil
	} else if jwk.Equal(registryKey, key) {
		return keyMatch, nil
	} else {
		return keyMismatch, nil
	}
}

func registerNamespacePrep(ctx context.Context, prefix string) (key jwk.Key, registrationEndpointURL string, isRegistered bool, err error) {
	// TODO: We eventually want to be able to export multiple prefixes; at that point, we'll
	// refactor to loop around all the namespaces
	if prefix == "" {
		err = errors.New("Invalid empty prefix for registration")
		return
	}
	if prefix[0] != '/' {
		err = errors.New("Prefix specified for registration must start with a '/'")
		return
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return
	}
	namespaceEndpoint := fedInfo.NamespaceRegistrationEndpoint
	if namespaceEndpoint == "" {
		err = errors.New("No namespace registry specified; try passing the `-f` flag specifying the federation name")
		return
	}

	registrationEndpointURL, err = url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		err = errors.Wrap(err, "Failed to construct registration endpoint URL: %v")
		return
	}
	key, err = config.GetIssuerPrivateJWK()
	if err != nil {
		err = errors.Wrap(err, "failed to load the origin's JWK")
		return
	}
	if key.KeyID() == "" {
		if err = jwk.AssignKeyID(key); err != nil {
			err = errors.Wrap(err, "Error when generating a key ID for registration")
			return
		}
	}
	keyStatus, err := keyIsRegistered(key, registrationEndpointURL, prefix)
	if err != nil {
		err = errors.Wrap(err, "Failed to determine whether namespace is already registered")
		return
	}
	switch keyStatus {
	case keyMatch:
		isRegistered = true
		return
	case keyMismatch:
		err = errors.Errorf("Namespace %v already registered under a different key", prefix)
		return
	case noKeyPresent:
		log.Infof("Namespace %v not registered; new registration will proceed\n", prefix)
	}
	return
}

func registerNamespaceImpl(key jwk.Key, prefix string, registrationEndpointURL string) error {
	if err := registry.NamespaceRegister(key, registrationEndpointURL, "", prefix); err != nil {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusCritical, fmt.Sprintf("XRootD server failed to register its namespace %s at the registry: %v", prefix, err))
		return errors.Wrapf(err, "Failed to register prefix %s", prefix)
	}
	metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusOK, "")
	return nil
}

// Register the namespace. If failed, retry every 10s (default)
func RegisterNamespaceWithRetry(ctx context.Context, egrp *errgroup.Group, prefix string) error {
	retryInterval := param.Server_RegistrationRetryInterval.GetDuration()
	if retryInterval == 0 {
		log.Warning("Server.RegistrationRetryInterval is 0. Fall back to 10s")
		retryInterval = 10 * time.Second
	}

	key, url, isRegistered, err := registerNamespacePrep(ctx, prefix)
	if err != nil {
		return err
	}
	if isRegistered {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusOK, "")
		log.Debugf("Origin already has prefix %v registered\n", prefix)
		if err := origin.FetchAndSetRegStatus(prefix); err != nil {
			return errors.Wrapf(err, "failed to fetch registration status for the prefix %s", prefix)
		}
		return nil
	}

	if err = registerNamespaceImpl(key, prefix, url); err == nil {
		return nil
	}
	log.Errorf("Failed to register with namespace service: %v; will automatically retry in 10 seconds\n", err)
	// For failed registration, set the status to RegError without a TTL
	origin.SetNamespacesStatus(prefix, origin.RegistrationStatus{Status: origin.RegError}, ttlcache.NoTTL)

	egrp.Go(func() error {
		ticker := time.NewTicker(retryInterval)
		for {
			select {
			case <-ticker.C:
				if err := registerNamespaceImpl(key, prefix, url); err == nil {
					if err := origin.FetchAndSetRegStatus(prefix); err != nil {
						log.Errorf("failed to fetch registration status for the prefix %s: %v", prefix, err)
					}
					return nil
				}
				log.Errorf("Failed to register with namespace service: %v; will automatically retry in 10 seconds\n", err)
			case <-ctx.Done():
				return nil
			}
		}
	})
	return nil
}
