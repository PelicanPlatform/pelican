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

package server_ui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	errorResp struct {
		Error string `json:"error"`
	}

	keyStatus int
)

const (
	noKeyPresent keyStatus = iota
	keyMismatch
	keyMatch
)

func keyIsRegistered(privkey jwk.Key, url string, prefix string) (keyStatus, error) {
	keyId := privkey.KeyID()
	if keyId == "" {
		return noKeyPresent, errors.New("Provided key is missing a key ID")
	}
	key, err := privkey.PublicKey()
	if err != nil {
		return noKeyPresent, err
	}

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return noKeyPresent, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pelican-Prefix", prefix)

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return noKeyPresent, err
	}
	defer resp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 404 || resp.StatusCode == 500 {
		// TODO: The registry returns a 500 for unregistered namespaces instead of a 404.
		// It would be better to have an error message in this case but we must instead assume
		// it's an unregistered namespace.
		return noKeyPresent, nil
	} else if resp.StatusCode != 200 {
		var msg errorResp
		if err := json.Unmarshal(body, &msg); err != nil {
			log.Warningln("Failed to unmarshal error message response from namespace registry", err)
		}
		if msg.Error != "" {
			return noKeyPresent, errors.Errorf("Failed to query registry for public key (status code %v): %v", resp.StatusCode, msg.Error)
		} else {
			return noKeyPresent, errors.Errorf("Failed to query registry for public key: status code %v", resp.StatusCode)
		}
	}

	var ns *registry.Namespace
	err = json.Unmarshal(body, &ns)
	if err != nil {
		return noKeyPresent, errors.Errorf("Failed unmarshal namespace from response")
	}

	registrySet, err := jwk.ParseString(ns.Pubkey)
	if err != nil {
		log.Debugln("Failed to parse registry response:", string(body))
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

func registerNamespacePrep() (key jwk.Key, prefix string, registrationEndpointURL string, isRegistered bool, err error) {
	// TODO: We eventually want to be able to export multiple prefixes; at that point, we'll
	// refactor to loop around all the namespaces
	prefix = param.Origin_NamespacePrefix.GetString()
	if prefix == "" {
		err = errors.New("Invalid empty prefix for registration")
		return
	}
	if prefix[0] != '/' {
		err = errors.New("Prefix specified for registration must start with a '/'")
		return
	}

	namespaceEndpoint := param.Federation_RegistryUrl.GetString()
	log.Error(namespaceEndpoint)
	if namespaceEndpoint == "" {
		err = errors.New("No namespace registry specified; try passing the `-f` flag specifying the federation name")
		return
	}

	registrationEndpointURL, err = url.JoinPath(namespaceEndpoint, "api", "v2.0", "registry")
	if err != nil {
		err = errors.Wrap(err, "Failed to construct registration endpoint URL: %v")
		return
	}
	registrationCheckEndpointURL, err := url.JoinPath(registrationEndpointURL, "getNamespace")
	if err != nil {
		err = errors.Wrap(err, "Failed to construct registration check endpoint URL: %v")
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
	keyStatus, err := keyIsRegistered(key, registrationCheckEndpointURL, prefix)
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
		return errors.Wrapf(err, "Failed to register prefix %s", prefix)
	}
	return nil
}

func RegisterNamespaceWithRetry() error {
	metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, "Origin not registered with federation")

	key, prefix, url, isRegistered, err := registerNamespacePrep()
	if err != nil {
		return err
	}
	if isRegistered {
		log.Debugf("Origin already has prefix %v registered\n", prefix)
		return nil
	}

	if err = registerNamespaceImpl(key, prefix, url); err == nil {
		return nil
	}
	log.Errorf("Failed to register with namespace service: %v; will automatically retry in 10 seconds\n", err)
	go func() {
		for {
			time.Sleep(10 * time.Second)
			if err := registerNamespaceImpl(key, prefix, url); err == nil {
				return
			}
			log.Errorf("Failed to register with namespace service: %v; will automatically retry in 10 seconds\n", err)
		}
	}()
	return nil
}
