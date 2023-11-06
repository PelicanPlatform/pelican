//go:build !windows

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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	nsregistry "github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type directorResponse struct {
	Error string `json:"error"`
}

func makeRequest(url string, method string, data map[string]interface{}, headers map[string]string) ([]byte, error) {
	payload, _ := json.Marshal(data)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return body, errors.Errorf("The URL %s replied with status code %d", url, resp.StatusCode)
	}

	return body, nil
}

func periodicAdvertiseCache(prefix string, nsAds []director.NamespaceAd) error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := advertiseCache(prefix, nsAds)
		if err != nil {
			log.Warningln("Cache advertise failed:", err)
			if err = metrics.SetComponentHealthStatus("federation", "critical", "Error advertising cache to federation"); err != nil {
				log.Warningln("Failed to update internal component health status:", err)
			}
		} else if err = metrics.SetComponentHealthStatus("federation", "ok", ""); err != nil {
			log.Warningln("Failed to update internal component health status:", err)
		}

		for {
			<-ticker.C
			err := advertiseCache(prefix, nsAds)
			if err != nil {
				log.Warningln("Cache advertise failed:", err)
				if err = metrics.SetComponentHealthStatus("federation", "critical", "Error advertising origin to federation"); err != nil {
					log.Warningln("Failed to update internal component health status:", err)
				}
			} else if err = metrics.SetComponentHealthStatus("federation", "ok", ""); err != nil {
				log.Warningln("Failed to update internal component health status:", err)
			}
		}
	}()

	return nil
}

func advertiseCache(prefix string, nsAds []director.NamespaceAd) error {
	name := param.Xrootd_Sitename.GetString()
	if name == "" {
		return errors.New("Cache name isn't set")
	}

	// TODO: waiting on a different branch to merge origin URL generation
	// The checkdefaults func that runs before the origin is served checks for and
	// parses the originUrl, so it should be safe to just grab it as a string here.
	originUrl := param.Origin_Url.GetString()

	// TODO: Need to figure out where to get some of these values
	//               so that they aren't hardcoded...
	cAd := director.NamespaceAd{
		RequireToken:  true,
		Path:          prefix,
		Issuer:        url.URL{},
		MaxScopeDepth: 3,
		Strategy:      "OAuth2",
		BasePath:      "/",
	}
	ad := director.OriginAdvertise{
		Name:       name,
		URL:        originUrl,
		Namespaces: append(nsAds, cAd),
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, "Failed to generate JSON description of origin")
	}

	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse Federation.DirectorURL")
	}
	directorUrl.Path = "/api/v1.0/director/registerCache"

	token, err := director.CreateAdvertiseToken(prefix)
	if err != nil {
		return errors.Wrap(err, "Failed to generate advertise token")
	}

	req, err := http.NewRequest("POST", directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for director registration")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	userAgent := "pelican-cache/" + client.ObjectClientOptions.Version
	req.Header.Set("User-Agent", userAgent)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return errors.Wrapf(unmarshalErr, "Could not unmarshall the director's response, which responded %v from director registration: %v", resp.StatusCode, resp.Status)
		}
		return errors.Errorf("Error during director registration: %v\n", respErr.Error)
	}

	return nil
}

func serveCache( /*cmd*/ *cobra.Command /*args*/, []string) error {
	defer config.CleanupTempResources()

	err := config.DiscoverFederation()
	if err != nil {
		log.Warningln("Failed to do service auto-discovery:", err)
	}

	err = xrootd.SetUpMonitoring()
	if err != nil {
		return err
	}

	cachePrefix := "/caches/" + param.Xrootd_Sitename.GetString()

	//Should this be the Server.IssuerKey? That doesn't seem to be set anywhere, though.
	privKeyPath := param.IssuerKey.GetString()

	// Get the namespace endpoint
	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Errorln("Failed to get NamespaceURL from config: ", err)
		os.Exit(1)
	}

	// Parse the namespace URL to make sure it's okay
	registrationEndpointURL, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		return err
	}

	// Register the cache prefix in the registry
	err = nsregistry.NamespaceRegister(privKeyPath, registrationEndpointURL, "", cachePrefix)

	// Check that the error isn't because the prefix is already registered
	if err != nil {
		if !strings.Contains(err.Error(), "The prefix already is registered") {
			log.Errorln("Failed to register cache: ", err)
			os.Exit(1)
		}
	}

	// Get the endpoint of the director
	directorEndpoint, err := getDirectorEndpoint()
	if err != nil {
		log.Errorln("Failed to get DirectorURL from config: ", err)
		os.Exit(1)
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpoint, "api", "v1.0", "director", "listNamespaces")
	if err != nil {
		return err
	}

	respData, err := makeRequest(directorNSListEndpointURL, "GET", nil, nil)
	var respNS []director.NamespaceAd
	if err != nil {
		if jsonErr := json.Unmarshal(respData, &respNS); jsonErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", err)
		}
		return errors.Wrap(err, "Failed to make request")
	}
	err = json.Unmarshal(respData, &respNS)
	if err != nil {
		log.Errorln("Failed to marshal response in to JSON: ", err)
		os.Exit(1)
	}

	err = checkDefaults(false, respNS)
	if err != nil {
		return err
	}

	configPath, err := xrootd.ConfigXrootd(false)
	if err != nil {
		return err
	}

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false)
	if err != nil {
		return err
	}
	err = periodicAdvertiseCache(cachePrefix, respNS)

	if err != nil {
		return err
	}

	if err = daemon.LaunchDaemons(launchers); err != nil {
		return err
	}

	log.Info("Clean shutdown of the cache")
	return nil
}
