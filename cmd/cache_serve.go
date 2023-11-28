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
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/director"
	nsregistry "github.com/pelicanplatform/pelican/namespace_registry"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	CacheServer = server_utils.XRootDServer{
		ServerType:          string(server_utils.CacheType),
		NameSpaceAds:        []director.NamespaceAd{},
		CreateAdvertisement: cache_ui.CreateCacheAdvertisement,
	}
)

func getNSAdsFromDirector() ([]director.NamespaceAd, error) {
	// Get the endpoint of the director
	var respNS []director.NamespaceAd
	directorEndpoint, err := getDirectorEndpoint()
	if err != nil {
		return respNS, errors.Wrapf(err, "Failed to get DirectorURL from config: %v", err)
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpoint, "api", "v1.0", "director", "listNamespaces")
	if err != nil {
		return respNS, err
	}

	respData, err := utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		if jsonErr := json.Unmarshal(respData, &respNS); jsonErr == nil { // Error creating json
			return respNS, errors.Wrapf(err, "Failed to make request: %v", err)
		}
		return respNS, errors.Wrap(err, "Failed to make request")
	}

	err = json.Unmarshal(respData, &respNS)
	if err != nil {
		return respNS, errors.Wrapf(err, "Failed to marshal response in to JSON: %v", err)
	}

	return respNS, nil
}

func serveCache( /*cmd*/ *cobra.Command /*args*/, []string) error {
	// Use this context for any goroutines that needs to react to server shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	// Use this wait group to ensure the goroutines can finish before the server exits/shutdown
	var wg sync.WaitGroup

	// This anonymous function ensures we cancel any context and wait for those goroutines to
	// finish their cleanup work before the server exits
	defer func() {
		shutdownCancel()
		wg.Wait()
		config.CleanupTempResources()
	}()

	err := config.DiscoverFederation()
	if err != nil {
		log.Warningln("Failed to do service auto-discovery:", err)
	}

	wg.Add(1)
	err = xrootd.SetUpMonitoring(shutdownCtx, &wg)
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
	privateKeyRaw, err := config.LoadPrivateKey(privKeyPath)
	if err != nil {
		log.Error("Failed to load private key", err)
		os.Exit(1)
	}
	privKey, err := jwk.FromRaw(privateKeyRaw)
	if err != nil {
		log.Error("Failed to create JWK private key", err)
		os.Exit(1)
	}
	err = nsregistry.NamespaceRegister(privKey, registrationEndpointURL, "", cachePrefix)

	// Check that the error isn't because the prefix is already registered
	if err != nil {
		if !strings.Contains(err.Error(), "The prefix already is registered") {
			log.Errorln("Failed to register cache: ", err)
			os.Exit(1)
		}
	}

	nsAds, err := getNSAdsFromDirector()
	if err != nil {
		return err
	}

	err = checkDefaults(false, nsAds)
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
	err = server_ui.PeriodicAdvertise(CacheServer)

	if err != nil {
		return err
	}

	ctx := context.Background()
	if err = daemon.LaunchDaemons(ctx, launchers); err != nil {
		return err
	}

	log.Info("Clean shutdown of the cache")
	return nil
}
