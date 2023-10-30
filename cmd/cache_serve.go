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
	"net/url"
	"os"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	nsregistry "github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/xrootd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

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

	err = checkDefaults(false)
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

	if err = daemon.LaunchDaemons(launchers); err != nil {
		return err
	}

	log.Info("Clean shutdown of the cache")
	return nil
}
