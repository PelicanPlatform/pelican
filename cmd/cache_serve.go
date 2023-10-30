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
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/xrootd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveCache( /*cmd*/ *cobra.Command /*args*/, []string) error {
	defer config.CleanupTempResources()

	err := xrootd.SetUpMonitoring()
	if err != nil {
		return err
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
