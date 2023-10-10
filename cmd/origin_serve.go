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
	"crypto/elliptic"
	_ "embed"
	"fmt"
	"net/url"
	"os"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func checkConfigFileReadable(fileName string, errMsg string) error {
	if _, err := os.Open(fileName); errors.Is(err, os.ErrNotExist) {
		return errors.New(fmt.Sprintf("%v: the specified path in the configuration (%v) "+
			"does not exist", errMsg, fileName))
	} else if err != nil {
		return errors.New(fmt.Sprintf("%v; an error occurred when reading %v: %v", errMsg,
			fileName, err.Error()))
	}
	return nil
}

func checkDefaults() error {
	requiredConfigs := []string{"Server.TLSCertificate", "Server.TLSKey", "Xrootd.RunLocation", "Xrootd.RobotsTxtFile"}
	for _, configName := range requiredConfigs {
		mgr := viper.GetString(configName) // TODO: Remove direct access once all parameters are generated
		if mgr == "" {
			return errors.New(fmt.Sprintf("Required value of '%v' is not set in config",
				configName))
		}
	}

	if managerHost := param.Xrootd_ManagerHost.GetString(); managerHost == "" {
		log.Debug("No manager host specified for the cmsd process in origin; assuming no xrootd protocol support")
		viper.SetDefault("Origin.UseCmsd", false)
		metrics.DeleteComponentHealthStatus("cmsd")
	} else {
		viper.SetDefault("Origin.UseCmsd", true)
	}

	// As necessary, generate a private key and corresponding cert
	if err := config.GeneratePrivateKey(param.Server_TLSKey.GetString(), elliptic.P256()); err != nil {
		return err
	}
	if err := config.GenerateCert(); err != nil {
		return err
	}

	// TODO: Could upgrade this to a check for a cert in the file...
	if err := checkConfigFileReadable(param.Server_TLSCertificate.GetString(),
		"A TLS certificate is required to serve HTTPS"); err != nil {
		return err
	}
	if err := checkConfigFileReadable(param.Server_TLSKey.GetString(),
		"A TLS key is required to serve HTTPS"); err != nil {
		return err
	}

	if err := xrootd.CheckXrootdEnv(true); err != nil {
		return err
	}

	// Check that OriginUrl is defined in the config file. Make sure it parses.
	// Fail if either condition isn't met, although note that url.Parse doesn't
	// generate errors for many things that are not recognizable urls.
	originUrlStr := param.Origin_Url.GetString()
	if originUrlStr == "" {
		return errors.New("OriginUrl must be configured to serve an origin")
	}

	if _, err := url.Parse(originUrlStr); err != nil {
		return errors.Wrapf(err, "Could not parse the provided OriginUrl (%v)", originUrlStr)
	}

	return nil
}

func serveOrigin( /*cmd*/ *cobra.Command /*args*/, []string) error {
	defer config.CleanupTempResources()

	err := config.DiscoverFederation()
	if err != nil {
		log.Warningln("Failed to do service auto-discovery:", err)
	}

	err = xrootd.SetUpMonitoring()
	if err != nil {
		return err
	}

	err = checkDefaults()
	if err != nil {
		return err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}
	if err = origin_ui.ConfigureOriginUI(engine); err != nil {
		return err
	}
	if err = origin_ui.PeriodicAdvertiseOrigin(); err != nil {
		return err
	}

	go web_ui.RunEngine(engine)
	if err = metrics.SetComponentHealthStatus("web-ui", "warning", "Authentication not initialized"); err != nil {
		return err
	}

	// Ensure we wait until the origin has been initialized
	// before launching XRootD.
	if err = origin_ui.WaitUntilLogin(); err != nil {
		return err
	}
	if err = metrics.SetComponentHealthStatus("web-ui", "ok", ""); err != nil {
		return err
	}

	configPath, err := xrootd.ConfigXrootd(true)
	if err != nil {
		return err
	}

	if param.Origin_SelfTest.GetBool() {
		go origin_ui.PeriodicSelfTest()
	}

	privileged := param.Origin_Multiuser.GetBool()
	err = xrootd.LaunchXrootd(privileged, configPath)
	if err != nil {
		return err
	}
	log.Info("Clean shutdown of the origin")
	return nil
}
