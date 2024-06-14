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
	"fmt"
	"net/url"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/xrootd"
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

func CheckDefaults(server server_structs.XRootDServer) error {
	requiredConfigs := []param.StringParam{param.Server_TLSCertificate, param.Server_TLSKey, param.Xrootd_RobotsTxtFile}
	for _, configName := range requiredConfigs {
		mgr := configName.GetString()
		if mgr == "" {
			return errors.New(fmt.Sprintf("Required value of '%v' is not set in config",
				configName))
		}
	}

	runDir := param.Origin_RunLocation.GetString()
	paramName := "param.Origin_RunLocation"
	if server.GetServerType().IsEnabled(config.CacheType) {
		runDir = param.Cache_RunLocation.GetString()
		paramName = "param.Cache_RunLocation"
	}

	if runDir == "" {
		return errors.New(fmt.Sprintf("Required value of '%v' is not set in config",
			paramName))
	}

	if managerHost := param.Xrootd_ManagerHost.GetString(); managerHost == "" {
		log.Debug("No manager host specified for the cmsd process in origin; assuming no xrootd protocol support")
		viper.SetDefault("Origin.EnableCmsd", false)
		metrics.DeleteComponentHealthStatus("cmsd")
	} else {
		viper.SetDefault("Origin.EnableCmsd", true)
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

	if err := xrootd.CheckXrootdEnv(server); err != nil {
		return err
	}

	// Check that OriginUrl is defined in the config file. Make sure it parses.
	// Fail if either condition isn't met, although note that url.Parse doesn't
	// generate errors for many things that are not recognizable urls.

	if server.GetServerType().IsEnabled(config.CacheType) {
		cacheUrlStr := param.Cache_Url.GetString()
		if cacheUrlStr == "" {
			return errors.New("CacheUrl must be configured to serve a cache")
		}

		if _, err := url.Parse(cacheUrlStr); err != nil {
			return errors.Wrapf(err, "Could not parse the provided CacheUrl (%v)", cacheUrlStr)
		}
	} else {
		originUrlStr := param.Origin_Url.GetString()
		if originUrlStr == "" {
			return errors.New("OriginUrl must be configured to serve an origin")
		}
		if _, err := url.Parse(originUrlStr); err != nil {
			return errors.Wrapf(err, "Could not parse the provided OriginUrl (%v)", originUrlStr)
		}
	}

	return nil
}
