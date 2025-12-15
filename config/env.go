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

package config

import (
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// Bind environment variables with non-Pelican prefixes (i.e. OSDF/STASH) to correct Pelican config keys
func bindNonPelicanEnv() {
	prefix := GetPreferredPrefix()
	if prefix != PelicanPrefix {
		found := false
		envs := os.Environ()
		for _, env := range envs {
			if strings.HasPrefix(env, prefix.String()+"_") { // OSDF_ | STASH_
				if !found {
					log.Warningf("Environment variables with %s prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.", prefix.String())
					found = true
				}
				osdfKey := strings.SplitN(env, "=", 2)[0]                                                   // OSDF_FOO_BAR
				viperKey := strings.Replace(strings.TrimPrefix(osdfKey, prefix.String()+"_"), "_", ".", -1) // FOO.BAR
				if err := viper.BindEnv(viperKey, osdfKey); err != nil {
					log.Errorf("Error binding environment variable %s to configuration parameter %s: %v", osdfKey, viperKey, err)
				}
			}
		}
	}
}

// bindLegacyClientEnv handles legacy/grandfathered client environment variables that use
// non-standard naming conventions (e.g., STASHCP_*, OSG_*, NEAREST_CACHE, etc.).
// This should be called from InitClient after InitConfigInternal has set up the base viper config.
func bindLegacyClientEnv() {
	prefixes := GetAllPrefixes()
	prefixes_with_osg := append(prefixes, "OSG")

	// Handle DISABLE_HTTP_PROXY
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix.String() + "_DISABLE_HTTP_PROXY"); isSet {
			viper.Set(param.Client_DisableHttpProxy.GetName(), true)
			break
		}
	}

	// Handle DISABLE_PROXY_FALLBACK
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix.String() + "_DISABLE_PROXY_FALLBACK"); isSet {
			viper.Set(param.Client_DisableProxyFallback.GetName(), true)
			break
		}
	}

	// Handle DIRECTOR_URL
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_DIRECTOR_URL"); isSet {
			viper.Set("Federation.DirectorURL", val)
			break
		}
	}

	// Handle NAMESPACE_URL
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_NAMESPACE_URL"); isSet {
			viper.Set("Federation.RegistryUrl", val)
			break
		}
	}

	// Handle TOPOLOGY_NAMESPACE_URL
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_TOPOLOGY_NAMESPACE_URL"); isSet {
			viper.Set(param.Federation_TopologyNamespaceUrl.GetName(), val)
			break
		}
	}

	// Handle MINIMUM_DOWNLOAD_SPEED (including STASHCP_* variants)
	var prefixes_with_cp []ConfigPrefix
	for _, prefix := range prefixes {
		prefixes_with_cp = append(prefixes_with_cp, prefix+"CP")
	}
	for _, prefix := range append(prefixes, prefixes_with_cp...) {
		downloadLimitStr := os.Getenv(prefix.String() + "_MINIMUM_DOWNLOAD_SPEED")
		if len(downloadLimitStr) == 0 {
			continue
		}
		downloadLimit, err := strconv.ParseInt(downloadLimitStr, 10, 64)
		if err != nil {
			log.Errorf("Environment variable %s_MINIMUM_DOWNLOAD_SPEED=%s is not parsable as integer: %s",
				prefix, downloadLimitStr, err.Error())
			continue
		}
		if downloadLimit < 0 {
			log.Errorf("Environment variable %s_MINIMUM_DOWNLOAD_SPEED=%s is negative value; ignoring and will use "+
				"built-in default of %v", prefix, downloadLimitStr, viper.Get(param.Client_MinimumDownloadSpeed.GetName()))
			continue
		}

		// Backward compatibility environment variables do not overwrite the new-style ones
		viper.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), downloadLimit)

		break
	}

	// Handle legacy config for (PELICAN_)NEAREST_CACHE
	if configuredCaches, isSet := os.LookupEnv("NEAREST_CACHE"); isSet {
		log.Warningf("You are using a legacy/deprecated parameter 'NEAREST_CACHE' to indicate preferred caches. Please use %s instead", param.Client_PreferredCaches.GetName())
		viper.Set(param.Client_PreferredCaches.GetName(), strings.Split(configuredCaches, ","))
	} else {
		for _, prefix := range prefixes {
			if val, isSet := os.LookupEnv(prefix.String() + "_NEAREST_CACHE"); isSet {
				log.Warningf("You are using a legacy/deprecated parameter '%s_NEAREST_CACHE' to indicate preferred caches. Please use %s instead", prefix.String(), param.Client_PreferredCaches.GetName())
				viper.Set(param.Client_PreferredCaches.GetName(), strings.Split(val, ","))
				break
			}
		}
	}
}
