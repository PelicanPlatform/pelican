/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	classad "github.com/PelicanPlatform/classad/classad"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

var (
	// The prefix that OSDF- and Stash-named binaries previously mapped
	// wholesale onto configuration keys: OSDF_X_Y set X.Y, whatever the
	// suffix.
	removedOsdfEnvPrefix = "OSDF_"

	// Individual environment variables that only OSDF- and Stash-named
	// binaries previously read. They are listed by name rather than
	// matched by prefix because the prefixes were never mapped wholesale.
	//
	// STASH_USE_TOPOLOGY is omitted because it never had an effect.
	removedOsdfEnvNames = []string{
		"STASH_DIRECTOR_URL",
		"STASH_DISABLE_HTTP_PROXY",
		"STASH_DISABLE_PROXY_FALLBACK",
		"STASH_MAXMINDKEY",
		"STASH_MINIMUM_DOWNLOAD_SPEED",
		"STASH_NAMESPACE_URL",
		"STASH_NEAREST_CACHE",
		"STASH_TOPOLOGY_NAMESPACE_URL",
		"OSDFCP_MINIMUM_DOWNLOAD_SPEED",
		"STASHCP_MINIMUM_DOWNLOAD_SPEED",
	}

	// Individual environment variables Pelican previously read regardless
	// of the binary name.
	removedEnvNames = []string{
		"NEAREST_CACHE",
		"OSG_DISABLE_HTTP_PROXY",
		"OSG_DISABLE_PROXY_FALLBACK",
		"PELICANCP_MINIMUM_DOWNLOAD_SPEED",
	}

	// Config initialization may run several times, but the warning about
	// removed environment variables is emitted at most once per process.
	warnRemovedEnvOnce sync.Once
)

// isRemovedEnv reports whether name is an environment variable that
// Pelican no longer reads. isOsdf includes the names that only OSDF- and
// Stash-named binaries read.
func isRemovedEnv(name string, isOsdf bool) bool {
	// Windows environment variable names are case-insensitive.
	if runtime.GOOS == "windows" {
		name = strings.ToUpper(name)
	}
	if slices.Contains(removedEnvNames, name) {
		return true
	}
	return isOsdf && (slices.Contains(removedOsdfEnvNames, name) ||
		strings.HasPrefix(name, removedOsdfEnvPrefix))
}

// warnRemovedEnv warns, once per process, about environment variables
// that Pelican no longer reads.
func warnRemovedEnv() {
	// Only an osdf* or stash*-named binary ever read the OSDF-branded names.
	isOsdf := GetPreferredPrefix() == OsdfPrefix

	found := make([]string, 0)
	for _, env := range os.Environ() {
		name := strings.SplitN(env, "=", 2)[0]
		if isRemovedEnv(name, isOsdf) {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return
	}
	warnRemovedEnvOnce.Do(func() {
		// Sort so that the message is deterministic regardless of environment order.
		slices.Sort(found)
		// Quote the names so that an embedded newline cannot forge a second log entry.
		quoted := make([]string, len(found))
		for i, name := range found {
			quoted[i] = strconv.Quote(name)
		}
		log.Warningf("Ignoring environment variable(s) %s: Pelican no longer reads configuration "+
			"from these variables. Please use the equivalent PELICAN_ variable instead.",
			strings.Join(quoted, ", "))
	})
}

// bindLegacyClientEnv handles legacy/grandfathered client environment variables that use
// non-standard naming conventions (e.g., PELICAN_DIRECTOR_URL, PELICAN_NEAREST_CACHE, etc.).
// This should be called from InitClient after InitConfigInternal has set up the base viper config.
func bindLegacyClientEnv() {
	// Handle DISABLE_HTTP_PROXY
	if _, isSet := os.LookupEnv("PELICAN_DISABLE_HTTP_PROXY"); isSet {
		viper.Set(param.Client_DisableHttpProxy.GetName(), true)
	}

	// Handle DISABLE_PROXY_FALLBACK
	if _, isSet := os.LookupEnv("PELICAN_DISABLE_PROXY_FALLBACK"); isSet {
		viper.Set(param.Client_DisableProxyFallback.GetName(), true)
	}

	// Handle DIRECTOR_URL
	if val, isSet := os.LookupEnv("PELICAN_DIRECTOR_URL"); isSet {
		viper.Set(param.Federation_DirectorUrl.GetName(), val)
	}

	// Handle NAMESPACE_URL
	if val, isSet := os.LookupEnv("PELICAN_NAMESPACE_URL"); isSet {
		viper.Set(param.Federation_RegistryUrl.GetName(), val)
	}

	// Handle TOPOLOGY_NAMESPACE_URL
	if val, isSet := os.LookupEnv("PELICAN_TOPOLOGY_NAMESPACE_URL"); isSet {
		viper.Set(param.Federation_TopologyNamespaceUrl.GetName(), val)
	}

	// Handle MINIMUM_DOWNLOAD_SPEED
	if downloadLimitStr := os.Getenv("PELICAN_MINIMUM_DOWNLOAD_SPEED"); len(downloadLimitStr) > 0 {
		downloadLimit, err := strconv.ParseInt(downloadLimitStr, 10, 64)
		if err != nil {
			log.Errorf("Environment variable PELICAN_MINIMUM_DOWNLOAD_SPEED=%s is not parsable as integer: %s",
				downloadLimitStr, err.Error())
		} else if downloadLimit < 0 {
			log.Errorf("Environment variable PELICAN_MINIMUM_DOWNLOAD_SPEED=%s is a negative value; ignoring and using "+
				"default of %v", downloadLimitStr, viper.Get(param.Client_MinimumDownloadSpeed.GetName()))
		} else {
			// Backward compatibility environment variables do not overwrite the new-style ones
			viper.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), downloadLimit)
		}
	}

	// Handle legacy config for PELICAN_NEAREST_CACHE
	if val, isSet := os.LookupEnv("PELICAN_NEAREST_CACHE"); isSet {
		log.Warningf("You are using a legacy/deprecated parameter 'PELICAN_NEAREST_CACHE' to indicate preferred caches. Please use %s instead", param.Client_PreferredCaches.GetName())
		viper.Set(param.Client_PreferredCaches.GetName(), strings.Split(val, ","))
	}
}

// bindClassAdConfig reads configuration from the HTCondor job ClassAd file.
// It looks for attributes prefixed with "PelicanCfg_" and converts them to Pelican configuration.
// For example, "PelicanCfg_Client_PreferredCaches" becomes "Client.PreferredCaches".
// This function should be called from InitClient after InitConfigInternal.
func bindClassAdConfig() {
	// Look for the condor job ad file
	condorJobAd, isPresent := os.LookupEnv("_CONDOR_JOB_AD")
	if !isPresent {
		// No job ad file specified, nothing to do
		return
	}

	// Open the job ad file
	file, err := os.Open(condorJobAd)
	if err != nil {
		log.Debugf("Unable to open job ad file %s: %v", condorJobAd, err)
		return
	}
	defer file.Close()

	// Parse the ClassAd using old-style reader (newline-delimited format)
	reader := classad.NewOldReader(file)
	if !reader.Next() {
		if err := reader.Err(); err != nil {
			log.Debugf("Unable to parse job ad file %s: %v", condorJobAd, err)
		}
		return
	}

	ad := reader.ClassAd()
	if ad == nil {
		log.Debugf("No ClassAd found in job ad file %s", condorJobAd)
		return
	}

	// Iterate through all attributes in the ClassAd looking for PelicanCfg_ prefix
	for _, attrName := range ad.GetAttributes() {
		// Skip attributes that don't have the PelicanCfg_ prefix
		if !strings.HasPrefix(attrName, "PelicanCfg_") {
			continue
		}

		// Convert PelicanCfg_Client_PreferredCaches -> Client.PreferredCaches
		viperKey := strings.Replace(strings.TrimPrefix(attrName, "PelicanCfg_"), "_", ".", -1)

		// Evaluate the attribute to get its value
		attrValue := ad.EvaluateAttr(attrName)
		if attrValue.IsUndefined() {
			log.Debugf("ClassAd attribute %s is undefined, skipping", attrName)
			continue
		}

		// Set the value in viper based on the type
		if attrValue.IsString() {
			if strVal, err := attrValue.StringValue(); err == nil {
				viper.Set(viperKey, strVal)
				log.Debugf("Set %s = %s from job ClassAd attribute %s", viperKey, strVal, attrName)
			} else {
				log.Debugf("Failed to get string value for ClassAd attribute %s: %v", attrName, err)
			}
		} else if attrValue.IsInteger() {
			if intVal, err := attrValue.IntValue(); err == nil {
				viper.Set(viperKey, intVal)
				log.Debugf("Set %s = %d from job ClassAd attribute %s", viperKey, intVal, attrName)
			} else {
				log.Debugf("Failed to get integer value for ClassAd attribute %s: %v", attrName, err)
			}
		} else if attrValue.IsBool() {
			if boolVal, err := attrValue.BoolValue(); err == nil {
				viper.Set(viperKey, boolVal)
				log.Debugf("Set %s = %t from job ClassAd attribute %s", viperKey, boolVal, attrName)
			} else {
				log.Debugf("Failed to get boolean value for ClassAd attribute %s: %v", attrName, err)
			}
		} else if attrValue.IsReal() {
			// For real numbers, get the actual float64 value
			if realVal, err := attrValue.RealValue(); err == nil {
				viper.Set(viperKey, realVal)
				log.Debugf("Set %s = %f from job ClassAd attribute %s", viperKey, realVal, attrName)
			} else {
				log.Debugf("Failed to get real value for ClassAd attribute %s: %v", attrName, err)
			}
		} else if attrValue.IsList() {
			// For lists, use ListValue() to get the list items
			items, err := attrValue.ListValue()
			if err != nil {
				log.Debugf("Failed to get list value for ClassAd attribute %s: %v", attrName, err)
				continue
			}

			// Convert list items to string slice
			out := make([]string, len(items))
			for i, v := range items {
				if !v.IsString() {
					log.Debugf("ClassAd attribute %s list element %d is %v, want string; skipping attribute", attrName, i, v.Type())
					continue
				}
				out[i], _ = v.StringValue()
			}

			viper.Set(viperKey, out)
			log.Debugf("Set %s = %v from job ClassAd attribute %s", viperKey, out, attrName)
		} else if attrValue.IsClassAd() {
			// For nested ClassAds, use the classad Unmarshal helper directly
			nestedAd, err := attrValue.ClassAdValue()
			if err != nil {
				log.Debugf("Failed to get ClassAd value for attribute %s: %v", attrName, err)
				continue
			}

			var result map[string]interface{}
			if err := classad.Unmarshal(nestedAd.String(), &result); err != nil {
				log.Debugf("Failed to unmarshal ClassAd for attribute %s: %v", attrName, err)
				continue
			}

			viper.Set(viperKey, result)
			log.Debugf("Set %s = %v from job ClassAd attribute %s", viperKey, result, attrName)
		} else {
			// For other types, log a warning
			log.Debugf("Unsupported ClassAd type for attribute %s (type %v), skipping", attrName, attrValue.Type())
		}
	}
}

// Bind any legacy/deprecated server environment variables to their new config parameters.
// The function should log any warnings about deprecation; this class of env vars is so old
// these config parameters are not included in the params table, meaning
// `config/config.go::handleDeprecatedConfig` will not catch them/log warnings.
func bindLegacyServerEnv() {
	// MAXMINDKEY
	if val, isSet := os.LookupEnv("PELICAN_MAXMINDKEY"); isSet {
		log.Warningf("You are using a legacy/deprecated parameter 'PELICAN_MAXMINDKEY' to indicate the MaxMind license key. "+
			"Support for this environment variable will be removed in a future release. Please use %s instead",
			param.Director_MaxMindKeyFile.GetName())

		// Use SetDefault so that if both the env var and the config param are set, the config param takes precedence
		viper.SetDefault(param.Director_MaxMindKeyFile.GetName(), val)
	}
}
