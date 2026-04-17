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

package config_printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// ConfigLoadOptions controls what config loading stages are included.
type ConfigLoadOptions struct {
	// Service selects which server context to simulate (e.g. "cache", "origin",
	// "director", "registry"). When set, the config entrypoint is switched to
	// /etc/pelican/pelican-{service}.yaml, falling back to /etc/pelican/pelican.yaml
	// if the service-specific file does not exist.
	//
	// NOTE: If the service config file names in systemd/ are changed, this
	// code must be updated to match.
	Service string
	// WithDiscovery triggers federation discovery to resolve Federation.DirectorUrl etc.
	// Default false — no network calls.
	WithDiscovery bool
}

// initClientAndServerConfig initializes configuration on the given viper instance and
// returns the fully-resolved config struct, with explicit control over which loading
// stages are performed.
func initClientAndServerConfig(v *viper.Viper, opts ConfigLoadOptions) *param.Config {
	// When a service is specified, point at /etc/pelican/pelican-{service}.yaml.
	// If that file doesn't exist, fall back to /etc/pelican/pelican.yaml.
	//
	// Note that here we explicitly avoid using ${ConfigBase} because service config file installation
	// should be independent of the user running the command.
	if opts.Service != "" {
		servicePath := filepath.Join("/etc", "pelican", fmt.Sprintf("pelican-%s.yaml", opts.Service))
		if _, err := os.Stat(servicePath); err == nil {
			viper.Set("config", servicePath)
		} else {
			fallback := filepath.Join("/etc", "pelican", "pelican.yaml")
			log.Debugf("Service config %s not found, falling back to %s", servicePath, fallback)
			viper.Set("config", fallback)
		}
	}

	// Initialize base config (defaults + config files + env) on the global viper instance.
	// Only invoke InitConfigInternal when operating on the global viper to avoid double-init.
	if v == viper.GetViper() {
		currentLevel := config.GetEffectiveLogLevel()
		config.SetLogging(log.ErrorLevel)
		config.InitConfigInternal(log.InfoLevel)
		config.SetLogging(currentLevel)
	}

	if err := config.SetClientDefaults(v); err != nil {
		log.Errorf("Error setting client defaults: %v", err)
	}
	if err := config.SetServerDefaults(v); err != nil {
		log.Errorf("Error setting server defaults: %v", err)
	}

	// Load web-config.yaml overrides when operating on the global viper.
	// The fresh defaultConfig viper (used by summary for the baseline) skips
	// this since it should reflect pure defaults without runtime overrides.
	// This must happen BEFORE ApplyLogLevelInheritance so that a web-config
	// change to Logging.Level is visible to the inheritance logic.
	if v == viper.GetViper() {
		webConfigPath := param.Server_WebConfigFile.GetString()
		if webConfigPath != "" {
			if err := config.SetWebConfigOverride(v, webConfigPath); err != nil {
				log.Debugf("Could not load web config overrides from %s: %v", webConfigPath, err)
			}
		}
	}

	// Apply log level inheritance: if the user explicitly set Logging.Level
	// (via config file, env var, OR web-config), propagate it to sub-loggers
	// not individually pinned. Only applies to the global viper since the
	// source tracker is a global singleton tied to the global config loading.
	if v == viper.GetViper() {
		config.ApplyLogLevelInheritance(v)
	}

	// Optionally resolve federation metadata via discovery.
	if opts.WithDiscovery && v == viper.GetViper() {
		globalFedInfo, globalFedErr := config.GetFederation(context.Background())
		if globalFedErr != nil {
			log.Errorf("Error getting federation info: %v", globalFedErr)
		}
		config.SetFederation(globalFedInfo)
	}

	expandedConfig, err := param.DecodeConfig(v)
	if err != nil {
		log.Errorf("Error unmarshalling config: %v", err)
	}
	return expandedConfig
}

// printConfig is used to print a config.
//
// It takes as input a config instance of type interface{} (not necessarily a full Config struct)
// and another parameter, format, which can be "yaml" or "json". It then prints the config in the
// corresponding format.
func printConfig(configData interface{}, format string) {
	switch format {
	case "yaml":
		if yamlData, err := yaml.Marshal(configData); err != nil {
			log.Errorf("Error marshaling config to YAML: %v", err)
		} else {
			fmt.Println(string(yamlData))
		}
	case "json":
		if jsonData, err := json.MarshalIndent(configData, "", "  "); err != nil {
			log.Errorf("Error marshaling config to JSON: %v", err)
		} else {
			fmt.Println(string(jsonData))
		}
	default:
		log.Errorf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}

	// Add an eye break before any other logs are printed.
	fmt.Println()
}

// formatValue formats values appropriately for printing.
//
// It renders values of different kinds for printing. For example, a slice `[]int{1, 2, 3, 4}`
// would be formatted as "[1,2,3,4]".
func formatValue(value interface{}) string {
	if value == nil || value == "none" {
		return "none"
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		// Handle map[string]struct{} as a set
		if rv.Type().Key().Kind() == reflect.String && rv.Type().Elem().Kind() == reflect.Struct {
			var quotedKeys []string
			for _, key := range rv.MapKeys() {
				quotedKeys = append(quotedKeys, fmt.Sprintf("\"%s\"", key.String()))
			}
			return "[" + strings.Join(quotedKeys, ", ") + "]"
		}
		// Generic map handling (if needed)
		var elements []string
		for _, key := range rv.MapKeys() {
			formattedValue := formatValue(rv.MapIndex(key).Interface())
			elements = append(elements, fmt.Sprintf("%s: %s", key, formattedValue))
		}
		return "{" + strings.Join(elements, ", ") + "}"
	case reflect.Slice, reflect.Array:
		var elements []string
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i).Interface()
			elements = append(elements, formatValue(elem))
		}
		return "[" + strings.Join(elements, ", ") + "]"
	case reflect.String:
		// Surround string with double quotes
		return fmt.Sprintf("\"%s\"", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}
