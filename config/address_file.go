/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// getServerRuntimeDir returns the runtime directory for server-wide runtime files using
// the configuration populated during server initialization.
func getServerRuntimeDir() (string, error) {
	runtimeDir := viper.GetString(param.RuntimeDir.GetName())
	if runtimeDir == "" {
		return "", errors.New("runtime directory is not configured")
	}
	return runtimeDir, nil
}

// WriteAddressFile writes a file containing the actual addresses selected by Pelican
// after startup. This allows scripts to source the file to get the server's addresses
// instead of probing for ports (which can lead to race conditions).
//
// The file is written to the runtime directory and contains KEY=VALUE pairs,
// one per line, with the following keys:
//   - SERVER_EXTERNAL_WEB_URL: The main web UI/API endpoint
//   - ORIGIN_URL: The origin's XRootD endpoint (if origin is enabled)
//   - CACHE_URL: The cache's XRootD endpoint (if cache is enabled)
//
// The file is written atomically using a temporary file and rename.
func WriteAddressFile(modules server_structs.ServerType) error {
	runtimeDir, err := getServerRuntimeDir()
	if err != nil {
		return errors.Wrap(err, "failed to determine runtime directory")
	}

	// Ensure the runtime directory exists
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return errors.Wrap(err, "failed to create runtime directory")
	}

	addressFilePath := filepath.Join(runtimeDir, "pelican.addresses")
	tempFilePath := addressFilePath + ".tmp"

	// Build the content
	var content string

	// Always include the server external web URL
	serverWebUrl := param.Server_ExternalWebUrl.GetString()
	if serverWebUrl != "" {
		content += fmt.Sprintf("SERVER_EXTERNAL_WEB_URL=%s\n", serverWebUrl)
	}

	// Include origin URL if origin is enabled
	if modules.IsEnabled(server_structs.OriginType) {
		originUrl := param.Origin_Url.GetString()
		if originUrl != "" {
			content += fmt.Sprintf("ORIGIN_URL=%s\n", originUrl)
		}
	}

	// Include cache URL if cache is enabled
	if modules.IsEnabled(server_structs.CacheType) {
		cacheUrl := param.Cache_Url.GetString()
		if cacheUrl != "" {
			content += fmt.Sprintf("CACHE_URL=%s\n", cacheUrl)
		}
	}

	// Write to temporary file first
	if err := os.WriteFile(tempFilePath, []byte(content), 0600); err != nil {
		return errors.Wrap(err, "failed to write temporary address file")
	}

	// Atomically rename the temporary file to the final location
	if err := os.Rename(tempFilePath, addressFilePath); err != nil {
		// Clean up the temp file if rename fails
		os.Remove(tempFilePath)
		return errors.Wrap(err, "failed to rename address file")
	}

	log.Infof("Address file written to %s", addressFilePath)
	return nil
}
