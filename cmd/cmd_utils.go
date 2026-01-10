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

package main

import (
	"context"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/param"
)

// Given an input map of flag-->viper config, convert any comma-delineated
// input lists and store them as a string slice with Viper
func commaFlagsListToViperSlice(cmd *cobra.Command, flags map[string]string) {
	for flagName, viperName := range flags {
		if flagValue, _ := cmd.Flags().GetString(flagName); flagValue != "" {
			trimmedValues := []string{}
			for _, value := range strings.Split(flagValue, ",") {
				trimmedValues = append(trimmedValues, strings.TrimSpace(value))
			}
			if err := param.Set(viperName, trimmedValues); err != nil {
				cobra.CheckErr(err)
			}
		}
	}
}

// To be invoked by cmds that need to pass a slice of "preferred" caches
// as an option when invoking a new transfer job/client.
func getPreferredCaches() ([]*url.URL, error) {
	var caches []*url.URL
	for _, cacheStr := range param.Client_PreferredCaches.GetStringSlice() {
		cache, err := url.Parse(cacheStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse cache URL from preferred caches config: %s", cacheStr)
		}

		caches = append(caches, cache)
	}

	return caches, nil
}

// inferDestinationPath checks if the remote destination is a directory and, if so,
// infers the destination filename from the source file. This mimics the behavior of
// common Unix commands like cp, mv, and scp.
//
// Parameters:
//   - ctx: Context for the operation
//   - source: Local source file path
//   - dest: Remote destination URL
//   - options: Transfer options to pass to DoStat
//
// Returns:
//   - string: The potentially modified destination URL
//   - error: An error if URL parsing fails, otherwise nil
func inferDestinationPath(ctx context.Context, source string, dest string, options ...client.TransferOption) (string, error) {
	// Check if destination is a directory by using DoStat
	statInfo, err := client.DoStat(ctx, dest, options...)
	if err != nil {
		// If stat fails, destination may not exist yet - proceed with original destination
		log.Debugln("Failed to stat destination, proceeding with original path:", err)
		return dest, nil
	}

	// If the destination is a collection (directory), append the source filename
	if statInfo.IsCollection {
		sourceFilename := filepath.Base(source)

		// Parse the destination URL to modify the path
		destURL, err := url.Parse(dest)
		if err != nil {
			return dest, errors.Wrap(err, "failed to parse destination URL")
		}

		// Use path.Join for URL paths (not filepath.Join which is OS-specific)
		newPath := path.Join(destURL.Path, sourceFilename)
		destURL.Path = newPath

		newDest := destURL.String()
		log.Debugln("Remote destination is a directory, inferred destination:", newDest)
		return newDest, nil
	}

	return dest, nil
}
