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
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// Given an input map of flag-->viper config, convert any comma-delineated
// input lists and store them as a string slice with Viper
func commaFlagsListToViperSlice(cmd *cobra.Command, flags map[string]string) {
	for flagName, viperName := range flags {
		if flagValue, _ := cmd.Flags().GetString(flagName); flagValue != "" {
			viper.Set(viperName, strings.Split(flagValue, ","))
		}
	}
}

// To be invoked by cmds that need to pass a slice of "preferred" caches
// as an option when invoking a new transfer job/client.
func getPreferredCaches() ([]*url.URL, error) {
	var caches []*url.URL
	for _, cacheStr := range param.Client_PreferredCaches.GetStringSlice() {
		// If the current entry contains a comma because it comes directly from an env var
		// and hasn't yet been converted to a string slice, split it into multiple entries
		if strings.Contains(cacheStr, ",") {
			for _, cache := range strings.Split(cacheStr, ",") {
				cache, err := url.Parse(strings.TrimSpace(cache))
				if err != nil {
					return nil, errors.Wrapf(err, "failed to parse cache URL from preferred caches config: %s", cacheStr)
				}
				caches = append(caches, cache)
			}
		} else {
			cache, err := url.Parse(cacheStr)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse cache URL from preferred caches config: %s", cacheStr)
			}
			caches = append(caches, cache)
		}
	}

	return caches, nil
}
