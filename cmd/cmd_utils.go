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
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
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

const (
	incorrectPasswordAccessMessage = "Failed to access local credential file - entered incorrect local decryption password"
	incorrectPasswordResetMessage  = "Failed to reset password - entered incorrect local decryption password"
)

func handleIncorrectPassword(err error, actionMessage string) bool {
	if err == nil || !errors.Is(err, config.ErrIncorrectPassword) {
		return false
	}
	fmt.Fprintln(os.Stderr, actionMessage)
	fmt.Fprintln(os.Stderr, "If you have forgotten your password, you can reset the local state (deleting all on-disk credentials)")
	fmt.Fprintf(os.Stderr, "by running '%s credentials reset-local'\n", os.Args[0])
	return true
}

func handleCredentialPasswordError(err error) bool {
	return handleIncorrectPassword(err, incorrectPasswordAccessMessage)
}
