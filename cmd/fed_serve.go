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
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func fedServeStart(cmd *cobra.Command, args []string) error {
	moduleSlice := param.Server_Modules.GetStringSlice()
	if len(moduleSlice) == 0 {
		return errors.New("No modules are enabled; pass the --module flag or set the Server.Modules parameter")
	}
	modules := config.NewServerType()
	for _, module := range moduleSlice {
		if !modules.SetString(module) {
			return errors.Errorf("Unknown module name: %s", module)
		}
	}
	if modules.IsEnabled(config.CacheType) {
		return errors.New("`pelican serve` does not support the cache module")
	}

	_, err := launchers.LaunchModules(cmd.Context(), modules)
	return err
}
