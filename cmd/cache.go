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
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/spf13/cobra"
)

var (
	cacheCmd = &cobra.Command{
		Use:   "cache",
		Short: "Operate a Pelican cache service",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := initCache()
			return err
		},
	}

	cacheServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "Start the cache service",
		RunE:         serveCache,
		SilenceUsage: true,
	}
)

func initCache() error {
	err := config.InitServer()
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("xrootd", "critical", "xrootd has not been started")
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("cmsd", "critical", "cmsd has not been started")
	cobra.CheckErr(err)

	return err
}

func init() {
	cacheCmd.AddCommand(cacheServeCmd)
	cacheServeCmd.Flags().AddFlag(portFlag)
}
