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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	originCmd = &cobra.Command{
		Use:   "origin",
		Short: "Operate a Pelican origin service",
	}

	originConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "Launch the Pelican web service in configuration mode",
		Run:   configOrigin,
	}

	originServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "Start the origin service",
		RunE:         serveOrigin,
		SilenceUsage: true,
	}
)

func configOrigin( /*cmd*/ *cobra.Command /*args*/, []string) {
	fmt.Println("'origin config' command is not yet implemented")
	os.Exit(1)
}

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)
	originServeCmd.Flags().StringP("volume", "v", "", "Setting the volue to /SRC:/DEST will export the contents of /SRC as /DEST in the Pelican federation")
	if err := viper.BindPFlag("ExportVolume", originServeCmd.Flags().Lookup("volume")); err != nil {
		panic(err)
	}
	originServeCmd.Flags().AddFlag(portFlag)
}
