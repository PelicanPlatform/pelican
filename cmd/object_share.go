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

package main

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	shareCmd = &cobra.Command{
		Use: "share {URL}",
		Short: `Generate a string for sharing access to a namespace.
Note the sharing is based on prefixes; all object names matching the prefix will be accessible`,
		RunE: shareMain,
	}
)

func init() {
	flagSet := shareCmd.Flags()
	flagSet.Bool("write", false, "Allow writes to the target prefix")
	objectCmd.AddCommand(shareCmd)
}

func shareMain(cmd *cobra.Command, args []string) error {

	err := config.InitClient()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize the client")
	}

	isWrite, err := cmd.Flags().GetBool("write")
	if err != nil {
		return errors.Wrap(err, "Unable to get the value of the --write flag")
	}

	if len(args) == 0 {
		return errors.New("A URL must be specified to share")
	}

	objectUrl, err := url.Parse(args[0])
	if err != nil {
		return errors.Wrapf(err, "Failed to parse '%v' as a URL", args[0])
	}

	token, err := client.CreateSharingUrl(cmd.Context(), objectUrl, isWrite)
	if err != nil {
		return errors.Wrapf(err, "Failed to create a sharing URL for %v", objectUrl.String())
	}

	objectUrl.RawQuery = "authz=" + token
	fmt.Println(objectUrl.String())
	return nil
}
