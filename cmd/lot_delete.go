//go:build server

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

package main

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

var lotDeleteCmd = &cobra.Command{
	Use:   "delete <lotName>",
	Short: "Delete a lot and its descendants",
	Long: `Delete a storage lot from a Pelican cache. Deletion is recursive: the named
lot and all of its descendant lots are removed. Requires an administrative
token for the cache.`,
	Args:    cobra.ExactArgs(1),
	RunE:    deleteLot,
	Aliases: []string{"rm"},
}

func init() {
	lotCmd.AddCommand(lotDeleteCmd)
}

func deleteLot(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	base, err := constructLotsAPIURL(lotServerURLStr)
	if err != nil {
		return err
	}
	targetURL, err := url.Parse(base.String() + "/" + url.PathEscape(args[0]))
	if err != nil {
		return errors.Wrap(err, "Failed to build lot API URL")
	}

	body, err := lotAPIDo(ctx, "DELETE", targetURL, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to delete lot")
	}

	fmt.Printf("Lot %q deleted successfully.\n", args[0])
	if len(body) > 0 {
		log.Debugf("Delete response body: %s", string(body))
	}
	return nil
}
