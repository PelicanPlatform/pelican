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
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
)

var lotUpdateCmd = &cobra.Command{
	Use:   "update <lotName>",
	Short: "Update a lot's management-policy attributes",
	Long: `Update the management-policy attributes of an existing storage lot.

Only the attributes you specify are sent; quota flags are in GB and time flags
are UTC 'YYYY-MM-DD HH:MM:SS'. Requires an administrative token for the cache.`,
	Args: cobra.ExactArgs(1),
	RunE: updateLot,
}

var lotMPAFlagNames = []string{"dedicated-gb", "opportunistic-gb", "max-objects", "creation", "expiration", "deletion"}

func init() {
	flags := lotUpdateCmd.Flags()
	flags.Float64("dedicated-gb", 0, "Dedicated (guaranteed) quota, in GB")
	flags.Float64("opportunistic-gb", 0, "Opportunistic (burst) quota, in GB")
	flags.Int64("max-objects", 0, "Maximum number of objects")
	flags.String("creation", "", "Creation time, UTC 'YYYY-MM-DD HH:MM:SS'")
	flags.String("expiration", "", "Expiration time, UTC 'YYYY-MM-DD HH:MM:SS'")
	flags.String("deletion", "", "Deletion time, UTC 'YYYY-MM-DD HH:MM:SS'")
	lotCmd.AddCommand(lotUpdateCmd)
}

func updateLot(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	changed := false
	for _, f := range lotMPAFlagNames {
		if cmd.Flags().Changed(f) {
			changed = true
			break
		}
	}
	if !changed {
		return errors.Errorf("nothing to update: set at least one of %v", lotMPAFlagNames)
	}

	base, err := constructLotsAPIURL(lotServerURLStr)
	if err != nil {
		return err
	}
	targetURL, err := url.Parse(base.String() + "/" + url.PathEscape(args[0]))
	if err != nil {
		return errors.Wrap(err, "Failed to build lot API URL")
	}

	mpa, err := buildMPAInput(cmd)
	if err != nil {
		return err
	}
	req := lotman.PatchLotRequest{ManagementPolicyAttrs: mpa}
	payload, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal update request")
	}

	body, err := lotAPIDo(ctx, "PATCH", targetURL, payload)
	if err != nil {
		return errors.Wrap(err, "Failed to update lot")
	}

	var resp lotman.Reservation
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(body))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}
	fmt.Println("Lot updated successfully:")
	return printLotResult(cmd, resp)
}
