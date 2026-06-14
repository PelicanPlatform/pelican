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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
)

var lotCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new lot",
	Long: `Create a new storage lot (reservation) on a Pelican cache.

At least one --path is required. Quota flags are in GB; time flags are UTC
'YYYY-MM-DD HH:MM:SS'. Unspecified attributes are filled in by the server's
policy defaults. Requires an administrative token for the cache.`,
	Args: cobra.NoArgs,
	RunE: createLot,
}

func init() {
	flags := lotCreateCmd.Flags()
	flags.String("name", "", "Optional lot name; the server generates a UUID if omitted")
	flags.StringArray("path", nil, "Path prefix owned by the lot (repeatable); at least one is required")
	flags.Bool("recursive", false, "Treat the given --path values as recursive")
	flags.Float64("dedicated-gb", 0, "Dedicated (guaranteed) quota, in GB")
	flags.Float64("opportunistic-gb", 0, "Opportunistic (burst) quota, in GB")
	flags.Int64("max-objects", 0, "Maximum number of objects")
	flags.String("creation", "", "Creation time, UTC 'YYYY-MM-DD HH:MM:SS' (optional)")
	flags.String("expiration", "", "Expiration time, UTC 'YYYY-MM-DD HH:MM:SS' (optional)")
	flags.String("deletion", "", "Deletion time, UTC 'YYYY-MM-DD HH:MM:SS' (optional)")
	if err := lotCreateCmd.MarkFlagRequired("path"); err != nil {
		log.Errorln("Failed to mark --path required:", err)
	}
	lotCmd.AddCommand(lotCreateCmd)
}

func createLot(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	targetURL, err := constructLotsAPIURL(lotServerURLStr)
	if err != nil {
		return err
	}

	name, _ := cmd.Flags().GetString("name")
	pathVals, _ := cmd.Flags().GetStringArray("path")
	recursive, _ := cmd.Flags().GetBool("recursive")
	if len(pathVals) == 0 {
		return errors.New("at least one --path is required")
	}

	paths := make([]lotman.LotPathInput, 0, len(pathVals))
	for _, p := range pathVals {
		paths = append(paths, lotman.LotPathInput{Path: p, Recursive: recursive})
	}

	mpa, err := buildMPAInput(cmd)
	if err != nil {
		return err
	}

	req := lotman.CreateLotRequest{
		LotName:               name,
		Paths:                 paths,
		ManagementPolicyAttrs: mpa,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal create request")
	}

	body, err := lotAPIDo(ctx, "POST", targetURL, payload)
	if err != nil {
		return errors.Wrap(err, "Failed to create lot")
	}

	var resp lotman.Reservation
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(body))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}
	fmt.Println("Lot created successfully:")
	return printLotResult(cmd, resp)
}

// buildMPAInput assembles an MPAInput from the quota/time flags shared by the
// create and update commands. Only flags the user set are populated, so unset
// attributes fall through to the server's defaults (create) or are left
// unchanged (update).
func buildMPAInput(cmd *cobra.Command) (*lotman.MPAInput, error) {
	mpa := &lotman.MPAInput{}
	if cmd.Flags().Changed("dedicated-gb") {
		v, _ := cmd.Flags().GetFloat64("dedicated-gb")
		mpa.DedicatedGB = &v
	}
	if cmd.Flags().Changed("opportunistic-gb") {
		v, _ := cmd.Flags().GetFloat64("opportunistic-gb")
		mpa.OpportunisticGB = &v
	}
	if cmd.Flags().Changed("max-objects") {
		v, _ := cmd.Flags().GetInt64("max-objects")
		mpa.MaxNumObjects = &v
	}
	creation, err := parseLotTimeFlag(cmd, "creation")
	if err != nil {
		return nil, err
	}
	mpa.CreationTimeMs = creation
	expiration, err := parseLotTimeFlag(cmd, "expiration")
	if err != nil {
		return nil, err
	}
	mpa.ExpirationTimeMs = expiration
	deletion, err := parseLotTimeFlag(cmd, "deletion")
	if err != nil {
		return nil, err
	}
	mpa.DeletionTimeMs = deletion
	return mpa, nil
}
