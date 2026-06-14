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

var lotReclaimCmd = &cobra.Command{
	Use:   "reclaim <lotName>",
	Short: "Reclaim a lot and its descendants",
	Long: `Mark a storage lot (and its descendants) as reclaimed. Reclamation severs the
lot's accounting tie to its paths so its usage no longer counts toward quotas;
it is recorded in an append-only ledger. Requires an administrative token for
the cache.`,
	Args: cobra.ExactArgs(1),
	RunE: reclaimLot,
}

func init() {
	lotReclaimCmd.Flags().String("reason", "", "Free-form audit note recorded with the reclamation")
	lotCmd.AddCommand(lotReclaimCmd)
}

func reclaimLot(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	base, err := constructLotsAPIURL(lotServerURLStr)
	if err != nil {
		return err
	}
	targetURL, err := url.Parse(base.String() + "/" + url.PathEscape(args[0]) + "/reclaim")
	if err != nil {
		return errors.Wrap(err, "Failed to build lot API URL")
	}

	reason, _ := cmd.Flags().GetString("reason")
	payload, err := json.Marshal(lotman.ReclaimLotRequest{Reason: reason})
	if err != nil {
		return errors.Wrap(err, "Failed to marshal reclaim request")
	}

	body, err := lotAPIDo(ctx, "POST", targetURL, payload)
	if err != nil {
		return errors.Wrap(err, "Failed to reclaim lot")
	}

	var resp lotman.ReclaimLotResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(body))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}
	fmt.Println("Lot reclaim recorded:")
	return printLotResult(cmd, resp)
}
