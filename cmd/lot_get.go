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
	"net/url"
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
)

var lotGetCmd = &cobra.Command{
	Use:   "get <lotName>",
	Short: "Show a single lot",
	Long:  "Fetch and display the details of a single storage lot by name. Requires an administrative token for the cache.",
	Args:  cobra.ExactArgs(1),
	RunE:  getLot,
}

func init() {
	lotGetCmd.Flags().Bool("recursive", false, "Include ancestral policy restrictions in the result")
	lotCmd.AddCommand(lotGetCmd)
}

func getLot(cmd *cobra.Command, args []string) error {
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

	recursive, _ := cmd.Flags().GetBool("recursive")
	query := targetURL.Query()
	query.Set("recursive", strconv.FormatBool(recursive))
	targetURL.RawQuery = query.Encode()

	body, err := lotAPIDo(ctx, "GET", targetURL, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to get lot")
	}

	var resp lotman.Reservation
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(body))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}
	return printLotResult(cmd, resp)
}
