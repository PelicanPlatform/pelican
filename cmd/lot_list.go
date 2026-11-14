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
	"sort"
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
)

var lotListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List the lots known to a cache",
	Long:    "List the names of the storage lots configured on a Pelican cache. Requires an administrative token for the cache.",
	Args:    cobra.NoArgs,
	RunE:    listLots,
	Aliases: []string{"ls"},
}

func init() {
	flags := lotListCmd.Flags()
	flags.String("owner", "", "Only list lots owned by this issuer URL")
	flags.Bool("recursive", true, "Include child lots")
	lotCmd.AddCommand(lotListCmd)
}

func listLots(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	targetURL, err := constructLotsAPIURL(lotServerURLStr)
	if err != nil {
		return err
	}

	owner, _ := cmd.Flags().GetString("owner")
	recursive, _ := cmd.Flags().GetBool("recursive")
	query := targetURL.Query()
	query.Set("recursive", strconv.FormatBool(recursive))
	if owner != "" {
		query.Set("owner", owner)
	}
	targetURL.RawQuery = query.Encode()

	body, err := lotAPIDo(ctx, "GET", targetURL, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to list lots")
	}

	var resp lotman.LotListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(body))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}

	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		return printLotResult(cmd, resp)
	}
	if len(resp.Lots) == 0 {
		fmt.Println("No lots found.")
		return nil
	}
	sort.Strings(resp.Lots)
	for _, name := range resp.Lots {
		fmt.Println(name)
	}
	return nil
}
