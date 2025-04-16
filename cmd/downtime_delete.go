/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

var downtimeDeleteCmd = &cobra.Command{
	Use:   "delete [uuid]",
	Short: "Delete a downtime period",
	Long:  "Delete the specified downtime period by UUID. Sends a DELETE request to the downtime API.",
	Args:  cobra.ExactArgs(1),
	RunE:  deleteDowntime,
}

func init() {
	downtimeCmd.AddCommand(downtimeDeleteCmd)
}

func deleteDowntime(cmd *cobra.Command, args []string) error {
	downtimeUUID := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	// Basic validation of the input
	apiURL, err := constructDowntimeApiURL(serverURLStr)
	if err != nil {
		return err
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(serverURLStr, tokenLocation)
	if err != nil {
		return err
	}

	// Build the API URL for deletion
	targetURL, err := url.Parse(apiURL.String() + "/" + downtimeUUID)
	if err != nil {
		return errors.Wrap(err, "Failed to build delete API URL")
	}

	log.Debugln("Deleting downtime from:", targetURL.String())

	req, err := http.NewRequestWithContext(ctx, "DELETE", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server delete request failed")
	}

	fmt.Println("Downtime deleted successfully:")
	fmt.Println(string(bodyBytes))
	return nil
}
