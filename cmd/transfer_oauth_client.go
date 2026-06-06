//go:build client || server

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
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	oauthClientCmd = &cobra.Command{
		Use:   "oauth-client",
		Short: "Manage OAuth2 client registrations",
	}

	oauthClientAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Register a new OAuth2 client on the transfer server",
		RunE:  oauthClientAddMain,
	}

	oauthClientListCmd = &cobra.Command{
		Use:   "list",
		Short: "List OAuth2 clients on the transfer server",
		RunE:  oauthClientListMain,
	}

	oauthClientDeleteCmd = &cobra.Command{
		Use:   "delete {id}",
		Short: "Delete an OAuth2 client from the transfer server",
		Args:  cobra.ExactArgs(1),
		RunE:  oauthClientDeleteMain,
	}

	oauthName         string
	oauthIssuerURL    string
	oauthClientID         string
	oauthClientSecretFile string
)

func init() {
	transferCmd.AddCommand(oauthClientCmd)
	oauthClientCmd.AddCommand(oauthClientAddCmd)
	oauthClientCmd.AddCommand(oauthClientListCmd)
	oauthClientCmd.AddCommand(oauthClientDeleteCmd)

	oauthClientAddCmd.Flags().StringVar(&oauthName, "name", "", "Name for the OAuth2 client (required)")
	oauthClientAddCmd.Flags().StringVar(&oauthIssuerURL, "issuer-url", "", "Issuer URL for the OAuth2 provider (required)")
	oauthClientAddCmd.Flags().StringVar(&oauthClientID, "client-id", "", "OAuth2 client ID (required)")
	oauthClientAddCmd.Flags().StringVar(&oauthClientSecretFile, "client-secret-file", "", "Path to a file containing the OAuth2 client secret (required)")
}

func oauthClientAddMain(cmd *cobra.Command, args []string) error {
	if oauthName == "" {
		return errors.New("--name is required")
	}
	if oauthIssuerURL == "" {
		return errors.New("--issuer-url is required")
	}
	if oauthClientID == "" {
		return errors.New("--client-id is required")
	}
	if oauthClientSecretFile == "" {
		return errors.New("--client-secret-file is required")
	}

	secretBytes, err := os.ReadFile(oauthClientSecretFile)
	if err != nil {
		return errors.Wrap(err, "failed to read client secret file")
	}
	oauthClientSecret := strings.TrimSpace(string(secretBytes))
	if oauthClientSecret == "" {
		return errors.New("client secret file is empty")
	}

	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	reqBody := map[string]string{
		"name":          oauthName,
		"issuer_url":    oauthIssuerURL,
		"client_id":     oauthClientID,
		"client_secret": oauthClientSecret,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to marshal request")
	}

	respBody, _, err := doTransferRequest(cmd.Context(), httpClient, http.MethodPost,
		serverURL+"/api/v1.0/transfer/oauth-clients", tokenValue, bodyBytes)
	if err != nil {
		return err
	}

	if outputJSON {
		fmt.Println(string(respBody))
	} else {
		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err != nil {
			log.Warnln("Failed to parse response:", err)
			fmt.Println(string(respBody))
			return nil
		}
		fmt.Printf("OAuth2 client created: %s (id: %s)\n", result["name"], result["id"])
	}

	return nil
}

func oauthClientListMain(cmd *cobra.Command, args []string) error {
	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	respBody, _, err := doTransferRequest(cmd.Context(), httpClient, http.MethodGet,
		serverURL+"/api/v1.0/transfer/oauth-clients", tokenValue, nil)
	if err != nil {
		return err
	}

	if outputJSON {
		fmt.Println(string(respBody))
		return nil
	}

	var clients []map[string]interface{}
	if err := json.Unmarshal(respBody, &clients); err != nil {
		return errors.Wrap(err, "failed to parse response")
	}

	if len(clients) == 0 {
		fmt.Println("No OAuth2 clients found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tISSUER URL\tCREATED")
	for _, c := range clients {
		id, _ := c["id"].(string)
		name, _ := c["name"].(string)
		issuer, _ := c["issuer_url"].(string)
		created, _ := c["created_at"].(string)
		if len(created) > 19 {
			created = created[:19]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id, name, issuer, created)
	}
	w.Flush()

	return nil
}

func oauthClientDeleteMain(cmd *cobra.Command, args []string) error {
	clientID := args[0]

	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	_, _, err = doTransferRequest(cmd.Context(), httpClient, http.MethodDelete,
		serverURL+"/api/v1.0/transfer/oauth-clients/"+clientID, tokenValue, nil)
	if err != nil {
		return err
	}

	if outputJSON {
		result, _ := json.Marshal(map[string]string{"id": clientID, "status": "deleted"})
		fmt.Println(string(result))
	} else {
		fmt.Printf("OAuth2 client %s deleted.\n", clientID)
	}
	return nil
}
