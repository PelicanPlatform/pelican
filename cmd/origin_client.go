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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

var (
	originIssuerCmd = &cobra.Command{
		Use:   "issuer",
		Short: "Manage the origin's embedded OIDC token issuer",
	}

	originIssuerClientCmd = &cobra.Command{
		Use:   "client",
		Short: "Manage OIDC clients for the origin's embedded issuer",
		Long:  `Provides commands to create, list, update, and delete OIDC clients configured on the origin's embedded token issuer.`,
	}

	issuerClientServerURL  string
	issuerClientTokenPath  string
	issuerClientNamespace  string
	issuerClientGrantTypes string
	issuerClientScopes     string

	originIssuerClientCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new OIDC client",
		Long: `Create a new OIDC client on the origin's embedded issuer.

The --grant-types flag controls which OAuth2 flows the client can use.
Accepted values (comma-separated):
  authorization_code
  refresh_token
  urn:ietf:params:oauth:grant-type:device_code
  urn:ietf:params:oauth:grant-type:token-exchange

Example — create a token-exchange client:
  pelican origin issuer client create --server https://my-origin:8447 \
    --grant-types "urn:ietf:params:oauth:grant-type:token-exchange,refresh_token"`,
		RunE: issuerClientCreateRun,
	}

	originIssuerClientListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all OIDC clients",
		RunE:  issuerClientListRun,
	}

	originIssuerClientUpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update an existing OIDC client",
		Long: `Update the configuration of an existing OIDC client.

Only the flags you provide are changed; omitted fields are left unchanged.

Example — add token-exchange grant and narrow scopes:
  pelican origin issuer client update --server https://my-origin:8447 \
    --id <client-id> \
    --grant-types "urn:ietf:params:oauth:grant-type:token-exchange,refresh_token" \
    --scopes "openid,storage.read:/"`,
		RunE: issuerClientUpdateRun,
	}

	originIssuerClientDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete an OIDC client",
		RunE:  issuerClientDeleteRun,
	}

	issuerClientDeleteID string
	issuerClientUpdateID string
)

func init() {
	originCmd.AddCommand(originIssuerCmd)
	originIssuerCmd.AddCommand(originIssuerClientCmd)

	originIssuerClientCmd.PersistentFlags().StringVar(&issuerClientServerURL, "server", "", "Web URL of the Pelican origin server (e.g. https://my-origin:8447)")
	originIssuerClientCmd.PersistentFlags().StringVar(&issuerClientTokenPath, "token", "", "Path to a file containing an admin token (optional; generated automatically if omitted)")
	originIssuerClientCmd.PersistentFlags().StringVar(&issuerClientNamespace, "namespace", "", "Federation namespace prefix for the issuer (e.g. /data/analysis) (required)")
	if err := originIssuerClientCmd.MarkPersistentFlagRequired("namespace"); err != nil {
		log.Errorln("Failed to mark namespace flag as required:", err)
	}

	// Create sub-command
	originIssuerClientCmd.AddCommand(originIssuerClientCreateCmd)
	originIssuerClientCreateCmd.Flags().StringVar(&issuerClientGrantTypes, "grant-types", "", "Comma-separated list of grant types (required)")
	originIssuerClientCreateCmd.Flags().StringVar(&issuerClientScopes, "scopes", "", "Comma-separated list of scopes (optional; defaults to common WLCG scopes)")
	if err := originIssuerClientCreateCmd.MarkFlagRequired("grant-types"); err != nil {
		log.Errorln("Failed to mark grant-types flag as required:", err)
	}

	// List sub-command
	originIssuerClientCmd.AddCommand(originIssuerClientListCmd)

	// Update sub-command
	originIssuerClientCmd.AddCommand(originIssuerClientUpdateCmd)
	originIssuerClientUpdateCmd.Flags().StringVar(&issuerClientUpdateID, "id", "", "Client ID to update (required)")
	originIssuerClientUpdateCmd.Flags().StringVar(&issuerClientGrantTypes, "grant-types", "", "Comma-separated list of grant types")
	originIssuerClientUpdateCmd.Flags().StringVar(&issuerClientScopes, "scopes", "", "Comma-separated list of scopes")
	if err := originIssuerClientUpdateCmd.MarkFlagRequired("id"); err != nil {
		log.Errorln("Failed to mark id flag as required:", err)
	}

	// Delete sub-command
	originIssuerClientCmd.AddCommand(originIssuerClientDeleteCmd)
	originIssuerClientDeleteCmd.Flags().StringVar(&issuerClientDeleteID, "id", "", "Client ID to delete (required)")
	if err := originIssuerClientDeleteCmd.MarkFlagRequired("id"); err != nil {
		log.Errorln("Failed to mark id flag as required:", err)
	}
}

// issuerAdminClientsAPIPath returns the full admin clients API path
// for the configured namespace.
func issuerAdminClientsAPIPath() string {
	return "/api/v1.0/issuer/admin/ns" + issuerClientNamespace + "/clients"
}

// constructIssuerAdminURL validates the server URL and returns the full admin API endpoint.
func constructIssuerAdminURL(serverURLStr, apiPath string) (*url.URL, error) {
	if serverURLStr == "" {
		return nil, errors.New("The --server flag providing the origin's web URL is required")
	}
	serverURLStr = strings.TrimSuffix(serverURLStr, "/")
	baseURL, err := url.Parse(serverURLStr)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid server URL format: %s", serverURLStr)
	}
	if baseURL.Scheme != "https" {
		return nil, errors.Errorf("Server URL must have an https scheme: %s", serverURLStr)
	}
	if baseURL.Host == "" {
		return nil, errors.Errorf("Server URL must include a hostname: %s", serverURLStr)
	}
	targetURL, err := baseURL.Parse(apiPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct issuer admin API URL")
	}
	return targetURL, nil
}

// issuerClientCreateRun creates a new OIDC client on the origin.
func issuerClientCreateRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	grantTypes := splitAndTrim(issuerClientGrantTypes)
	if len(grantTypes) == 0 {
		return errors.New("--grant-types flag is required and must not be empty")
	}

	var scopes []string
	if issuerClientScopes != "" {
		scopes = splitAndTrim(issuerClientScopes)
	}

	targetURL, err := constructIssuerAdminURL(issuerClientServerURL, issuerAdminClientsAPIPath())
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"grant_types": grantTypes,
	}
	if len(scopes) > 0 {
		payload["scopes"] = scopes
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal request payload")
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(issuerClientServerURL, issuerClientTokenPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server request failed")
	}

	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, bodyBytes, "", "  "); err == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(bodyBytes))
		}
	} else {
		var result map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			fmt.Println(string(bodyBytes))
			return nil
		}
		fmt.Printf("Client ID:     %s\n", result["client_id"])
		fmt.Printf("Client Secret: %s\n", result["client_secret"])
		if gt, ok := result["grant_types"]; ok {
			fmt.Printf("Grant Types:   %v\n", gt)
		}
		if sc, ok := result["scopes"]; ok {
			fmt.Printf("Scopes:        %v\n", sc)
		}
	}
	return nil
}

// issuerClientListRun lists all OIDC clients on the origin.
func issuerClientListRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	targetURL, err := constructIssuerAdminURL(issuerClientServerURL, issuerAdminClientsAPIPath())
	if err != nil {
		return err
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(issuerClientServerURL, issuerClientTokenPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server request failed")
	}

	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, bodyBytes, "", "  "); err == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(bodyBytes))
		}
	} else {
		var clients []map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &clients); err != nil {
			fmt.Println(string(bodyBytes))
			return nil
		}
		if len(clients) == 0 {
			fmt.Println("No clients registered.")
			return nil
		}
		for _, c := range clients {
			fmt.Printf("%-36s  grant_types=%v  scopes=%v\n",
				c["client_id"], c["grant_types"], c["scopes"])
		}
	}
	return nil
}

// issuerClientUpdateRun updates an existing OIDC client on the origin.
func issuerClientUpdateRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	if issuerClientUpdateID == "" {
		return errors.New("--id flag is required")
	}

	// Build a partial-update payload from whichever flags were explicitly set.
	payload := make(map[string]interface{})
	if cmd.Flags().Changed("grant-types") {
		grantTypes := splitAndTrim(issuerClientGrantTypes)
		if len(grantTypes) == 0 {
			return errors.New("--grant-types must not be empty when provided")
		}
		payload["grant_types"] = grantTypes
	}
	if cmd.Flags().Changed("scopes") {
		payload["scopes"] = splitAndTrim(issuerClientScopes)
	}

	if len(payload) == 0 {
		return errors.New("At least one of --grant-types or --scopes must be provided")
	}

	targetURL, err := constructIssuerAdminURL(issuerClientServerURL, issuerAdminClientsAPIPath()+"/"+url.PathEscape(issuerClientUpdateID))
	if err != nil {
		return err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal request payload")
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(issuerClientServerURL, issuerClientTokenPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", targetURL.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server request failed")
	}

	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, bodyBytes, "", "  "); err == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(bodyBytes))
		}
	} else {
		var result map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			fmt.Println(string(bodyBytes))
			return nil
		}
		fmt.Printf("Client %s updated successfully.\n", issuerClientUpdateID)
		if gt, ok := result["grant_types"]; ok {
			fmt.Printf("Grant Types:   %v\n", gt)
		}
		if sc, ok := result["scopes"]; ok {
			fmt.Printf("Scopes:        %v\n", sc)
		}
	}
	return nil
}

// issuerClientDeleteRun deletes an OIDC client from the origin.
func issuerClientDeleteRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	if issuerClientDeleteID == "" {
		return errors.New("--id flag is required")
	}

	targetURL, err := constructIssuerAdminURL(issuerClientServerURL, issuerAdminClientsAPIPath()+"/"+url.PathEscape(issuerClientDeleteID))
	if err != nil {
		return err
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(issuerClientServerURL, issuerClientTokenPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		fmt.Printf("Client %s deleted successfully.\n", issuerClientDeleteID)
		return nil
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return errors.Wrapf(readErr, "Server responded with %s and body could not be read", resp.Status)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errors.Errorf("Client %s not found", issuerClientDeleteID)
	}
	return errors.Errorf("Server responded with %s: %s", resp.Status, string(bodyBytes))
}

// splitAndTrim splits a comma-separated string and trims whitespace.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
