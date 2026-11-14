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
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/transfer"
)

var (
	oauthClientCmd = &cobra.Command{
		Use:   "oauth-client",
		Short: "Manage OAuth2 client registrations",
	}

	oauthClientAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Register a new OAuth2 client on the transfer server",
		Long: `Register an external issuer's confidential OAuth2 client with the transfer server.

The server selects a registered client by the grant it needs, so --grant-types
decides which credential bootstrap flows this client can serve.  Accepted
values (comma-separated):
  authorization_code                                  (browser flow)
  urn:ietf:params:oauth:grant-type:token-exchange     (RFC 8693 exchange)

Example -- register a client usable for both flows:
  pelican-server transfer oauth-client add --server https://transfer.example.com:8447 \
    --name example-issuer --issuer-url https://issuer.example.com \
    --client-id <id> --client-secret-file /path/to/secret \
    --grant-types "authorization_code,urn:ietf:params:oauth:grant-type:token-exchange"`,
		RunE: oauthClientAddMain,
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

	oauthName             string
	oauthIssuerURL        string
	oauthClientID         string
	oauthClientSecretFile string
	oauthGrantTypes       string
	oauthScopes           string
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
	oauthClientAddCmd.Flags().StringVar(&oauthGrantTypes, "grant-types", "",
		"Comma-separated list of grant types the client may be used for (required)")
	oauthClientAddCmd.Flags().StringVar(&oauthScopes, "scopes", "",
		"Comma-separated list of scopes the client can obtain; narrows which requests it is chosen for")
}

// buildOAuthClientCreateRequest validates the add command's inputs and renders
// them as the request body the transfer server expects.
//
// It exists as its own function for two reasons.  The body is built from
// transfer.OAuthClientCreateRequest rather than an ad-hoc map, so a field the
// API understands cannot be dropped by forgetting to name it here -- which is
// how grant_types came to be omitted, leaving every client registered by this
// command unusable.  And the grant types are checked against the set the
// server actually looks up: an unrecognized grant is never rejected by the
// server, it just means the client is silently never selected, with the
// failure surfacing much later as "no OAuth client configured for this
// issuer".
//
// The server stores and matches grant types and scopes whitespace-separated,
// while the CLI takes them comma-separated for consistency with
// `origin issuer client create`; the join happens here.
func buildOAuthClientCreateRequest(name, issuerURL, clientID, clientSecret, grantTypes, scopes string) (transfer.OAuthClientCreateRequest, error) {
	grants := splitAndTrim(grantTypes)
	if len(grants) == 0 {
		return transfer.OAuthClientCreateRequest{}, errors.Errorf(
			"--grant-types is required and must not be empty; accepted values are %s",
			strings.Join(transfer.SupportedGrantTypes, ", "))
	}
	for _, grant := range grants {
		if !slices.Contains(transfer.SupportedGrantTypes, grant) {
			return transfer.OAuthClientCreateRequest{}, errors.Errorf(
				"unsupported grant type %q; accepted values are %s",
				grant, strings.Join(transfer.SupportedGrantTypes, ", "))
		}
	}

	return transfer.OAuthClientCreateRequest{
		Name:         name,
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		GrantTypes:   strings.Join(grants, " "),
		Scopes:       strings.Join(splitAndTrim(scopes), " "),
	}, nil
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

	req, err := buildOAuthClientCreateRequest(oauthName, oauthIssuerURL, oauthClientID,
		oauthClientSecret, oauthGrantTypes, oauthScopes)
	if err != nil {
		return err
	}

	bodyBytes, err := json.Marshal(req)
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
