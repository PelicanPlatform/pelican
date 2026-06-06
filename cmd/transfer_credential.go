//go:build client || server

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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/transfer"
)

var (
	credentialCmd = &cobra.Command{
		Use:   "credential",
		Short: "Manage transfer credentials",
	}

	credentialAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new credential to the transfer server",
		RunE:  credentialAddMain,
	}

	credentialListCmd = &cobra.Command{
		Use:   "list",
		Short: "List credentials on the transfer server",
		RunE:  credentialListMain,
	}

	credentialDeleteCmd = &cobra.Command{
		Use:   "delete {id}",
		Short: "Delete a credential from the transfer server",
		Args:  cobra.ExactArgs(1),
		RunE:  credentialDeleteMain,
	}

	credName            string
	credAccessTokenFile string
	credIssuer          string
)

func init() {
	transferCmd.AddCommand(credentialCmd)
	credentialCmd.AddCommand(credentialAddCmd)
	credentialCmd.AddCommand(credentialListCmd)
	credentialCmd.AddCommand(credentialDeleteCmd)

	credentialAddCmd.Flags().StringVar(&credName, "name", "", "Name for the credential (required)")
	credentialAddCmd.Flags().StringVar(&credAccessTokenFile, "access-token-file", "", "Path to a file containing the access token (reads from stdin if not provided)")
	credentialAddCmd.Flags().StringVar(&credIssuer, "issuer", "", "Token issuer URL")
}

// newTransferHTTPClient creates an HTTP client and resolves the server URL
// and bearer token for transfer API requests.
// If the server URL contains no scheme, "https://" is prepended automatically.
func newTransferHTTPClient() (*http.Client, string, string, error) {
	serverURL := transferServerURL
	if serverURL == "" {
		return nil, "", "", errors.New("--server flag is required")
	}
	if !strings.Contains(serverURL, "://") {
		serverURL = "https://" + serverURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	tokenValue := ""
	if transferToken != "" {
		tokenBytes, err := os.ReadFile(transferToken)
		if err != nil {
			return nil, "", "", errors.Wrap(err, "failed to read token file")
		}
		tokenValue = strings.TrimSpace(string(tokenBytes))
	}

	transport := config.GetTransport()

	client := &http.Client{Transport: transport}
	return client, serverURL, tokenValue, nil
}

// doTransferRequest is a convenience wrapper for transfer server API calls.
// It builds the request, sets Content-Type and Authorization headers, executes
// the call, and parses structured error responses on failure.
// On success (any 2xx) it returns the raw response body.
func doTransferRequest(ctx context.Context, httpClient *http.Client, method, url, token string, body []byte) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to create request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to contact transfer server")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		// Try to parse a structured error from the server.
		var errResp transfer.ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, resp.StatusCode, fmt.Errorf("server error %d (%s): %s", resp.StatusCode, errResp.Code, errResp.Error)
		}
		return nil, resp.StatusCode, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, resp.StatusCode, nil
}

func credentialAddMain(cmd *cobra.Command, args []string) error {
	if credName == "" {
		return errors.New("--name is required")
	}

	var accessToken string
	if credAccessTokenFile != "" {
		tokenBytes, err := os.ReadFile(credAccessTokenFile)
		if err != nil {
			return errors.Wrap(err, "failed to read access token file")
		}
		accessToken = strings.TrimSpace(string(tokenBytes))
	} else {
		// Read from stdin
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return errors.Wrap(err, "failed to read access token from stdin")
		}
		accessToken = strings.TrimSpace(string(data))
	}
	if accessToken == "" {
		return errors.New("access token must be provided via --access-token-file or stdin")
	}

	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	reqBody := map[string]string{
		"name":         credName,
		"access_token": accessToken,
	}
	if credIssuer != "" {
		reqBody["token_issuer"] = credIssuer
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to marshal request")
	}

	respBody, _, err := doTransferRequest(cmd.Context(), httpClient, http.MethodPost,
		serverURL+"/api/v1.0/transfer/credentials", tokenValue, bodyBytes)
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
		fmt.Printf("Credential created: %s (id: %s)\n", result["name"], result["id"])
	}

	return nil
}

func credentialListMain(cmd *cobra.Command, args []string) error {
	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	respBody, _, err := doTransferRequest(cmd.Context(), httpClient, http.MethodGet,
		serverURL+"/api/v1.0/transfer/credentials", tokenValue, nil)
	if err != nil {
		return err
	}

	if outputJSON {
		fmt.Println(string(respBody))
		return nil
	}

	var creds []map[string]interface{}
	if err := json.Unmarshal(respBody, &creds); err != nil {
		return errors.Wrap(err, "failed to parse response")
	}

	if len(creds) == 0 {
		fmt.Println("No credentials found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tISSUER\tCREATED")
	for _, c := range creds {
		id, _ := c["id"].(string)
		name, _ := c["name"].(string)
		ctype, _ := c["credential_type"].(string)
		issuer, _ := c["token_issuer"].(string)
		created, _ := c["created_at"].(string)
		if len(created) > 19 {
			created = created[:19]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", id, name, ctype, issuer, created)
	}
	w.Flush()

	return nil
}

func credentialDeleteMain(cmd *cobra.Command, args []string) error {
	credID := args[0]

	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return err
	}

	_, _, err = doTransferRequest(cmd.Context(), httpClient, http.MethodDelete,
		serverURL+"/api/v1.0/transfer/credentials/"+credID, tokenValue, nil)
	if err != nil {
		return err
	}

	if outputJSON {
		result, _ := json.Marshal(map[string]string{"id": credID, "status": "deleted"})
		fmt.Println(string(result))
	} else {
		fmt.Printf("Credential %s deleted.\n", credID)
	}
	return nil
}
