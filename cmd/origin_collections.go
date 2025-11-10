/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	originCollectionsCmd = &cobra.Command{
		Use:   "collections",
		Short: "Manage collections on a Pelican origin",
		Long:  "Manage collections on a Pelican origin server using OAuth2 authentication",
	}
	collectionsOutputJSON bool
)

// Director server response structures
type directorServerResponse struct {
	Name           string `json:"name"`
	WebURL         string `json:"webUrl"`
	Type           string `json:"type"`
	AuthURL        string `json:"authUrl"`
	RegistryPrefix string `json:"registryPrefix"`
}

// getDirectorOriginWebUrl queries the Director API to find an origin server's web URL
func getDirectorOriginWebUrl(ctx context.Context) (string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to get federation information")
	}

	directorUrlStr := fedInfo.DirectorEndpoint
	if directorUrlStr == "" {
		return "", errors.New("Director endpoint not found in federation configuration. Please set Federation.DirectorUrl")
	}

	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "invalid Director URL")
	}

	// Construct the servers API endpoint
	serversUrl, err := url.JoinPath(directorUrl.String(), "/api/v1.0/director_ui/servers")
	if err != nil {
		return "", errors.Wrap(err, "failed to construct Director servers URL")
	}

	// Query with server_type=origin to only get origin servers
	serversUrlParsed, err := url.Parse(serversUrl)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse Director servers URL")
	}
	q := serversUrlParsed.Query()
	q.Set("server_type", "origin")
	serversUrlParsed.RawQuery = q.Encode()

	// Make HTTP request
	client := &http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serversUrlParsed.String(), nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create Director API request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to query Director API")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.Errorf("Director API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read Director API response")
	}

	var servers []directorServerResponse
	if err := json.Unmarshal(body, &servers); err != nil {
		return "", errors.Wrap(err, "failed to parse Director API response")
	}

	if len(servers) == 0 {
		return "", errors.New("no origin servers found in Director")
	}

	// Use the first origin server found
	// TODO: Could add a flag to specify which origin to use if multiple exist
	origin := servers[0]
	if origin.WebURL == "" {
		return "", errors.Errorf("origin server '%s' does not have a webUrl", origin.Name)
	}

	return origin.WebURL, nil
}

// acquireOAuthToken performs OAuth2 device flow to get a token with the specified scopes
func acquireOAuthToken(ctx context.Context, issuerUrl string, scopes []string) (string, error) {
	// Get issuer metadata
	issuerInfo, err := config.GetIssuerMetadata(issuerUrl)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get issuer metadata from %s", issuerUrl)
	}

	// Check if device code flow is supported
	if !deviceCodeSupported(&issuerInfo.GrantTypes) {
		return "", errors.Errorf("issuer at %s does not support device flow", issuerUrl)
	}

	// Get or register OAuth client credentials
	// Use issuerUrl as the prefix identifier for storing credentials
	osdfConfig, err := config.GetCredentialConfigContents()
	if err != nil {
		return "", errors.Wrap(err, "failed to get credential config")
	}

	var prefixEntry *config.PrefixEntry
	prefixIdx := -1

	// Look for existing credentials for this issuer
	for idx, entry := range osdfConfig.OSDF.OauthClient {
		if entry.Prefix == issuerUrl {
			prefixIdx = idx
			prefixEntry = &osdfConfig.OSDF.OauthClient[idx]
			break
		}
	}

	// If no credentials found, register a new client
	if prefixIdx < 0 || prefixEntry.ClientID == "" || prefixEntry.ClientSecret == "" {
		if issuerInfo.RegistrationURL == "" {
			return "", errors.Errorf("issuer %s does not support dynamic client registration and no credentials are configured", issuerUrl)
		}

		// Register new client
		drcp := pelican_oauth2.DCRPConfig{
			ClientRegistrationEndpointURL: issuerInfo.RegistrationURL,
			Transport:                     config.GetTransport(),
			Metadata: pelican_oauth2.Metadata{
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Pelican Collections CLI Client",
				Scopes:                  scopes,
			},
		}

		resp, err := drcp.Register()
		if err != nil {
			return "", errors.Wrap(err, "failed to register OAuth client")
		}

		newEntry := config.PrefixEntry{
			Prefix:       issuerUrl,
			ClientID:     resp.ClientID,
			ClientSecret: resp.ClientSecret,
		}

		if prefixIdx < 0 {
			// Add new entry
			osdfConfig.OSDF.OauthClient = append(osdfConfig.OSDF.OauthClient, newEntry)
			prefixEntry = &osdfConfig.OSDF.OauthClient[len(osdfConfig.OSDF.OauthClient)-1]
		} else {
			// Update existing entry
			osdfConfig.OSDF.OauthClient[prefixIdx] = newEntry
			prefixEntry = &newEntry
		}

		// Save credentials
		if err := config.SaveConfigContents(&osdfConfig); err != nil {
			return "", errors.Wrap(err, "failed to save OAuth client credentials")
		}
	}

	// Build OAuth2 config
	oauth2Config := pelican_oauth2.Config{
		ClientID:     prefixEntry.ClientID,
		ClientSecret: prefixEntry.ClientSecret,
		Endpoint: pelican_oauth2.Endpoint{
			AuthURL:       issuerInfo.AuthURL,
			TokenURL:      issuerInfo.TokenURL,
			DeviceAuthURL: issuerInfo.DeviceAuthURL,
		},
		Scopes: scopes,
	}

	// Start device flow
	client := &http.Client{Transport: config.GetTransport()}
	oauthCtx := context.WithValue(ctx, pelican_oauth2.HTTPClient, client)
	deviceAuth, err := oauth2Config.AuthDevice(oauthCtx)
	if err != nil {
		return "", errors.Wrapf(err, "failed to perform device code flow with URL %s", issuerInfo.DeviceAuthURL)
	}

	// Print instructions to user
	if len(deviceAuth.VerificationURIComplete) > 0 {
		fmt.Fprintln(os.Stderr, "To approve credentials for this operation, please navigate to the following URL and approve the request:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, deviceAuth.VerificationURIComplete)
	} else {
		fmt.Fprintln(os.Stderr, "To approve credentials for this operation, please navigate to the following URL:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, deviceAuth.VerificationURI)
		fmt.Fprintln(os.Stderr, "\nand enter the following code")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, deviceAuth.UserCode)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Waiting for approval...")

	// Poll for token
	upstreamToken, err := oauth2Config.Poll(oauthCtx, deviceAuth)
	if err != nil {
		return "", errors.Wrap(err, "failed to acquire token - please ensure you have approved the request in your browser")
	}

	fmt.Fprintln(os.Stderr, "Token acquired successfully.")

	return upstreamToken.AccessToken, nil
}

// deviceCodeSupported checks if device code flow is supported
func deviceCodeSupported(grantTypes *[]string) bool {
	if grantTypes == nil {
		return false
	}
	deviceFlowGrant := "urn:ietf:params:oauth:grant-type:device_code"
	for _, gt := range *grantTypes {
		if gt == deviceFlowGrant {
			return true
		}
	}
	return false
}

// makeCollectionAPIRequest makes an authenticated HTTP request to the collections API
// collectionID is optional - if provided, it will be included in the scope for ACL checking
func makeCollectionAPIRequest(ctx context.Context, method, endpoint string, body interface{}, scope token_scopes.TokenScope, collectionID string) ([]byte, error) {
	// Get origin web URL from Director
	originWebUrl, err := getDirectorOriginWebUrl(ctx)
	if err != nil {
		return nil, err
	}

	// Construct API URL
	apiUrl, err := url.JoinPath(originWebUrl, "/api/v1.0/origin_ui", endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct API URL")
	}

	// Build scope string - include collection ID if provided
	// Format: "collection.read:collection_id" for ACL checking in OA4MP proxy
	scopeStr := string(scope)
	if collectionID != "" && strings.HasPrefix(scopeStr, "collection.") {
		scopeStr = scopeStr + ":" + collectionID
	}

	// Get OAuth token with collection-specific scope
	scopes := []string{scopeStr}
	token, err := acquireOAuthToken(ctx, originWebUrl, scopes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to acquire OAuth token")
	}

	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal request body")
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, apiUrl, bodyReader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Make request
	client := &http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute HTTP request")
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiResp server_structs.SimpleApiResp
		if err := json.Unmarshal(respBody, &apiResp); err == nil && apiResp.Msg != "" {
			return nil, errors.Errorf("API error (status %d): %s", resp.StatusCode, apiResp.Msg)
		}
		return nil, errors.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// formatOutput formats output as JSON or human-readable based on global flag
func formatOutput(data interface{}) error {
	if collectionsOutputJSON {
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return errors.Wrap(err, "failed to marshal JSON")
		}
		fmt.Println(string(jsonBytes))
		return nil
	}

	// Human-readable format
	switch v := data.(type) {
	case []origin.ListCollectionRes:
		if len(v) == 0 {
			fmt.Println("No collections found")
			return nil
		}
		fmt.Printf("Found %d collection(s):\n\n", len(v))
		for _, coll := range v {
			fmt.Printf("ID:          %s\n", coll.ID)
			fmt.Printf("Name:        %s\n", coll.Name)
			fmt.Printf("Namespace:   %s\n", coll.Namespace)
			fmt.Printf("Visibility:  %s\n", coll.Visibility)
			if coll.Description != "" {
				fmt.Printf("Description: %s\n", coll.Description)
			}
			fmt.Printf("Owner ID:    %s\n", coll.OwnerID)
			fmt.Println()
		}
	case origin.GetCollectionRes:
		fmt.Printf("ID:          %s\n", v.ID)
		fmt.Printf("Name:        %s\n", v.Name)
		fmt.Printf("Namespace:   %s\n", v.Namespace)
		fmt.Printf("Visibility:  %s\n", v.Visibility)
		if v.Description != "" {
			fmt.Printf("Description: %s\n", v.Description)
		}
		fmt.Printf("Owner ID:    %s\n", v.OwnerID)
		fmt.Printf("Created:     %s\n", v.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Updated:     %s\n", v.UpdatedAt.Format(time.RFC3339))

		if len(v.Members) > 0 {
			fmt.Printf("\nMembers (%d):\n", len(v.Members))
			for _, member := range v.Members {
				fmt.Printf("  - %s\n", member)
			}
		}

		if len(v.ACLs) > 0 {
			fmt.Printf("\nACLs (%d):\n", len(v.ACLs))
			for _, acl := range v.ACLs {
				fmt.Printf("  - Group: %s, Role: %s", acl.GroupID, acl.Role)
				if acl.ExpiresAt != nil {
					fmt.Printf(", Expires: %s", acl.ExpiresAt.Format(time.RFC3339))
				}
				fmt.Println()
			}
		}

		if len(v.Metadata) > 0 {
			fmt.Printf("\nMetadata (%d):\n", len(v.Metadata))
			for key, value := range v.Metadata {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
	case map[string]string:
		if len(v) == 0 {
			fmt.Println("No metadata")
			return nil
		}
		for key, value := range v {
			fmt.Printf("%s: %s\n", key, value)
		}
	case []database.CollectionACL:
		if len(v) == 0 {
			fmt.Println("No ACLs")
			return nil
		}
		for _, acl := range v {
			fmt.Printf("Group: %s, Role: %s", acl.GroupID, acl.Role)
			if acl.ExpiresAt != nil {
				fmt.Printf(", Expires: %s", acl.ExpiresAt.Format(time.RFC3339))
			}
			fmt.Println()
		}
	default:
		// Fallback to JSON for unknown types
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return errors.Wrap(err, "failed to marshal JSON")
		}
		fmt.Println(string(jsonBytes))
	}
	return nil
}

// Command implementations
var originCollectionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all collections",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		// List command - no specific collection ID
		respBody, err := makeCollectionAPIRequest(ctx, http.MethodGet, "/collections", nil, token_scopes.Collection_Read, "")
		if err != nil {
			return err
		}

		var collections []origin.ListCollectionRes
		if err := json.Unmarshal(respBody, &collections); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}

		return formatOutput(collections)
	},
}

var originCollectionsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new collection",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		name, _ := cmd.Flags().GetString("name")
		namespace, _ := cmd.Flags().GetString("namespace")
		description, _ := cmd.Flags().GetString("description")
		visibility, _ := cmd.Flags().GetString("visibility")
		metadataFlags, _ := cmd.Flags().GetStringSlice("metadata")

		if name == "" {
			return errors.New("--name is required")
		}
		if namespace == "" {
			return errors.New("--namespace is required")
		}

		req := origin.CreateCollectionReq{
			Name:        name,
			Namespace:   namespace,
			Description: description,
			Visibility:  visibility,
		}

		// Parse metadata key=value pairs
		if len(metadataFlags) > 0 {
			req.Metadata = make(map[string]string)
			for _, meta := range metadataFlags {
				parts := strings.SplitN(meta, "=", 2)
				if len(parts) != 2 {
					return errors.Errorf("invalid metadata format '%s', expected key=value", meta)
				}
				req.Metadata[parts[0]] = parts[1]
			}
		}

		// Create command - no collection ID yet (creating new collection)
		respBody, err := makeCollectionAPIRequest(ctx, http.MethodPost, "/collections", req, token_scopes.Collection_Create, "")
		if err != nil {
			return err
		}

		var collection origin.GetCollectionRes
		if err := json.Unmarshal(respBody, &collection); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}

		fmt.Println("Collection created successfully:")
		return formatOutput(collection)
	},
}

var originCollectionsGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get a collection by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s", id)

		respBody, err := makeCollectionAPIRequest(ctx, http.MethodGet, endpoint, nil, token_scopes.Collection_Read, id)
		if err != nil {
			return err
		}

		var collection origin.GetCollectionRes
		if err := json.Unmarshal(respBody, &collection); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}

		return formatOutput(collection)
	},
}

var originCollectionsUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s", id)

		req := origin.UpdateCollectionReq{}
		flagsSet := false

		if cmd.Flags().Changed("name") {
			name, _ := cmd.Flags().GetString("name")
			req.Name = &name
			flagsSet = true
		}
		if cmd.Flags().Changed("description") {
			description, _ := cmd.Flags().GetString("description")
			req.Description = &description
			flagsSet = true
		}
		if cmd.Flags().Changed("visibility") {
			visibility, _ := cmd.Flags().GetString("visibility")
			req.Visibility = &visibility
			flagsSet = true
		}

		if !flagsSet {
			return errors.New("at least one of --name, --description, or --visibility must be provided")
		}

		respBody, err := makeCollectionAPIRequest(ctx, http.MethodPatch, endpoint, req, token_scopes.Collection_Modify, id)
		if err != nil {
			return err
		}

		if len(respBody) == 0 {
			fmt.Println("Collection updated successfully")
			return nil
		}

		var collection origin.GetCollectionRes
		if err := json.Unmarshal(respBody, &collection); err == nil {
			return formatOutput(collection)
		}

		return nil
	},
}

var originCollectionsDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s", id)

		_, err := makeCollectionAPIRequest(ctx, http.MethodDelete, endpoint, nil, token_scopes.Collection_Delete, id)
		if err != nil {
			return err
		}

		fmt.Println("Collection deleted successfully")
		return nil
	},
}

var originCollectionsMetadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Manage collection metadata",
}

var originCollectionsMetadataGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get all metadata for a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s/metadata", id)

		respBody, err := makeCollectionAPIRequest(ctx, http.MethodGet, endpoint, nil, token_scopes.Collection_Read, id)
		if err != nil {
			return err
		}

		var metadata map[string]string
		if err := json.Unmarshal(respBody, &metadata); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}

		return formatOutput(metadata)
	},
}

var originCollectionsMetadataSetCmd = &cobra.Command{
	Use:   "set <id> <key> <value>",
	Short: "Set a metadata key-value pair for a collection",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		key := args[1]
		value := args[2]
		endpoint := fmt.Sprintf("/collections/%s/metadata/%s", id, url.PathEscape(key))

		req := origin.MetadataValue{Value: value}

		_, err := makeCollectionAPIRequest(ctx, http.MethodPut, endpoint, req, token_scopes.Collection_Modify, id)
		if err != nil {
			return err
		}

		fmt.Printf("Metadata key '%s' set successfully\n", key)
		return nil
	},
}

var originCollectionsMetadataDeleteCmd = &cobra.Command{
	Use:   "delete <id> <key>",
	Short: "Delete a metadata key from a collection",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		key := args[1]
		endpoint := fmt.Sprintf("/collections/%s/metadata/%s", id, url.PathEscape(key))

		_, err := makeCollectionAPIRequest(ctx, http.MethodDelete, endpoint, nil, token_scopes.Collection_Modify, id)
		if err != nil {
			return err
		}

		fmt.Printf("Metadata key '%s' deleted successfully\n", key)
		return nil
	},
}

var originCollectionsACLCmd = &cobra.Command{
	Use:   "acl",
	Short: "Manage collection ACLs",
}

var originCollectionsACLListCmd = &cobra.Command{
	Use:   "list <id>",
	Short: "List all ACLs for a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s/acl", id)

		respBody, err := makeCollectionAPIRequest(ctx, http.MethodGet, endpoint, nil, token_scopes.Collection_Read, id)
		if err != nil {
			return err
		}

		var acls []database.CollectionACL
		if err := json.Unmarshal(respBody, &acls); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}

		return formatOutput(acls)
	},
}

var originCollectionsACLGrantCmd = &cobra.Command{
	Use:   "grant <id>",
	Short: "Grant an ACL to a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s/acl", id)

		groupID, _ := cmd.Flags().GetString("group-id")
		role, _ := cmd.Flags().GetString("role")
		expiresAtStr, _ := cmd.Flags().GetString("expires-at")

		if groupID == "" {
			return errors.New("--group-id is required")
		}
		if role == "" {
			return errors.New("--role is required")
		}

		req := origin.GrantAclReq{
			GroupID: groupID,
			Role:    role,
		}

		if expiresAtStr != "" {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
			if err != nil {
				return errors.Wrap(err, "invalid expires-at format, use RFC3339 (e.g., 2006-01-02T15:04:05Z07:00)")
			}
			req.ExpiresAt = &expiresAt
		}

		_, err := makeCollectionAPIRequest(ctx, http.MethodPost, endpoint, req, token_scopes.Collection_Modify, id)
		if err != nil {
			return err
		}

		fmt.Println("ACL granted successfully")
		return nil
	},
}

var originCollectionsACLRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an ACL from a collection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "failed to initialize client")
		}

		id := args[0]
		endpoint := fmt.Sprintf("/collections/%s/acl", id)

		groupID, _ := cmd.Flags().GetString("group-id")
		role, _ := cmd.Flags().GetString("role")

		if groupID == "" {
			return errors.New("--group-id is required")
		}
		if role == "" {
			return errors.New("--role is required")
		}

		req := origin.RevokeAclReq{
			GroupID: groupID,
			Role:    role,
		}

		_, err := makeCollectionAPIRequest(ctx, http.MethodDelete, endpoint, req, token_scopes.Collection_Modify, id)
		if err != nil {
			return err
		}

		fmt.Println("ACL revoked successfully")
		return nil
	},
}

func init() {
	// Global JSON output flag
	originCollectionsCmd.PersistentFlags().BoolVar(&collectionsOutputJSON, "json", false, "Output in JSON format")

	// Create command flags
	originCollectionsCreateCmd.Flags().String("name", "", "Collection name (required)")
	originCollectionsCreateCmd.Flags().String("namespace", "", "Collection namespace (required)")
	originCollectionsCreateCmd.Flags().String("description", "", "Collection description")
	originCollectionsCreateCmd.Flags().String("visibility", "private", "Collection visibility (private|public)")
	originCollectionsCreateCmd.Flags().StringSlice("metadata", []string{}, "Metadata as key=value pairs (can be specified multiple times)")

	originCollectionsUpdateCmd.Flags().String("name", "", "New collection name")
	originCollectionsUpdateCmd.Flags().String("description", "", "New collection description")
	originCollectionsUpdateCmd.Flags().String("visibility", "", "New collection visibility (private|public)")

	originCollectionsACLGrantCmd.Flags().String("group-id", "", "Group ID for the ACL (required)")
	originCollectionsACLGrantCmd.Flags().String("role", "", "Role for the ACL (required)")
	originCollectionsACLGrantCmd.Flags().String("expires-at", "", "Expiration time in RFC3339 format (e.g., 2006-01-02T15:04:05Z07:00)")

	originCollectionsACLRevokeCmd.Flags().String("group-id", "", "Group ID for the ACL (required)")
	originCollectionsACLRevokeCmd.Flags().String("role", "", "Role for the ACL (required)")

	// Register commands
	originCollectionsCmd.AddCommand(originCollectionsListCmd)
	originCollectionsCmd.AddCommand(originCollectionsCreateCmd)
	originCollectionsCmd.AddCommand(originCollectionsGetCmd)
	originCollectionsCmd.AddCommand(originCollectionsUpdateCmd)
	originCollectionsCmd.AddCommand(originCollectionsDeleteCmd)
	originCollectionsCmd.AddCommand(originCollectionsMetadataCmd)
	originCollectionsCmd.AddCommand(originCollectionsACLCmd)

	originCollectionsMetadataCmd.AddCommand(originCollectionsMetadataGetCmd)
	originCollectionsMetadataCmd.AddCommand(originCollectionsMetadataSetCmd)
	originCollectionsMetadataCmd.AddCommand(originCollectionsMetadataDeleteCmd)

	originCollectionsACLCmd.AddCommand(originCollectionsACLListCmd)
	originCollectionsACLCmd.AddCommand(originCollectionsACLGrantCmd)
	originCollectionsACLCmd.AddCommand(originCollectionsACLRevokeCmd)
}
