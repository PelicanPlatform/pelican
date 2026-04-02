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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	originGroupCmd = &cobra.Command{
		Use:   "group",
		Short: "Manage groups on a Pelican origin",
		Long:  "Manage groups on a Pelican origin server. Requires authentication.",
	}
)

// makeGroupAPICall is a helper that performs an authenticated API call for group/user endpoints.
// It uses the same admin token pattern as the collection API.
func makeGroupAPICall(method, path string, body interface{}) ([]byte, error) {
	serverURLStr, err := getOriginServerURL()
	if err != nil {
		return nil, err
	}

	apiUrl := serverURLStr + path

	tok, err := fetchOrGenerateWebAPIAdminToken(serverURLStr, "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to acquire admin token")
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal request body")
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, apiUrl, bodyReader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute HTTP request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiResp server_structs.SimpleApiResp
		if err := json.Unmarshal(respBody, &apiResp); err == nil && apiResp.Msg != "" {
			return nil, errors.Errorf("API error (status %d): %s", resp.StatusCode, apiResp.Msg)
		}
		return nil, errors.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// getOriginServerURL returns the origin server's URL for direct API calls.
func getOriginServerURL() (string, error) {
	webURL := param.Server_ExternalWebUrl.GetString()
	if webURL == "" {
		return "", errors.New("server external web URL not configured; set Server.ExternalWebUrl")
	}
	return webURL, nil
}

// ===== Group commands =====

var originGroupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/groups", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var groups []map[string]interface{}
		if err := json.Unmarshal(respBody, &groups); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(groups) == 0 {
			fmt.Println("No groups found")
			return nil
		}
		fmt.Printf("Found %d group(s):\n\n", len(groups))
		for _, g := range groups {
			fmt.Printf("ID:          %v\n", g["id"])
			fmt.Printf("Name:        %v\n", g["name"])
			if desc, ok := g["description"]; ok && desc != "" {
				fmt.Printf("Description: %v\n", desc)
			}
			fmt.Printf("Owner:       %v\n", g["ownerId"])
			fmt.Println()
		}
		return nil
	},
}

var originGroupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		description, _ := cmd.Flags().GetString("description")
		if name == "" {
			return errors.New("--name is required")
		}
		body := map[string]string{
			"name":        name,
			"description": description,
		}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/groups", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var g map[string]interface{}
		if err := json.Unmarshal(respBody, &g); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		fmt.Printf("Group created successfully!\nID:   %v\nName: %v\n", g["id"], g["name"])
		return nil
	},
}

var originGroupDeleteCmd = &cobra.Command{
	Use:   "delete <group-id>",
	Short: "Delete a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/groups/"+args[0], nil)
		if err != nil {
			return err
		}
		fmt.Println("Group deleted successfully")
		return nil
	},
}

var originGroupAddMemberCmd = &cobra.Command{
	Use:   "add-member <group-id>",
	Short: "Add a member to a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")
		if userID == "" {
			return errors.New("--user-id is required")
		}
		body := map[string]string{"userId": userID}
		_, err := makeGroupAPICall("POST", "/api/v1.0/groups/"+args[0]+"/members", body)
		if err != nil {
			return err
		}
		fmt.Println("Member added successfully")
		return nil
	},
}

var originGroupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member <group-id>",
	Short: "Remove a member from a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")
		if userID == "" {
			return errors.New("--user-id is required")
		}
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/groups/"+args[0]+"/members/"+userID, nil)
		if err != nil {
			return err
		}
		fmt.Println("Member removed successfully")
		return nil
	},
}

var originGroupSetOwnershipCmd = &cobra.Command{
	Use:   "set-ownership <group-id>",
	Short: "Set owner or admin of a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]interface{}{}
		if cmd.Flags().Changed("owner-id") {
			v, _ := cmd.Flags().GetString("owner-id")
			body["ownerId"] = v
		}
		if cmd.Flags().Changed("admin-id") {
			v, _ := cmd.Flags().GetString("admin-id")
			body["adminId"] = v
		}
		if cmd.Flags().Changed("admin-type") {
			v, _ := cmd.Flags().GetString("admin-type")
			body["adminType"] = v
		}
		if len(body) == 0 {
			return errors.New("at least one of --owner-id, --admin-id, --admin-type is required")
		}
		_, err := makeGroupAPICall("PUT", "/api/v1.0/groups/"+args[0]+"/ownership", body)
		if err != nil {
			return err
		}
		fmt.Println("Group ownership updated successfully")
		return nil
	},
}

// ===== Invite link commands =====

var originGroupInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage group invite links",
}

var originGroupInviteCreateCmd = &cobra.Command{
	Use:   "create <group-id>",
	Short: "Create an invite link for a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		singleUse, _ := cmd.Flags().GetBool("single-use")
		expiresIn, _ := cmd.Flags().GetString("expires-in")
		body := map[string]interface{}{
			"isSingleUse": singleUse,
		}
		if expiresIn != "" {
			body["expiresIn"] = expiresIn
		}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/groups/"+args[0]+"/invites", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		fmt.Println("Invite link created successfully!")
		fmt.Printf("Token:       %v\n", result["inviteToken"])
		fmt.Printf("Link ID:     %v\n", result["id"])
		fmt.Printf("Expires At:  %v\n", result["expiresAt"])
		fmt.Printf("Single Use:  %v\n", result["isSingleUse"])
		fmt.Println("\nShare the token with the user. It is shown only once.")
		return nil
	},
}

var originGroupInviteListCmd = &cobra.Command{
	Use:   "list <group-id>",
	Short: "List invite links for a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/groups/"+args[0]+"/invites", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var links []map[string]interface{}
		if err := json.Unmarshal(respBody, &links); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(links) == 0 {
			fmt.Println("No invite links found")
			return nil
		}
		fmt.Printf("Found %d invite link(s):\n\n", len(links))
		for _, l := range links {
			fmt.Printf("ID:          %v\n", l["id"])
			fmt.Printf("Expires:     %v\n", l["expiresAt"])
			fmt.Printf("Single Use:  %v\n", l["isSingleUse"])
			fmt.Printf("Revoked:     %v\n", l["revoked"])
			fmt.Println()
		}
		return nil
	},
}

var originGroupInviteRevokeCmd = &cobra.Command{
	Use:   "revoke <group-id> <link-id>",
	Short: "Revoke an invite link",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/groups/"+args[0]+"/invites/"+args[1], nil)
		if err != nil {
			return err
		}
		fmt.Println("Invite link revoked successfully")
		return nil
	},
}

var originGroupInviteRedeemCmd = &cobra.Command{
	Use:   "redeem <token>",
	Short: "Redeem an invite link token to join a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{"token": args[0]}
		_, err := makeGroupAPICall("POST", "/api/v1.0/invites/redeem", body)
		if err != nil {
			return err
		}
		fmt.Println("Successfully joined the group!")
		return nil
	},
}

// ===== User commands =====

var originUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users on a Pelican origin",
	Long:  "Manage users on a Pelican origin server. Requires authentication.",
}

var originUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/users", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var users []map[string]interface{}
		if err := json.Unmarshal(respBody, &users); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(users) == 0 {
			fmt.Println("No users found")
			return nil
		}
		fmt.Printf("Found %d user(s):\n\n", len(users))
		for _, u := range users {
			fmt.Printf("ID:       %v\n", u["id"])
			fmt.Printf("Username: %v\n", u["username"])
			fmt.Printf("Status:   %v\n", u["status"])
			if dn, ok := u["displayName"]; ok && dn != "" {
				fmt.Printf("Name:     %v\n", dn)
			}
			fmt.Println()
		}
		return nil
	},
}

var originUserCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		sub, _ := cmd.Flags().GetString("sub")
		issuer, _ := cmd.Flags().GetString("issuer")
		if username == "" || sub == "" || issuer == "" {
			return errors.New("--username, --sub, and --issuer are required")
		}
		body := map[string]string{
			"username": username,
			"sub":      sub,
			"issuer":   issuer,
		}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/users", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var u map[string]interface{}
		if err := json.Unmarshal(respBody, &u); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		fmt.Printf("User created successfully!\nID:       %v\nUsername: %v\n", u["id"], u["username"])
		return nil
	},
}

var originUserDeleteCmd = &cobra.Command{
	Use:   "delete <user-id>",
	Short: "Delete a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/users/"+args[0], nil)
		if err != nil {
			return err
		}
		fmt.Println("User deleted successfully")
		return nil
	},
}

var originUserStatusCmd = &cobra.Command{
	Use:   "set-status <user-id>",
	Short: "Update user status and display name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]interface{}{}
		if cmd.Flags().Changed("status") {
			v, _ := cmd.Flags().GetString("status")
			body["status"] = v
		}
		if cmd.Flags().Changed("display-name") {
			v, _ := cmd.Flags().GetString("display-name")
			body["displayName"] = v
		}
		if len(body) == 0 {
			return errors.New("at least one of --status or --display-name is required")
		}
		_, err := makeGroupAPICall("PUT", "/api/v1.0/users/"+args[0]+"/status", body)
		if err != nil {
			return err
		}
		fmt.Println("User status updated successfully")
		return nil
	},
}

var originUserIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage user identities",
}

var originUserIdentityListCmd = &cobra.Command{
	Use:   "list <user-id>",
	Short: "List identities for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/users/"+args[0]+"/identities", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var ids []map[string]interface{}
		if err := json.Unmarshal(respBody, &ids); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(ids) == 0 {
			fmt.Println("No identities found")
			return nil
		}
		for _, id := range ids {
			fmt.Printf("ID:     %v\n", id["id"])
			fmt.Printf("Sub:    %v\n", id["sub"])
			fmt.Printf("Issuer: %v\n", id["issuer"])
			fmt.Println()
		}
		return nil
	},
}

var originUserIdentityAddCmd = &cobra.Command{
	Use:   "add <user-id>",
	Short: "Add an identity to a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sub, _ := cmd.Flags().GetString("sub")
		issuer, _ := cmd.Flags().GetString("issuer")
		if sub == "" || issuer == "" {
			return errors.New("--sub and --issuer are required")
		}
		body := map[string]string{"sub": sub, "issuer": issuer}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/users/"+args[0]+"/identities", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		fmt.Println("Identity added successfully")
		return nil
	},
}

var originUserIdentityRemoveCmd = &cobra.Command{
	Use:   "remove <user-id> <identity-id>",
	Short: "Remove an identity from a user",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/users/"+args[0]+"/identities/"+args[1], nil)
		if err != nil {
			return err
		}
		fmt.Println("Identity removed successfully")
		return nil
	},
}

func init() {
	// Suppress unused import errors - time is used for formatting output
	_ = time.Now

	// Group commands
	originGroupCreateCmd.Flags().String("name", "", "Name of the group (required)")
	originGroupCreateCmd.Flags().String("description", "", "Description of the group")

	originGroupAddMemberCmd.Flags().String("user-id", "", "User ID to add (required)")
	originGroupRemoveMemberCmd.Flags().String("user-id", "", "User ID to remove (required)")

	originGroupSetOwnershipCmd.Flags().String("owner-id", "", "New owner user ID")
	originGroupSetOwnershipCmd.Flags().String("admin-id", "", "Admin user or group ID")
	originGroupSetOwnershipCmd.Flags().String("admin-type", "", "Admin type: 'user' or 'group'")

	// Invite commands
	originGroupInviteCreateCmd.Flags().Bool("single-use", false, "Create a single-use invite link")
	originGroupInviteCreateCmd.Flags().String("expires-in", "", "Expiration duration (e.g. '168h', '24h')")

	// User commands
	originUserCreateCmd.Flags().String("username", "", "Username (required)")
	originUserCreateCmd.Flags().String("sub", "", "OIDC subject claim (required)")
	originUserCreateCmd.Flags().String("issuer", "", "OIDC issuer URL (required)")

	originUserStatusCmd.Flags().String("status", "", "Status: 'active' or 'inactive'")
	originUserStatusCmd.Flags().String("display-name", "", "Display name")

	originUserIdentityAddCmd.Flags().String("sub", "", "OIDC subject claim (required)")
	originUserIdentityAddCmd.Flags().String("issuer", "", "OIDC issuer URL (required)")

	// Register group subcommands
	originGroupCmd.AddCommand(originGroupListCmd)
	originGroupCmd.AddCommand(originGroupCreateCmd)
	originGroupCmd.AddCommand(originGroupDeleteCmd)
	originGroupCmd.AddCommand(originGroupAddMemberCmd)
	originGroupCmd.AddCommand(originGroupRemoveMemberCmd)
	originGroupCmd.AddCommand(originGroupSetOwnershipCmd)
	originGroupCmd.AddCommand(originGroupInviteCmd)

	originGroupInviteCmd.AddCommand(originGroupInviteCreateCmd)
	originGroupInviteCmd.AddCommand(originGroupInviteListCmd)
	originGroupInviteCmd.AddCommand(originGroupInviteRevokeCmd)
	originGroupInviteCmd.AddCommand(originGroupInviteRedeemCmd)

	// Register user subcommands
	originUserCmd.AddCommand(originUserListCmd)
	originUserCmd.AddCommand(originUserCreateCmd)
	originUserCmd.AddCommand(originUserDeleteCmd)
	originUserCmd.AddCommand(originUserStatusCmd)
	originUserCmd.AddCommand(originUserIdentityCmd)

	originUserIdentityCmd.AddCommand(originUserIdentityListCmd)
	originUserIdentityCmd.AddCommand(originUserIdentityAddCmd)
	originUserIdentityCmd.AddCommand(originUserIdentityRemoveCmd)
}
