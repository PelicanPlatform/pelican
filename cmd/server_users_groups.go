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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	serverGroupCmd = &cobra.Command{
		Use:   "group",
		Short: "Manage groups on a Pelican server",
		Long: `Manage groups on a Pelican server (origin, cache, registry, or
director — wherever users and groups are configured). Requires authentication.`,
	}
)

// makeGroupAPICall is a helper that performs an authenticated API call for group/user endpoints.
// It uses the same admin token pattern as the collection API.
func makeGroupAPICall(method, path string, body interface{}) ([]byte, error) {
	serverURLStr, err := getServerWebURL()
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

// getServerWebURL returns the local server's externally-visible web URL
// for direct API calls. Component-agnostic: any Pelican server (origin,
// cache, registry, director) sets the same Server.ExternalWebUrl, so
// this helper works regardless of which module is enabled.
func getServerWebURL() (string, error) {
	webURL := param.Server_ExternalWebUrl.GetString()
	if webURL == "" {
		return "", errors.New("server external web URL not configured; set Server.ExternalWebUrl")
	}
	return webURL, nil
}

// ===== Group commands =====

var serverGroupListCmd = &cobra.Command{
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

var serverGroupCreateCmd = &cobra.Command{
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

var serverGroupDeleteCmd = &cobra.Command{
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

var serverGroupAddMemberCmd = &cobra.Command{
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

var serverGroupRemoveMemberCmd = &cobra.Command{
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

var serverGroupSetOwnershipCmd = &cobra.Command{
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

var serverGroupInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage group invite links",
}

var serverGroupInviteCreateCmd = &cobra.Command{
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
		fmt.Printf("Token ID:    %v   (public — safe to mention in chat/audit logs)\n", result["tokenPrefix"])
		fmt.Printf("Link ID:     %v\n", result["id"])
		fmt.Printf("Expires At:  %v\n", result["expiresAt"])
		fmt.Printf("Single Use:  %v\n", result["isSingleUse"])
		fmt.Println("\nShare the token with the user. It is shown only once.")
		return nil
	},
}

var serverGroupInviteListCmd = &cobra.Command{
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
			fmt.Printf("Token ID:    %v\n", l["tokenPrefix"])
			fmt.Printf("Expires:     %v\n", l["expiresAt"])
			fmt.Printf("Single Use:  %v\n", l["isSingleUse"])
			fmt.Printf("Revoked:     %v\n", l["revoked"])
			fmt.Println()
		}
		return nil
	},
}

var serverGroupInviteRevokeCmd = &cobra.Command{
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

var serverGroupInviteRedeemCmd = &cobra.Command{
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

// serverGroupGetCmd fetches a single group by ID. Filling the gap with
// the web UI's group-detail view: the CLI previously only had `list`.
var serverGroupGetCmd = &cobra.Command{
	Use:   "get <group-id>",
	Short: "Show details of a single group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/groups/"+args[0], nil)
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
		fmt.Printf("ID:           %v\n", g["id"])
		fmt.Printf("Name:         %v\n", g["name"])
		if dn, ok := g["displayName"]; ok && dn != "" {
			fmt.Printf("Display Name: %v\n", dn)
		}
		if desc, ok := g["description"]; ok && desc != "" {
			fmt.Printf("Description:  %v\n", desc)
		}
		fmt.Printf("Owner:        %v\n", g["ownerId"])
		if ad, ok := g["adminId"]; ok && ad != "" {
			fmt.Printf("Admin:        %v (%v)\n", ad, g["adminType"])
		}
		fmt.Printf("Created By:   %v\n", g["createdBy"])
		fmt.Printf("Created At:   %v\n", g["createdAt"])
		return nil
	},
}

// serverGroupUpdateCmd patches a group's mutable fields. `name` is the
// machine-readable identifier (system-admin-only on the server side);
// displayName and description are owner-editable.
var serverGroupUpdateCmd = &cobra.Command{
	Use:   "update <group-id>",
	Short: "Update a group's name, display name, or description",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{}
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			body["name"] = v
		}
		if cmd.Flags().Changed("display-name") {
			v, _ := cmd.Flags().GetString("display-name")
			body["displayName"] = v
		}
		if cmd.Flags().Changed("description") {
			v, _ := cmd.Flags().GetString("description")
			body["description"] = v
		}
		if len(body) == 0 {
			return errors.New("at least one of --name, --display-name, --description is required")
		}
		_, err := makeGroupAPICall("PATCH", "/api/v1.0/groups/"+args[0], body)
		if err != nil {
			return err
		}
		fmt.Println("Group updated successfully")
		return nil
	},
}

// serverGroupMembersListCmd lists the members of a group. Distinct from
// "group get" (which returns the group record itself, including a member
// summary): this hits the dedicated members endpoint, which is paginated
// server-side and is the right surface for large groups.
var serverGroupMembersListCmd = &cobra.Command{
	Use:   "list-members <group-id>",
	Short: "List members of a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/groups/"+args[0]+"/members", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var members []map[string]interface{}
		if err := json.Unmarshal(respBody, &members); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(members) == 0 {
			fmt.Println("No members in this group")
			return nil
		}
		fmt.Printf("Found %d member(s):\n\n", len(members))
		for _, m := range members {
			fmt.Printf("User ID:    %v\n", m["userId"])
			if u, ok := m["user"].(map[string]interface{}); ok {
				if uname, ok := u["username"]; ok {
					fmt.Printf("Username:   %v\n", uname)
				}
				if dn, ok := u["displayName"]; ok && dn != "" {
					fmt.Printf("Name:       %v\n", dn)
				}
			}
			fmt.Printf("Added By:   %v\n", m["createdBy"])
			fmt.Printf("Added At:   %v\n", m["createdAt"])
			fmt.Println()
		}
		return nil
	},
}

// ===== User commands =====

var serverUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users on a Pelican server",
	Long: `Manage users on a Pelican server (origin, cache, registry, or
director — wherever users and groups are configured). Requires authentication.`,
}

var serverUserListCmd = &cobra.Command{
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

var serverUserCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long: `Create a new user. There are three onboarding flavors — pick the one
that matches what you know about the user:

  1. Local user (username + password login):
       pelican server user create --username alice [--display-name "Alice"]
       pelican server user invite-password <user-id>   # hand the link to the user
     The admin never sees or chooses the password — the user picks one when
     they redeem the link.

  2. OIDC user, identity already known (pre-bind):
       pelican server user create --username alice \
           --sub abc-123 --issuer https://oidc.example/
     The next OIDC login matching (sub, issuer) is linked to this account.
     Use this when you have the user's IdP-issued subject claim in advance.

  3. OIDC user, identity NOT yet known (onboarding link):
       pelican server user invite-onboard
     Issues a single-use link the user follows AFTER logging in via OIDC.
     Their first OIDC identity claims the new account.

Admins do NOT set passwords directly in any flow.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		sub, _ := cmd.Flags().GetString("sub")
		issuer, _ := cmd.Flags().GetString("issuer")
		displayName, _ := cmd.Flags().GetString("display-name")
		if username == "" {
			return errors.New("--username is required")
		}
		hasOIDC := sub != "" || issuer != ""
		if hasOIDC && (sub == "" || issuer == "") {
			return errors.New("--sub and --issuer must be supplied together for an external user")
		}
		body := map[string]string{
			"username": username,
		}
		if displayName != "" {
			body["displayName"] = displayName
		}
		if hasOIDC {
			body["sub"] = sub
			body["issuer"] = issuer
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
		fmt.Printf("User created successfully!\nID:       %v\nUsername: %v\n", u["id"], username)
		if !hasOIDC {
			fmt.Printf("\nGenerate a password-set invite for this user with:\n  pelican server user invite-password %v\n", u["id"])
		}
		return nil
	},
}

// serverUserInvitePasswordCmd mints a single-use, time-bounded password-set
// invite link for a user. The admin then gives the link to the user, who
// follows it to choose their own password — the admin never sees it.
var serverUserInvitePasswordCmd = &cobra.Command{
	Use:   "invite-password <user-id>",
	Short: "Generate a single-use password-set invite link for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{}
		if cmd.Flags().Changed("expires-in") {
			v, _ := cmd.Flags().GetString("expires-in")
			body["expiresIn"] = v
		}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/users/"+args[0]+"/password-invite", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var r map[string]interface{}
		if err := json.Unmarshal(respBody, &r); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		fmt.Println("Password-set invite created.")
		fmt.Printf("Token:      %v\n", r["inviteToken"])
		fmt.Printf("Token ID:   %v   (public — safe to mention in chat/audit logs)\n", r["tokenPrefix"])
		fmt.Printf("Expires at: %v\n", r["expiresAt"])
		serverURL, _ := getServerWebURL()
		if serverURL != "" {
			fmt.Printf("\nGive the user this URL:\n  %s/view/invite/redeem?token=%v\n", serverURL, r["inviteToken"])
		}
		fmt.Println("\nThe token is shown only once. The admin never sees the password the user chooses.")
		return nil
	},
}

// serverUserInviteOnboardCmd mints a generic onboarding invite — no
// pre-bound user, no password set. The first OIDC login that redeems the
// link claims the new account. Use this when the admin wants to invite
// someone whose IdP subject claim is not known in advance (i.e. the
// admin can't use 'user create --sub --issuer' for a pre-bind).
//
// Distinct from 'invite-password' on purpose: this flow never produces
// a password, doesn't even create the user record up front, and is
// completely OIDC-driven. The caller's first OIDC login is the binding
// event.
var serverUserInviteOnboardCmd = &cobra.Command{
	Use:   "invite-onboard",
	Short: "Generate a no-password onboarding invite (OIDC-only)",
	Long: `Mint a single-use onboarding invite link. Hand the resulting URL
to the user; when they follow it AFTER logging in via OIDC, an account is
created for them and bound to the OIDC identity they used.

Use this when you do NOT know the user's OIDC subject claim in advance.
If you DO know it, prefer 'pelican server user create --sub --issuer'
so the account is pre-bound and the user can be added to groups before
their first login.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]interface{}{
			"isSingleUse": true,
		}
		if cmd.Flags().Changed("expires-in") {
			v, _ := cmd.Flags().GetString("expires-in")
			body["expiresIn"] = v
		}
		respBody, err := makeGroupAPICall("POST", "/api/v1.0/invites/onboarding", body)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var r map[string]interface{}
		if err := json.Unmarshal(respBody, &r); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		fmt.Println("OIDC onboarding invite created.")
		fmt.Printf("Token:      %v\n", r["inviteToken"])
		fmt.Printf("Token ID:   %v   (public — safe to mention in chat/audit logs)\n", r["tokenPrefix"])
		fmt.Printf("Expires at: %v\n", r["expiresAt"])
		serverURL, _ := getServerWebURL()
		if serverURL != "" {
			fmt.Printf("\nGive the user this URL:\n  %s/view/invite/redeem?token=%v\n", serverURL, r["inviteToken"])
		}
		fmt.Println("\nThe user must log in via OIDC before redeeming. Their first OIDC")
		fmt.Println("identity will claim the new account. Token is shown only once.")
		return nil
	},
}

// serverUserGetCmd fetches a single user record by ID. Mirrors the web
// /users/:id surface; useful for admin scripts that need to look up a
// specific user's status/identity without listing the whole table.
var serverUserGetCmd = &cobra.Command{
	Use:   "get <user-id>",
	Short: "Show details of a single user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/users/"+args[0], nil)
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
		fmt.Printf("ID:            %v\n", u["id"])
		fmt.Printf("Username:      %v\n", u["username"])
		if dn, ok := u["displayName"]; ok && dn != "" {
			fmt.Printf("Display Name:  %v\n", dn)
		}
		fmt.Printf("Status:        %v\n", u["status"])
		fmt.Printf("Sub:           %v\n", u["sub"])
		fmt.Printf("Issuer:        %v\n", u["issuer"])
		if hp, ok := u["hasPassword"]; ok {
			fmt.Printf("Has Password:  %v\n", hp)
		}
		fmt.Printf("Created By:    %v\n", u["createdBy"])
		fmt.Printf("Created At:    %v\n", u["createdAt"])
		if v, ok := u["lastLoginAt"]; ok && v != nil {
			fmt.Printf("Last Login:    %v\n", v)
		}
		return nil
	},
}

// serverUserPasswordInvitesListCmd lists every password-set invite (live
// AND historical, including redeemed/revoked) targeting a single user.
// Mirrors the web admin's "outstanding invites" surface so admins can
// see at a glance whether a user already has a setup link in flight.
var serverUserPasswordInvitesListCmd = &cobra.Command{
	Use:   "list-password-invites <user-id>",
	Short: "List password-set invites issued for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, err := makeGroupAPICall("GET", "/api/v1.0/users/"+args[0]+"/password-invites", nil)
		if err != nil {
			return err
		}
		if outputJSON {
			fmt.Println(string(respBody))
			return nil
		}
		var invites []map[string]interface{}
		if err := json.Unmarshal(respBody, &invites); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		if len(invites) == 0 {
			fmt.Println("No password invites found for this user")
			return nil
		}
		fmt.Printf("Found %d password invite(s):\n\n", len(invites))
		for _, l := range invites {
			fmt.Printf("Link ID:      %v\n", l["id"])
			fmt.Printf("Token ID:     %v\n", l["tokenPrefix"])
			fmt.Printf("Created At:   %v\n", l["createdAt"])
			fmt.Printf("Expires At:   %v\n", l["expiresAt"])
			fmt.Printf("Created By:   %v\n", l["createdBy"])
			if v, ok := l["redeemedAt"]; ok && v != nil {
				fmt.Printf("Redeemed At:  %v\n", v)
			}
			if v, ok := l["revoked"]; ok && v == true {
				fmt.Printf("Status:       revoked\n")
			} else if v, ok := l["redeemedAt"]; ok && v != nil {
				fmt.Printf("Status:       redeemed\n")
			} else {
				fmt.Printf("Status:       active\n")
			}
			fmt.Println()
		}
		return nil
	},
}

var serverUserDeleteCmd = &cobra.Command{
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

// serverUserClearPasswordCmd disables local-password login for a user
// without revealing or replacing the password (admins never learn it).
// To re-enable, mint a fresh password-set invite via 'invite-password'.
var serverUserClearPasswordCmd = &cobra.Command{
	Use:   "clear-password <user-id>",
	Short: "Disable local-password login for a user (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := makeGroupAPICall("DELETE", "/api/v1.0/users/"+args[0]+"/password", nil)
		if err != nil {
			return err
		}
		fmt.Println("Local password cleared (account can no longer log in via password)")
		return nil
	},
}

var serverUserStatusCmd = &cobra.Command{
	Use:   "set-status <user-id>",
	Short: "Update user status (active|inactive)",
	Long: `Set a user's account status to 'active' or 'inactive'.
Display name is a separate, human-only field; use 'pelican server user update'
to change it (or have the user edit it themselves under their profile).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("status") {
			return errors.New("--status is required")
		}
		v, _ := cmd.Flags().GetString("status")
		body := map[string]interface{}{"status": v}
		_, err := makeGroupAPICall("PUT", "/api/v1.0/users/"+args[0]+"/status", body)
		if err != nil {
			return err
		}
		fmt.Println("User status updated successfully")
		return nil
	},
}

// serverUserUpdateCmd carries admin-controlled, non-status field edits on a
// user record (username and display name). Sub/issuer changes are not done
// here — those go through 'pelican server user identity'.
var serverUserUpdateCmd = &cobra.Command{
	Use:   "update <user-id>",
	Short: "Update a user's username or display name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{}
		if cmd.Flags().Changed("username") {
			v, _ := cmd.Flags().GetString("username")
			body["username"] = v
		}
		if cmd.Flags().Changed("display-name") {
			v, _ := cmd.Flags().GetString("display-name")
			body["displayName"] = v
		}
		if len(body) == 0 {
			return errors.New("at least one of --username or --display-name is required")
		}
		_, err := makeGroupAPICall("PATCH", "/api/v1.0/users/"+args[0], body)
		if err != nil {
			return err
		}
		fmt.Println("User updated successfully")
		return nil
	},
}

var serverUserIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage user identities",
}

var serverUserIdentityListCmd = &cobra.Command{
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

var serverUserIdentityAddCmd = &cobra.Command{
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

var serverUserIdentityRemoveCmd = &cobra.Command{
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
	// Group commands
	serverGroupCreateCmd.Flags().String("name", "", "Name of the group (required)")
	serverGroupCreateCmd.Flags().String("description", "", "Description of the group")

	serverGroupUpdateCmd.Flags().String("name", "", "New machine-readable group name (system admin only)")
	serverGroupUpdateCmd.Flags().String("display-name", "", "New human-readable display name")
	serverGroupUpdateCmd.Flags().String("description", "", "New group description")

	serverGroupAddMemberCmd.Flags().String("user-id", "", "User ID to add (required)")
	serverGroupRemoveMemberCmd.Flags().String("user-id", "", "User ID to remove (required)")

	serverGroupSetOwnershipCmd.Flags().String("owner-id", "", "New owner user ID")
	serverGroupSetOwnershipCmd.Flags().String("admin-id", "", "Admin user or group ID")
	serverGroupSetOwnershipCmd.Flags().String("admin-type", "", "Admin type: 'user' or 'group'")

	// Invite commands
	serverGroupInviteCreateCmd.Flags().Bool("single-use", false, "Create a single-use invite link")
	serverGroupInviteCreateCmd.Flags().String("expires-in", "", "Expiration duration (e.g. '168h', '24h')")

	// User commands
	serverUserCreateCmd.Flags().String("username", "", "Username (required)")
	serverUserCreateCmd.Flags().String("sub", "", "OIDC subject claim (external/OIDC users only)")
	serverUserCreateCmd.Flags().String("issuer", "", "OIDC issuer URL (external/OIDC users only)")
	serverUserCreateCmd.Flags().String("display-name", "", "Display name")

	serverUserInvitePasswordCmd.Flags().String("expires-in", "", "Optional expiration duration (e.g. '24h'); defaults to Server.GroupInviteLinkExpiration")
	serverUserInviteOnboardCmd.Flags().String("expires-in", "", "Optional expiration duration (e.g. '24h'); defaults to Server.GroupInviteLinkExpiration")

	serverUserStatusCmd.Flags().String("status", "", "Status: 'active' or 'inactive'")

	serverUserUpdateCmd.Flags().String("username", "", "New username (admin-controlled authorization handle)")
	serverUserUpdateCmd.Flags().String("display-name", "", "New display name (human label)")

	serverUserIdentityAddCmd.Flags().String("sub", "", "OIDC subject claim (required)")
	serverUserIdentityAddCmd.Flags().String("issuer", "", "OIDC issuer URL (required)")

	// Register group subcommands
	serverGroupCmd.AddCommand(serverGroupListCmd)
	serverGroupCmd.AddCommand(serverGroupGetCmd)
	serverGroupCmd.AddCommand(serverGroupCreateCmd)
	serverGroupCmd.AddCommand(serverGroupUpdateCmd)
	serverGroupCmd.AddCommand(serverGroupDeleteCmd)
	serverGroupCmd.AddCommand(serverGroupAddMemberCmd)
	serverGroupCmd.AddCommand(serverGroupRemoveMemberCmd)
	serverGroupCmd.AddCommand(serverGroupMembersListCmd)
	serverGroupCmd.AddCommand(serverGroupSetOwnershipCmd)
	serverGroupCmd.AddCommand(serverGroupInviteCmd)

	serverGroupInviteCmd.AddCommand(serverGroupInviteCreateCmd)
	serverGroupInviteCmd.AddCommand(serverGroupInviteListCmd)
	serverGroupInviteCmd.AddCommand(serverGroupInviteRevokeCmd)
	serverGroupInviteCmd.AddCommand(serverGroupInviteRedeemCmd)

	// Register user subcommands
	serverUserCmd.AddCommand(serverUserListCmd)
	serverUserCmd.AddCommand(serverUserGetCmd)
	serverUserCmd.AddCommand(serverUserCreateCmd)
	serverUserCmd.AddCommand(serverUserUpdateCmd)
	serverUserCmd.AddCommand(serverUserDeleteCmd)
	serverUserCmd.AddCommand(serverUserInvitePasswordCmd)
	serverUserCmd.AddCommand(serverUserInviteOnboardCmd)
	serverUserCmd.AddCommand(serverUserPasswordInvitesListCmd)
	serverUserCmd.AddCommand(serverUserClearPasswordCmd)
	serverUserCmd.AddCommand(serverUserStatusCmd)
	serverUserCmd.AddCommand(serverUserIdentityCmd)

	serverUserIdentityCmd.AddCommand(serverUserIdentityListCmd)
	serverUserIdentityCmd.AddCommand(serverUserIdentityAddCmd)
	serverUserIdentityCmd.AddCommand(serverUserIdentityRemoveCmd)

	// Per the user/group design contract, users and groups can live on
	// any Pelican component (origin, cache, registry, director). Attach
	// the `user` and `group` subcommand trees to the component-agnostic
	// `pelican server` parent rather than `pelican origin`.
	serverCmd.AddCommand(serverGroupCmd)
	serverCmd.AddCommand(serverUserCmd)
}
