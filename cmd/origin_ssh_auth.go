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
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/ssh_posixv2"
)

var sshAuthCmd = &cobra.Command{
	Use:   "ssh-auth",
	Short: "SSH authentication tools for the SSH backend",
	Long: `Tools for SSH backend authentication and testing.

Sub-commands:
  login   - Interactive keyboard-interactive authentication via WebSocket
  test    - Test SSH connection, binary upload, and helper lifecycle
  status  - Check SSH connection status

For the 'login' and 'status' commands, if --origin is not specified, the command
will auto-detect the origin URL from the pelican.addresses file (for local
origins) or from the configuration file.

Example:
  # Interactive login via WebSocket (auto-detects local origin)
  pelican origin ssh-auth login

  # Interactive login to a specific origin
  pelican origin ssh-auth login --origin https://origin.example.com

  # Check the SSH connection status (auto-detects local origin)
  pelican origin ssh-auth status

  # Test SSH connectivity (similar to ssh command)
  pelican origin ssh-auth test storage.example.com
  pelican origin ssh-auth test pelican@storage.example.com
  pelican origin ssh-auth test pelican@storage.example.com -i ~/.ssh/id_rsa
`,
}

var sshAuthLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Interactive keyboard-interactive authentication via WebSocket",
	Long: `Connect to an origin's SSH backend via WebSocket to complete
keyboard-interactive authentication challenges from your terminal.

This is useful when the origin needs to authenticate to a remote SSH server
that requires keyboard-interactive authentication (e.g., 2FA, OTP).

If --origin is not specified, the command will try to determine the origin URL
from the pelican.addresses file (for local origins) or the configuration.

Example:
  pelican origin ssh-auth login
  pelican origin ssh-auth login --origin https://origin.example.com
  pelican origin ssh-auth login --origin https://origin.example.com --host storage.internal
`,
	RunE: runSSHAuthLogin,
}

var sshAuthStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check SSH connection status of an origin",
	Long: `Query the SSH connection status of an origin's SSH backend.

If --origin is not specified, the command will try to determine the origin URL
from the pelican.addresses file (for local origins) or the configuration.

Example:
  pelican origin ssh-auth status
  pelican origin ssh-auth status --origin https://origin.example.com
`,
	RunE: runSSHAuthStatus,
}

var (
	sshAuthOrigin string
	sshAuthHost   string
	sshAuthToken  string
)

func init() {
	// Login command flags
	sshAuthLoginCmd.Flags().StringVar(&sshAuthOrigin, "origin", "", "Origin URL to connect to (auto-detected if not specified)")
	sshAuthLoginCmd.Flags().StringVar(&sshAuthHost, "host", "", "SSH host to authenticate (optional, uses default if not specified)")
	sshAuthLoginCmd.Flags().StringVar(&sshAuthToken, "token", "", "Path to a file containing an admin token (auto-generated if not specified)")

	// Status command uses same origin flag
	sshAuthStatusCmd.Flags().StringVar(&sshAuthOrigin, "origin", "", "Origin URL to check (auto-detected if not specified)")
	sshAuthStatusCmd.Flags().StringVar(&sshAuthToken, "token", "", "Path to a file containing an admin token (auto-generated if not specified)")

	// Add sub-commands
	sshAuthCmd.AddCommand(sshAuthLoginCmd)
	sshAuthCmd.AddCommand(sshAuthStatusCmd)
}

// getOriginURL returns the origin URL from the flag, address file, or config
func getOriginURL() (string, error) {
	// First, check if explicitly provided via flag
	if sshAuthOrigin != "" {
		return sshAuthOrigin, nil
	}

	// Second, try to read from the address file (for local running origins)
	if addrFile, err := config.ReadAddressFile(); err == nil {
		if addrFile.ServerExternalWebURL != "" {
			fmt.Fprintf(os.Stderr, "Using origin URL from address file: %s\n", addrFile.ServerExternalWebURL)
			return addrFile.ServerExternalWebURL, nil
		}
	}

	// Third, try to get from config
	if serverWebUrl := param.Server_ExternalWebUrl.GetString(); serverWebUrl != "" {
		fmt.Fprintf(os.Stderr, "Using origin URL from config: %s\n", serverWebUrl)
		return serverWebUrl, nil
	}

	return "", fmt.Errorf("origin URL not specified and could not be auto-detected; use --origin flag or ensure a local origin is running")
}

func runSSHAuthLogin(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	originURL, err := getOriginURL()
	if err != nil {
		return err
	}

	// Generate or load an admin token for authenticating to the WebSocket endpoint
	tok, err := fetchOrGenerateWebAPIAdminToken(originURL, sshAuthToken)
	if err != nil {
		return fmt.Errorf("failed to obtain admin token: %w", err)
	}

	fmt.Fprintln(os.Stdout, "Starting interactive SSH authentication...")
	fmt.Fprintln(os.Stdout, "Press Ctrl+C to exit.")
	fmt.Fprintln(os.Stdout, "")

	return ssh_posixv2.RunInteractiveAuth(ctx, originURL, sshAuthHost, tok)
}

func runSSHAuthStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	originURL, err := getOriginURL()
	if err != nil {
		return err
	}

	// Generate or load an admin token for authenticating to the status endpoint
	tok, err := fetchOrGenerateWebAPIAdminToken(originURL, sshAuthToken)
	if err != nil {
		return fmt.Errorf("failed to obtain admin token: %w", err)
	}

	status, err := ssh_posixv2.GetConnectionStatus(ctx, originURL, tok)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	// Pretty print the status
	output, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format status: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
