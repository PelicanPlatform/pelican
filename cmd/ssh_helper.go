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
	"os"

	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/ssh_posixv2"
)

var sshHelperCmd = &cobra.Command{
	Use:    "ssh-helper",
	Short:  "Run as SSH POSIXv2 helper process (internal)",
	Long:   `This command is used internally by the SSH POSIXv2 backend to run a helper process on a remote host. It reads configuration from stdin and serves WebDAV requests via the broker.`,
	Hidden: true, // Hide from normal help output
	Run:    runSSHHelper,
}

var (
	sshHelperCommand string
)

func init() {
	sshHelperCmd.Flags().StringVar(&sshHelperCommand, "command", "", "Run a specific command (status, shutdown)")
	sshHelperCmd.Flags().Bool("help-full", false, "Show full help for ssh-helper")
}

func runSSHHelper(cmd *cobra.Command, args []string) {
	// Check for help-full flag
	if helpFull, _ := cmd.Flags().GetBool("help-full"); helpFull {
		ssh_posixv2.PrintHelperUsage()
		return
	}

	// Handle specific commands
	if sshHelperCommand != "" {
		switch sshHelperCommand {
		case "status":
			output, err := ssh_posixv2.HelperStatusCmd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(output)
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", sshHelperCommand)
			os.Exit(1)
		}
	}

	// Run the helper process
	ctx := context.Background()
	if err := ssh_posixv2.RunHelper(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Helper error: %v\n", err)
		os.Exit(1)
	}
}
