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
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/mcp"
)

var (
	mcpCmd = &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol (MCP) server for Pelican client",
		Long: `Start a Model Context Protocol (MCP) server that exposes Pelican client
functionality to AI assistants and other MCP clients.

The MCP server allows AI assistants to download files, get file information,
and list directories using the Pelican client. It communicates via JSON-RPC
over stdin/stdout.

Example usage with an MCP client:
  pelican mcp serve

Tools provided:
  - pelican_download: Download files from Pelican URLs
  - pelican_stat: Get metadata about Pelican objects
  - pelican_list: List contents of Pelican directories`,
	}

	mcpServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server",
		Long: `Start the Model Context Protocol server that exposes Pelican client
functionality to AI assistants.

The server reads JSON-RPC requests from stdin and writes responses to stdout.
It should be launched by an MCP client (such as an AI assistant with MCP support).`,
		RunE: runMCPServe,
	}
)

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Set up logging to stderr so it doesn't interfere with JSON-RPC on stdout
	log.SetOutput(os.Stderr)

	// Create and run the MCP server
	server := mcp.NewServer(ctx, os.Stdin, os.Stdout)
	if err := server.Run(); err != nil {
		log.Errorf("MCP server error: %v", err)
		return err
	}

	return nil
}
