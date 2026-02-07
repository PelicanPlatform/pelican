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

package mcp

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelicanplatform/pelican/client"
)

// getToolsList returns the list of available MCP tools
func getToolsList() []Tool {
	return []Tool{
		{
			Name:        "pelican_download",
			Description: "Download an object from a Pelican URL to a local destination. Supports both single files and recursive directory downloads.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL to download from (e.g., pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt)",
					},
					"destination": map[string]interface{}{
						"type":        "string",
						"description": "The local file path where the object should be saved",
					},
					"recursive": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, recursively download directories",
						"default":     false,
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"source", "destination"},
			},
		},
		{
			Name:        "pelican_stat",
			Description: "Get metadata information about a Pelican object, including size, modification time, and checksums.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL to get information about",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "pelican_list",
			Description: "List the contents of a directory in Pelican.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL of the directory to list",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "pelican_auth",
			Description: "Start authentication to a protected Pelican namespace using OAuth device flow. This returns a verification URL that the user must visit to authorize access. IMPORTANT: After the user completes authorization in their browser, call pelican_auth_complete to finish authentication and cache the token.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL of the protected resource to authenticate for (e.g., pelican://osg-htc.org/protected/path)",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "pelican_auth_complete",
			Description: "Complete the OAuth device flow authentication after the user has visited the verification URL. Call this AFTER the user confirms they have completed authorization in their browser. This will poll for the token and cache it for future operations.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The same Pelican URL that was used to start authentication with pelican_auth",
					},
				},
				"required": []string{"url"},
			},
		},
	}
}

// handleDownload implements the pelican_download tool
func (s *Server) handleDownload(args map[string]interface{}) CallToolResult {
	// Ensure Pelican client is initialized
	if err := s.ensureInitialized(); err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: Failed to initialize Pelican client: %v", err)}},
			IsError: true,
		}
	}

	source, ok := args["source"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'source' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	destination, ok := args["destination"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'destination' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	recursive := false
	if r, ok := args["recursive"].(bool); ok {
		recursive = r
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(destination)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error creating destination directory: %v", err)}},
			IsError: true,
		}
	}

	// Perform the download
	transferResults, err := client.DoGet(s.ctx, source, destination, recursive, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Download failed: %v", err)}},
			IsError: true,
		}
	}

	// Build success message
	var totalBytes int64
	for _, result := range transferResults {
		totalBytes += result.TransferredBytes
	}

	message := fmt.Sprintf("Successfully downloaded from %s to %s\n", source, destination)
	message += fmt.Sprintf("Files transferred: %d\n", len(transferResults))
	message += fmt.Sprintf("Total bytes: %d (%.2f MB)\n", totalBytes, float64(totalBytes)/(1024*1024))

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// handleStat implements the pelican_stat tool
func (s *Server) handleStat(args map[string]interface{}) CallToolResult {
	// Ensure Pelican client is initialized
	if err := s.ensureInitialized(); err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: Failed to initialize Pelican client: %v", err)}},
			IsError: true,
		}
	}

	url, ok := args["url"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'url' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// Get file info
	fileInfo, err := client.DoStat(s.ctx, url, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Stat failed: %v", err)}},
			IsError: true,
		}
	}

	// Build response message
	message := fmt.Sprintf("Object information for %s:\n", url)
	message += fmt.Sprintf("Name: %s\n", fileInfo.Name)
	message += fmt.Sprintf("Size: %d bytes (%.2f MB)\n", fileInfo.Size, float64(fileInfo.Size)/(1024*1024))
	message += fmt.Sprintf("Modified: %s\n", fileInfo.ModTime.Format("2006-01-02 15:04:05 MST"))
	message += fmt.Sprintf("Is Collection: %v\n", fileInfo.IsCollection)

	if len(fileInfo.Checksums) > 0 {
		message += "Checksums:\n"
		for algo, checksum := range fileInfo.Checksums {
			message += fmt.Sprintf("  %s: %s\n", algo, checksum)
		}
	}

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// handleList implements the pelican_list tool
func (s *Server) handleList(args map[string]interface{}) CallToolResult {
	// Ensure Pelican client is initialized
	if err := s.ensureInitialized(); err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: Failed to initialize Pelican client: %v", err)}},
			IsError: true,
		}
	}

	url, ok := args["url"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'url' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// List directory contents
	fileInfos, err := client.DoList(s.ctx, url, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("List failed: %v", err)}},
			IsError: true,
		}
	}

	// Build response message
	message := fmt.Sprintf("Contents of %s:\n\n", url)
	for _, info := range fileInfos {
		typeStr := "file"
		if info.IsCollection {
			typeStr = "dir"
		}
		message += fmt.Sprintf("[%s] %s (%d bytes, modified: %s)\n",
			typeStr, info.Name, info.Size, info.ModTime.Format("2006-01-02 15:04:05"))
	}

	if len(fileInfos) == 0 {
		message += "(empty directory)\n"
	}

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}
