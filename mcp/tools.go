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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelicanplatform/pelican/client"
)

// Timeout for polling in pelican_auth_complete (should be less than MCP client timeout, typically 60s)
const authCompletionPollTimeout = 45 * time.Second

// getToolsList returns the list of available MCP tools
func getToolsList() []Tool {
	return []Tool{
		{
			Name:        "pelican_download",
			Description: "Download an object from a Pelican URL to a local destination. IMPORTANT: Always ask the user to provide a destination directory/path before calling this tool. Do not assume or guess the destination - the user must explicitly specify where to save the file to avoid permission issues.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL to download from (e.g., pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt)",
					},
					"destination": map[string]interface{}{
						"type":        "string",
						"description": "The local file path where the object should be saved. MUST be provided by the user - do not assume a path. Ask the user: 'Where would you like me to save this file?'",
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

	// First check if token was explicitly provided
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	} else {
		// Check for cached token from previous authentication
		if cachedToken := s.getTokenForURL(source); cachedToken != "" {
			options = append(options, client.WithToken(cachedToken))
		}
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

	// First check if token was explicitly provided
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	} else {
		// Check for cached token from previous authentication
		if cachedToken := s.getTokenForURL(url); cachedToken != "" {
			options = append(options, client.WithToken(cachedToken))
		}
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

	// First check if token was explicitly provided
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	} else {
		// Check for cached token from previous authentication
		if cachedToken := s.getTokenForURL(url); cachedToken != "" {
			options = append(options, client.WithToken(cachedToken))
		}
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

// handleAuth implements the pelican_auth tool for starting authentication to protected namespaces.
// This returns the verification URL immediately without blocking for user authorization.
func (s *Server) handleAuth(args map[string]interface{}) CallToolResult {
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

	// Initiate device auth
	authInfo, err := client.InitiateDeviceAuth(s.ctx, url)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Failed to initiate authentication: %v", err)}},
			IsError: true,
		}
	}

	// Store the pending auth for later completion and clean up expired entries
	s.authMutex.Lock()
	// Clean up expired pending auths to prevent memory leaks
	for u, pa := range s.pendingAuths {
		if pa.authInfo.ExpiresIn > 0 {
			maxAge := time.Duration(pa.authInfo.ExpiresIn) * time.Second
			if time.Since(pa.createdAt) > maxAge {
				delete(s.pendingAuths, u)
			}
		}
	}
	// Store the new pending auth
	s.pendingAuths[url] = &pendingAuth{
		authInfo:  authInfo,
		url:       url,
		createdAt: time.Now(),
	}
	s.authMutex.Unlock()

	// Calculate expiry time from server's ExpiresIn
	expiryMinutes := float64(authInfo.ExpiresIn) / 60

	// Build response message with the verification URL
	var message string
	if authInfo.VerificationURLComplete != "" {
		message = fmt.Sprintf("🔐 **Authentication Required**\n\nTo access the protected namespace at `%s`, please:\n\n1. **Click or visit this URL** to authenticate:\n\n   %s\n\n2. Complete the authorization in your browser\n\n", url, authInfo.VerificationURLComplete)
	} else {
		message = fmt.Sprintf("🔐 **Authentication Required**\n\nTo access the protected namespace at `%s`, please:\n\n1. **Visit this URL:**\n\n   %s\n\n2. **Enter this code:** `%s`\n\n3. Complete the authorization in your browser\n\n", url, authInfo.VerificationURL, authInfo.UserCode)
	}
	message += fmt.Sprintf("⏱️ You have **%.0f minutes** to complete authentication.\n\n", expiryMinutes)
	message += "**IMPORTANT:** After you complete authorization in your browser, tell me and I'll call `pelican_auth_complete` to finish the process."

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// handleAuthComplete implements the pelican_auth_complete tool for completing authentication.
// This polls for the token after the user has authorized in their browser.
func (s *Server) handleAuthComplete(args map[string]interface{}) CallToolResult {
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

	// Get the pending auth
	s.authMutex.Lock()
	pending, exists := s.pendingAuths[url]
	if exists {
		// Remove it from pending regardless of outcome
		delete(s.pendingAuths, url)
	}
	s.authMutex.Unlock()

	if !exists {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("❌ No pending authentication found for `%s`.\n\nPlease start authentication first with `pelican_auth`.", url)}},
			IsError: true,
		}
	}

	// Check if the auth has expired using server's ExpiresIn
	elapsed := time.Since(pending.createdAt)
	maxDuration := time.Duration(pending.authInfo.ExpiresIn) * time.Second
	if maxDuration <= 0 {
		// Default to 1 minute if server didn't specify
		maxDuration = 1 * time.Minute
	}

	if elapsed > maxDuration {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("❌ **Authentication expired.** The authorization request for `%s` has expired.\n\nPlease start a new authentication with `pelican_auth`.", url)}},
			IsError: true,
		}
	}

	// Create a timeout context - use the shorter of remaining time or our poll timeout
	remaining := maxDuration - elapsed
	timeout := authCompletionPollTimeout
	if remaining < timeout {
		timeout = remaining
	}
	authCtx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	// Poll for completion
	token, namespace, err := client.CompleteDeviceAuth(authCtx, url, pending.authInfo)
	if err != nil {
		if authCtx.Err() == context.DeadlineExceeded {
			return CallToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("⏳ **Still waiting for authorization.**\n\nIf you haven't completed authorization yet, please visit the URL and approve the request, then call `pelican_auth_complete` again.\n\nIf you've already authorized, there might be a delay. Please wait a moment and try again.")}},
				IsError: true,
			}
		}
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("❌ **Authorization failed:** %v\n\nPlease start a new authentication with `pelican_auth`.", err)}},
			IsError: true,
		}
	}

	// Cache the token in the MCP server's memory for use by subsequent operations
	if namespace != "" && token != "" {
		s.cacheToken(namespace, token)
	}

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("✅ **Authorization successful!** Token has been cached.\n\nYou can now access protected resources at `%s`.", url)}},
		IsError: false,
	}
}
