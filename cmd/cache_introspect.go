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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	cacheIntrospectCmd = &cobra.Command{
		Use:   "introspect",
		Short: "Introspect the cache's persistent database",
		Long: `Inspect the contents of the cache server's persistent cache.

These commands allow administrators to examine cached objects, their metadata,
and verify data integrity. If the cache server is running, commands connect
to its API automatically; otherwise they fall back to direct database access.

The cache directory is derived from Cache.StorageLocation configuration.`,
		SilenceUsage: true,
	}

	cacheIntrospectEtagsCmd = &cobra.Command{
		Use:   "etags <object-url>",
		Short: "List all cached ETags for an object",
		Long: `List all cached versions (ETags) of a specific object.

The object URL should be a pelican:// or osdf:// URL, or a bare path
if the federation context is known.

Example:
  pelican cache introspect etags pelican://my-federation/data/file.dat
  pelican cache introspect etags /data/file.dat`,
		Args:         cobra.ExactArgs(1),
		RunE:         runCacheIntrospectEtags,
		SilenceUsage: true,
	}

	cacheIntrospectMetadataCmd = &cobra.Command{
		Use:   "metadata <object-url>",
		Short: "Show detailed metadata for a cached object",
		Long: `Display detailed metadata for a cached object instance.

By default shows the latest cached version. Use --etag to specify
a particular version, or --instance to specify by instance hash.

Example:
  pelican cache introspect metadata pelican://my-federation/data/file.dat
  pelican cache introspect metadata /data/file.dat --etag="abc123"
  pelican cache introspect metadata --instance=<hash>`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runCacheIntrospectMetadata,
		SilenceUsage: true,
	}

	cacheIntrospectVerifyCmd = &cobra.Command{
		Use:   "verify <object-url>",
		Short: "Verify checksum of a cached object",
		Long: `Trigger checksum verification for a cached object.

This reads the entire object from disk, decrypts it, and verifies
that stored checksums (if any) match the actual data.

Example:
  pelican cache introspect verify pelican://my-federation/data/file.dat
  pelican cache introspect verify /data/file.dat --etag="abc123"`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runCacheIntrospectVerify,
		SilenceUsage: true,
	}

	cacheIntrospectListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all cached objects",
		Long: `List all objects currently in the cache.

Warning: For large caches, this may return many results. Use --limit
to restrict the number of entries returned.

Example:
  pelican cache introspect list --limit=100`,
		RunE:         runCacheIntrospectList,
		SilenceUsage: true,
	}

	// Flags
	introspectEtag     string
	introspectInstance string
	introspectJSON     bool
	introspectLimit    int
	introspectCacheDir string
	introspectOffline  bool
	introspectToken    string
)

func init() {
	// Add introspect command to cache
	cacheCmd.AddCommand(cacheIntrospectCmd)

	// Add subcommands
	cacheIntrospectCmd.AddCommand(cacheIntrospectEtagsCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectMetadataCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectVerifyCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectListCmd)

	// Common flags
	cacheIntrospectCmd.PersistentFlags().BoolVar(&introspectJSON, "json", false, "Output in JSON format")
	cacheIntrospectCmd.PersistentFlags().StringVar(&introspectCacheDir, "cache-dir", "", "Override cache directory (default: from config)")
	cacheIntrospectCmd.PersistentFlags().BoolVar(&introspectOffline, "offline", false, "Force offline mode (direct database access). By default, if the cache is running, queries go to the live service.")
	cacheIntrospectCmd.PersistentFlags().StringVarP(&introspectToken, "token", "t", "", "Path to admin token file (online mode only; auto-generated if not provided)")

	// Metadata/verify specific flags
	cacheIntrospectMetadataCmd.Flags().StringVar(&introspectEtag, "etag", "", "Specify ETag of the version to inspect")
	cacheIntrospectMetadataCmd.Flags().StringVar(&introspectInstance, "instance", "", "Specify instance hash directly")
	cacheIntrospectVerifyCmd.Flags().StringVar(&introspectEtag, "etag", "", "Specify ETag of the version to verify")
	cacheIntrospectVerifyCmd.Flags().StringVar(&introspectInstance, "instance", "", "Specify instance hash directly")

	// List specific flags
	cacheIntrospectListCmd.Flags().IntVar(&introspectLimit, "limit", 100, "Maximum number of objects to list")
}

// initIntrospectConfig initializes server configuration needed by both
// online and offline introspection modes.  It is safe to call multiple
// times (idempotent via config internals).
var introspectConfigDone bool

func initIntrospectConfig() error {
	if introspectConfigDone {
		return nil
	}
	ctx := context.Background()
	if err := config.InitServer(ctx, server_structs.CacheType); err != nil {
		return errors.Wrap(err, "failed to initialize cache server config")
	}
	introspectConfigDone = true
	return nil
}

// getCacheDir returns the persistent-cache base directory.
// The cache server stores its persistent cache under
//    <Cache.StorageLocation>/persistent-cache
// which is where the BadgerDB "db" subdirectory lives.
func getCacheDir() (string, error) {
	if introspectCacheDir != "" {
		return introspectCacheDir, nil
	}

	if err := initIntrospectConfig(); err != nil {
		return "", err
	}

	storageLocation := param.Cache_StorageLocation.GetString()
	if storageLocation == "" {
		return "", errors.New("Cache.StorageLocation is not configured. Use --cache-dir to specify the cache directory")
	}

	return filepath.Join(storageLocation, "persistent-cache"), nil
}

// discoverServerURL attempts to find the running cache's web URL from the
// address file.  Returns empty string if the cache is not running or the
// address file cannot be read.
func discoverServerURL() string {
	addrFile, err := config.ReadAddressFile()
	if err != nil {
		log.Debugln("Could not read address file:", err)
		return ""
	}
	serverURL := addrFile.ServerExternalWebURL
	if serverURL == "" {
		log.Debugln("Address file found but ServerExternalWebURL is empty")
	}
	return serverURL
}

// getIntrospectToken returns a bearer token for the introspection API.
// If --token was provided it reads from that file; otherwise it generates
// a short-lived admin token using the local issuer private key.
func getIntrospectToken(serverURL string) (string, error) {
	return fetchOrGenerateWebAPIAdminToken(serverURL, introspectToken)
}

// introspectHTTPGet does an authenticated GET against the running service.
func introspectHTTPGet(serverURL, apiPath string, query url.Values) ([]byte, error) {
	tok, err := getIntrospectToken(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain admin token")
	}

	targetURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid server URL")
	}
	targetURL.Path = apiPath
	targetURL.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	return handleAdminApiResponse(resp)
}

// introspectHTTPPost does an authenticated POST against the running service.
func introspectHTTPPost(serverURL, apiPath string, query url.Values) ([]byte, error) {
	tok, err := getIntrospectToken(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain admin token")
	}

	targetURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid server URL")
	}
	targetURL.Path = apiPath
	targetURL.RawQuery = query.Encode()

	req, err := http.NewRequest("POST", targetURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response")
	}
	if resp.StatusCode >= 300 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, errors.Errorf("server error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, errors.Errorf("server error: %s", resp.Status)
	}
	return body, nil
}

// useOnlineMode returns the server URL if the cache is running and we should
// use online mode, or empty string if we should use offline/direct mode.
func useOnlineMode() string {
	if introspectOffline {
		log.Debugln("Online mode disabled by --offline flag")
		return ""
	}
	// InitServer populates the runtime dir and server config needed for
	// ReadAddressFile.  This is the same config offline mode needs, so
	// we initialize it once.
	if err := initIntrospectConfig(); err != nil {
		log.Debugln("Server config init failed, falling back to offline:", err)
		return ""
	}
	return discoverServerURL()
}

// openIntrospectAPI opens the cache database for introspection (offline mode)
func openIntrospectAPI() (*local_cache.IntrospectAPIOpen, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	// Check directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return nil, errors.Errorf("cache directory does not exist: %s", cacheDir)
	}

	log.Debugln("Opening cache database at", cacheDir)
	return local_cache.NewIntrospectAPI(cacheDir)
}

func runCacheIntrospectEtags(cmd *cobra.Command, args []string) error {
	objectURL := args[0]

	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{"url": {objectURL}}
		body, err := introspectHTTPGet(serverURL, "/api/v1.0/cache/introspect/etags", query)
		if err != nil {
			return errors.Wrap(err, "online introspection failed")
		}
		var instances []local_cache.ObjectInstance
		if err := json.Unmarshal(body, &instances); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printEtags(instances)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	instances, err := api.ListObjectInstances(objectURL)
	if err != nil {
		return errors.Wrap(err, "failed to list object instances")
	}

	return printEtags(instances)
}

func printEtags(instances []local_cache.ObjectInstance) error {
	if len(instances) == 0 {
		fmt.Println("No cached versions found for this object.")
		return nil
	}

	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(instances)
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ETAG\tSIZE\tLAST ACCESSED\tCOMPLETED\tLATEST\tSTORAGE\n")
	for _, inst := range instances {
		storage := "disk"
		if inst.IsInline {
			storage = "inline"
		}
		latest := ""
		if inst.IsLatest {
			latest = "*"
		}
		completed := ""
		if !inst.Completed.IsZero() {
			completed = inst.Completed.Format(time.RFC3339)
		}
		lastAccessed := ""
		if !inst.LastAccessed.IsZero() {
			lastAccessed = inst.LastAccessed.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
			truncateETag(inst.ETag, 20), inst.ContentLength, lastAccessed, completed, latest, storage)
	}
	w.Flush()

	return nil
}

func runCacheIntrospectMetadata(cmd *cobra.Command, args []string) error {
	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{}
		if introspectInstance != "" {
			query.Set("instance", introspectInstance)
		} else if len(args) > 0 {
			query.Set("url", args[0])
			if introspectEtag != "" {
				query.Set("etag", introspectEtag)
			}
		} else {
			return errors.New("either <object-url> or --instance is required")
		}
		body, err := introspectHTTPGet(serverURL, "/api/v1.0/cache/introspect/metadata", query)
		if err != nil {
			return errors.Wrap(err, "online introspection failed")
		}
		var details local_cache.ObjectDetails
		if err := json.Unmarshal(body, &details); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printMetadata(&details)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	var details *local_cache.ObjectDetails

	if introspectInstance != "" {
		details, err = api.GetObjectDetails(introspectInstance)
	} else if len(args) > 0 {
		details, err = api.GetObjectDetailsByURL(args[0], introspectEtag)
	} else {
		return errors.New("either <object-url> or --instance is required")
	}

	if err != nil {
		return errors.Wrap(err, "failed to get object details")
	}

	return printMetadata(details)
}

func printMetadata(details *local_cache.ObjectDetails) error {
	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(details)
	}

	// Human-readable output
	fmt.Printf("Instance Hash: %s\n", details.InstanceHash)
	fmt.Printf("Source URL:    %s\n", details.SourceURL)
	fmt.Printf("ETag:          %s\n", details.ETag)
	fmt.Printf("Content-Length: %d bytes\n", details.ContentLength)
	fmt.Printf("Content-Type:  %s\n", details.ContentType)
	fmt.Printf("Storage:       %s (ID: %d)\n", storageType(details.IsInline), details.StorageID)
	fmt.Printf("Namespace ID:  %d\n", details.NamespaceID)

	if !details.LastModified.IsZero() {
		fmt.Printf("Last-Modified: %s\n", details.LastModified.Format(time.RFC3339))
	}
	if !details.LastValidated.IsZero() {
		fmt.Printf("Last Validated: %s\n", details.LastValidated.Format(time.RFC3339))
	}
	if !details.Completed.IsZero() {
		fmt.Printf("Completed:     %s\n", details.Completed.Format(time.RFC3339))
	}
	if !details.LastAccessed.IsZero() {
		fmt.Printf("Last Accessed: %s\n", details.LastAccessed.Format(time.RFC3339))
	}
	if !details.Expires.IsZero() {
		fmt.Printf("Expires:       %s\n", details.Expires.Format(time.RFC3339))
	}
	if details.CacheControl != "" {
		fmt.Printf("Cache-Control: %s\n", details.CacheControl)
	}
	fmt.Printf("Is Latest:     %t\n", details.IsLatest)

	// Checksums
	if len(details.Checksums) > 0 {
		fmt.Println("\nChecksums:")
		for _, ck := range details.Checksums {
			verified := ""
			if ck.OriginVerified {
				verified = " (origin verified)"
			}
			fmt.Printf("  %s: %s%s\n", ck.Type, ck.Value, verified)
		}
	}

	// Block summary (for disk storage)
	if details.BlockSummary != nil {
		bs := details.BlockSummary
		fmt.Println("\nBlock Status:")
		fmt.Printf("  Total Blocks:      %d\n", bs.TotalBlocks)
		fmt.Printf("  Downloaded Blocks: %d\n", bs.DownloadedBlocks)
		fmt.Printf("  Complete:          %t (%.1f%%)\n", bs.IsComplete, bs.PercentComplete)
		if len(bs.MissingBlocks) > 0 {
			if len(bs.MissingBlocks) <= 10 {
				fmt.Printf("  Missing Blocks:    %v\n", bs.MissingBlocks)
			} else {
				fmt.Printf("  Missing Blocks:    %v... (%d more)\n", bs.MissingBlocks[:10], len(bs.MissingBlocks)-10)
			}
		}
	}

	// Chunk info (for large objects)
	if details.ChunkSummary != nil {
		ci := details.ChunkSummary
		fmt.Println("\nChunking:")
		fmt.Printf("  Chunk Size:     %d bytes\n", ci.ChunkSizeBytes)
		fmt.Printf("  Chunk Count:    %d\n", ci.ChunkCount)
		fmt.Printf("  Chunk Locations: %v\n", ci.ChunkLocations)
	}

	return nil
}

func runCacheIntrospectVerify(cmd *cobra.Command, args []string) error {
	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{}
		if introspectInstance != "" {
			query.Set("instance", introspectInstance)
		} else if len(args) > 0 {
			query.Set("url", args[0])
			if introspectEtag != "" {
				query.Set("etag", introspectEtag)
			}
		} else {
			return errors.New("either <object-url> or --instance is required")
		}
		body, err := introspectHTTPPost(serverURL, "/api/v1.0/cache/introspect/verify", query)
		if err != nil {
			return errors.Wrap(err, "online verification failed")
		}
		var result local_cache.VerificationResult
		if err := json.Unmarshal(body, &result); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printVerification(&result)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	var result *local_cache.VerificationResult

	if introspectInstance != "" {
		result, err = api.VerifyChecksum(introspectInstance)
	} else if len(args) > 0 {
		result, err = api.VerifyChecksumByURL(args[0], introspectEtag)
	} else {
		return errors.New("either <object-url> or --instance is required")
	}

	if err != nil {
		return errors.Wrap(err, "failed to verify checksum")
	}

	return printVerification(result)
}

func printVerification(result *local_cache.VerificationResult) error {
	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Instance: %s\n", result.InstanceHash)
	if result.Error != "" {
		fmt.Printf("Status:   ERROR\n")
		fmt.Printf("Error:    %s\n", result.Error)
		return nil
	}

	if result.Valid {
		fmt.Printf("Status:   VALID\n")
	} else {
		fmt.Printf("Status:   INVALID (checksum mismatch)\n")
	}

	if len(result.ChecksumStatus) > 0 {
		fmt.Println("\nChecksum Details:")
		for _, cs := range result.ChecksumStatus {
			status := "match"
			if !cs.Match {
				status = "MISMATCH"
			}
			fmt.Printf("  %s: %s\n", cs.Type, status)
			fmt.Printf("    Expected: %s\n", cs.Expected)
			if cs.Computed != "" {
				fmt.Printf("    Computed: %s\n", cs.Computed)
			}
		}
	}

	return nil
}

func runCacheIntrospectList(cmd *cobra.Command, args []string) error {
	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{"limit": {fmt.Sprintf("%d", introspectLimit)}}
		body, err := introspectHTTPGet(serverURL, "/api/v1.0/cache/introspect/list", query)
		if err != nil {
			return errors.Wrap(err, "online introspection failed")
		}
		var instances []local_cache.ObjectInstance
		if err := json.Unmarshal(body, &instances); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printList(instances)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	instances, err := api.ListAllObjects(introspectLimit)
	if err != nil {
		return errors.Wrap(err, "failed to list cached objects")
	}

	return printList(instances)
}

func printList(instances []local_cache.ObjectInstance) error {
	if len(instances) == 0 {
		fmt.Println("Cache is empty.")
		return nil
	}

	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(instances)
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "SOURCE URL\tSIZE\tETAG\tSTORAGE\n")
	for _, inst := range instances {
		storage := "disk"
		if inst.IsInline {
			storage = "inline"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n",
			truncateURL(inst.SourceURL, 60), inst.ContentLength, truncateETag(inst.ETag, 12), storage)
	}
	w.Flush()

	if len(instances) == introspectLimit {
		fmt.Printf("\n(Showing first %d entries. Use --limit to see more.)\n", introspectLimit)
	}

	return nil
}

// Helper functions

func truncateETag(etag string, maxLen int) string {
	if len(etag) <= maxLen {
		return etag
	}
	return etag[:maxLen-3] + "..."
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return "..." + url[len(url)-maxLen+3:]
}

func storageType(isInline bool) string {
	if isInline {
		return "inline (BadgerDB)"
	}
	return "disk (encrypted files)"
}
