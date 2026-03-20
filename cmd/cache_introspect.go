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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
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
		Use:   "list [pattern]",
		Short: "List cached objects",
		Long: `List objects currently in the cache, optionally filtered by a glob pattern.

The pattern is matched against the source URL of each cached object.
Standard glob syntax is supported: * matches any sequence of non-/
characters, ** matches everything including slashes, and ? matches
a single character.

If no pattern is given, all objects are listed.

Warning: For large caches, this may return many results. Use --limit
to restrict the number of entries returned.

Examples:
  pelican cache introspect list
  pelican cache introspect list '/chtc/staging/**'
  pelican cache introspect list '*.bin'
  pelican cache introspect list --limit=50 'pelican://origin.example.com/data/*'`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runCacheIntrospectList,
		SilenceUsage: true,
	}

	cacheIntrospectStatsCmd = &cobra.Command{
		Use:   "stats",
		Short: "Show cache size statistics",
		Long: `Display aggregate size statistics about the cache.

Shows total inline bytes stored in BadgerDB, total number of metadata
entries, total bytes claimed by metadata, and per-storage-directory
breakdown. This is a cheap operation that only scans metadata.

Example:
  pelican cache introspect stats
  pelican cache introspect stats --json`,
		RunE:         runCacheIntrospectStats,
		SilenceUsage: true,
	}

	cacheIntrospectDiskUsageCmd = &cobra.Command{
		Use:   "disk-usage",
		Short: "Compute actual disk usage by walking storage directories",
		Long: `Walk all storage directories and sum the actual file sizes on disk.

This is an EXPENSIVE operation that stats every file in the cache's
storage directories. For large caches this may take significant time.

Example:
  pelican cache introspect disk-usage
  pelican cache introspect disk-usage --json`,
		RunE:         runCacheIntrospectDiskUsage,
		SilenceUsage: true,
	}

	cacheIntrospectConsistencyCmd = &cobra.Command{
		Use:   "consistency",
		Short: "Run a cache consistency check",
		Long: `Trigger a consistency check between the database and disk.

By default runs both a metadata scan (cross-references DB entries with
disk files to find orphans) and a data scan (reads and verifies checksums).
Use --metadata-only or --data-only to run only one scan type.

The data scan is expensive as it reads and checksums every cached file.

Example:
  pelican cache introspect consistency
  pelican cache introspect consistency --metadata-only
  pelican cache introspect consistency --data-only
  pelican cache introspect consistency --json`,
		RunE:         runCacheIntrospectConsistency,
		SilenceUsage: true,
	}

	// Flags
	introspectEtag         string
	introspectInstance     string
	introspectJSON         bool
	introspectLimit        int
	introspectCacheDir     string
	introspectOffline      bool
	introspectToken        string
	introspectMetadataOnly bool
	introspectDataOnly     bool
)

func init() {
	// Add introspect command to cache
	cacheCmd.AddCommand(cacheIntrospectCmd)

	// Add subcommands
	cacheIntrospectCmd.AddCommand(cacheIntrospectEtagsCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectMetadataCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectVerifyCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectListCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectStatsCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectDiskUsageCmd)
	cacheIntrospectCmd.AddCommand(cacheIntrospectConsistencyCmd)

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

	// Consistency specific flags
	cacheIntrospectConsistencyCmd.Flags().BoolVar(&introspectMetadataOnly, "metadata-only", false, "Run only the metadata scan (skip data scan)")
	cacheIntrospectConsistencyCmd.Flags().BoolVar(&introspectDataOnly, "data-only", false, "Run only the data scan (skip metadata scan)")
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
//
//	<Cache.StorageLocation>/persistent-cache
//
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
	fmt.Fprintf(w, "ETAG\tSIZE\tLAST ACCESSED\tEXPIRES\tCOMPLETED\tLATEST\tSTORAGE\n")
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
		expires := ""
		if !inst.Expires.IsZero() {
			expires = inst.Expires.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			truncateETag(inst.ETag, 20), inst.ContentLength, lastAccessed, expires, completed, latest, storage)
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
	if details.ETag != "" {
		fmt.Printf("ETag:          %s\n", details.ETag)
	} else {
		fmt.Printf("ETag:          (none)\n")
	}
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
	pattern := ""
	if len(args) > 0 {
		pattern = args[0]
	}

	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{"limit": {fmt.Sprintf("%d", introspectLimit)}}
		if pattern != "" {
			query.Set("pattern", pattern)
		}
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

	instances, err := api.ListAllObjects(introspectLimit, pattern)
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

func runCacheIntrospectStats(cmd *cobra.Command, args []string) error {
	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		body, err := introspectHTTPGet(serverURL, "/api/v1.0/cache/introspect/stats", nil)
		if err != nil {
			return errors.Wrap(err, "online introspection failed")
		}
		var stats local_cache.CacheStats
		if err := json.Unmarshal(body, &stats); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printStats(&stats)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	stats, err := api.GetCacheStats()
	if err != nil {
		return errors.Wrap(err, "failed to get cache stats")
	}

	return printStats(stats)
}

func printStats(stats *local_cache.CacheStats) error {
	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(stats)
	}

	fmt.Printf("Cache Size Statistics\n")
	fmt.Printf("=====================\n\n")
	fmt.Printf("Total metadata entries:  %d\n", stats.TotalMetadataEntries)
	fmt.Printf("Total bytes (metadata):  %s (%d bytes)\n", utils.HumanBytes(stats.TotalBytesMetadata), stats.TotalBytesMetadata)
	fmt.Printf("Total inline data:       %s (%d bytes)\n", utils.HumanBytes(stats.TotalInlineBytes), stats.TotalInlineBytes)

	if len(stats.StorageBreakdown) > 0 {
		fmt.Printf("\nPer-Storage Directory:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  DIRECTORY\tOBJECTS\tTOTAL BYTES\tINLINE\tON DISK\n")
		for name, ds := range stats.StorageBreakdown {
			if p, ok := stats.DirPaths[ds.StorageID]; ok {
				name = p
			}
			fmt.Fprintf(w, "  %s\t%d\t%s\t%d (%s)\t%d (%s)\n",
				name, ds.ObjectCount, utils.HumanBytes(ds.TotalBytes),
				ds.InlineCount, utils.HumanBytes(ds.InlineBytes),
				ds.OnDiskCount, utils.HumanBytes(ds.OnDiskBytes))
		}
		w.Flush()
	}

	if len(stats.UsageCounters) > 0 {
		// Build reverse lookups for human-readable labels.
		dirName := func(sid uint8) string {
			if p, ok := stats.DirPaths[sid]; ok {
				return p
			}
			return fmt.Sprintf("storage-%d", sid)
		}
		nsName := func(nid uint32) string {
			if n, ok := stats.NamespaceNames[nid]; ok {
				return n
			}
			return fmt.Sprintf("ns%d", nid)
		}

		// Collect lines and find the widest human-bytes string for alignment.
		type usageLine struct {
			label string
			human string
			raw   int64
		}
		lines := make([]usageLine, 0, len(stats.UsageCounters))
		maxHuman := 0
		maxRaw := 0
		for key, val := range stats.UsageCounters {
			// Parse "s<sid>:ns<nid>" back to IDs.
			var sid uint8
			var nid uint32
			if _, err := fmt.Sscanf(key, "s%d:ns%d", &sid, &nid); err == nil {
				key = dirName(sid) + " : " + nsName(nid)
			}
			h := utils.HumanBytes(val)
			r := fmt.Sprintf("%d", val)
			lines = append(lines, usageLine{label: key, human: h, raw: val})
			if len(h) > maxHuman {
				maxHuman = len(h)
			}
			if len(r) > maxRaw {
				maxRaw = len(r)
			}
		}

		fmt.Printf("\nUsage Counters (pre-computed):\n")
		for _, l := range lines {
			fmt.Printf("  %s: %*s (%*d bytes)\n", l.label, maxHuman, l.human, maxRaw, l.raw)
		}
	}

	return nil
}

func runCacheIntrospectDiskUsage(cmd *cobra.Command, args []string) error {
	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		body, err := introspectHTTPPost(serverURL, "/api/v1.0/cache/introspect/disk-usage", nil)
		if err != nil {
			return errors.Wrap(err, "online introspection failed")
		}
		var result local_cache.DiskUsageResult
		if err := json.Unmarshal(body, &result); err != nil {
			return errors.Wrap(err, "failed to parse response")
		}
		return printDiskUsage(&result)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	fmt.Println("Walking storage directories (this may take a while)...")
	result, err := api.GetDiskUsage()
	if err != nil {
		return errors.Wrap(err, "failed to compute disk usage")
	}

	return printDiskUsage(result)
}

func printDiskUsage(result *local_cache.DiskUsageResult) error {
	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Disk Usage (via filesystem walk)\n")
	fmt.Printf("================================\n\n")
	fmt.Printf("Total bytes on disk: %s (%d bytes)\n", utils.HumanBytes(result.TotalBytesOnDisk), result.TotalBytesOnDisk)
	fmt.Printf("Total files:         %d\n", result.TotalFiles)
	fmt.Printf("Scan duration:       %s\n", result.Duration)

	if len(result.Directories) > 0 {
		fmt.Printf("\nPer-Directory:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  DIRECTORY\tFILES\tBYTES USED\tPATH\n")
		for name, ds := range result.Directories {
			fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n",
				name, ds.FileCount, utils.HumanBytes(ds.BytesUsed), ds.Path)
		}
		w.Flush()
	}

	return nil
}

func runOnlineConsistencyCheck(serverURL string, query url.Values) (*local_cache.ConsistencyCheckResult, error) {
	tok, err := getIntrospectToken(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain admin token")
	}

	targetURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid server URL")
	}
	targetURL.Path = "/api/v1.0/cache/introspect/consistency"
	targetURL.RawQuery = query.Encode()

	req, err := http.NewRequest("POST", targetURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{
		Transport: config.GetTransport(),
		// No timeout — the SSE stream keeps the connection alive.
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("server responded with %s (body: %s)", resp.Status, strings.TrimSpace(string(body)))
	}

	// Shared state for decorator closures (updated atomically by SSE loop).
	var metaDBEntries, metaFiles atomic.Int64
	var dataObjects, dataBytes atomic.Int64

	// Set up mpb progress container.
	progress := mpb.New(mpb.WithWidth(64))

	// Bars are created lazily on first matching event.
	var metaBar, dataBar *mpb.Bar

	var result *local_cache.ConsistencyCheckResult

	// Parse SSE stream.
	scanner := bufio.NewScanner(resp.Body)
	var currentEvent string
	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
			continue
		}

		// Empty line = end of SSE event.
		if line == "" && currentEvent != "" && len(dataLines) > 0 {
			payload := strings.Join(dataLines, "\n")
			dataLines = dataLines[:0]

			switch {
			case currentEvent == "metadata_progress" || currentEvent == "metadata_done":
				var evt local_cache.ScanProgressEvent
				if json.Unmarshal([]byte(payload), &evt) == nil {
					if metaBar == nil {
						metaBar = progress.AddBar(100,
							mpb.PrependDecorators(
								decor.Name("Metadata scan ", decor.WCSyncSpaceR),
								decor.Percentage(decor.WCSyncSpace),
							),
							mpb.AppendDecorators(
								decor.Any(func(s decor.Statistics) string {
									return fmt.Sprintf("  %d entries, %d files",
										metaDBEntries.Load(), metaFiles.Load())
								}),
							),
						)
					}
					metaDBEntries.Store(evt.DBEntriesScanned)
					metaFiles.Store(evt.FilesScanned)
					metaBar.SetCurrent(int64(evt.PercentComplete))
					if currentEvent == "metadata_done" {
						metaBar.SetCurrent(100)
						metaBar.Abort(true)
					}
				}

			case currentEvent == "data_progress" || currentEvent == "data_done":
				var evt local_cache.ScanProgressEvent
				if json.Unmarshal([]byte(payload), &evt) == nil {
					if dataBar == nil {
						dataBar = progress.AddBar(100,
							mpb.PrependDecorators(
								decor.Name("Data scan     ", decor.WCSyncSpaceR),
								decor.Percentage(decor.WCSyncSpace),
							),
							mpb.AppendDecorators(
								decor.Any(func(s decor.Statistics) string {
									return fmt.Sprintf("  %d objects, %s verified",
										dataObjects.Load(), utils.HumanBytes(dataBytes.Load()))
								}),
							),
						)
					}
					dataObjects.Store(evt.ObjectsVerified)
					dataBytes.Store(evt.BytesVerified)
					dataBar.SetCurrent(int64(evt.PercentComplete))
					if currentEvent == "data_done" {
						dataBar.SetCurrent(100)
						dataBar.Abort(true)
					}
				}

			case currentEvent == "done":
				var res local_cache.ConsistencyCheckResult
				if json.Unmarshal([]byte(payload), &res) == nil {
					result = &res
				}

			case currentEvent == "error":
				var evt local_cache.ScanProgressEvent
				if json.Unmarshal([]byte(payload), &evt) == nil {
					log.Warnf("Scan error: %s", evt.Message)
				}
			}

			currentEvent = ""
		}
	}

	// Shut down progress bars cleanly.
	progress.Shutdown()

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "error reading SSE stream")
	}

	if result == nil {
		return nil, errors.New("server closed connection without sending final result")
	}

	return result, nil
}

func runCacheIntrospectConsistency(cmd *cobra.Command, args []string) error {
	metadataScan := !introspectDataOnly
	dataScan := !introspectMetadataOnly

	if introspectMetadataOnly && introspectDataOnly {
		return errors.New("--metadata-only and --data-only are mutually exclusive")
	}

	// Try online mode first
	if serverURL := useOnlineMode(); serverURL != "" {
		query := url.Values{}
		query.Set("metadata", fmt.Sprintf("%t", metadataScan))
		query.Set("data", fmt.Sprintf("%t", dataScan))
		result, err := runOnlineConsistencyCheck(serverURL, query)
		if err != nil {
			return errors.Wrap(err, "online consistency check failed")
		}
		return printConsistencyResult(result)
	}

	// Offline mode
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	fmt.Println("Running consistency check (this may take a while)...")
	ctx := context.Background()
	result, err := api.RunConsistencyCheck(ctx, metadataScan, dataScan)
	if err != nil {
		return errors.Wrap(err, "consistency check failed")
	}

	return printConsistencyResult(result)
}

func printConsistencyResult(result *local_cache.ConsistencyCheckResult) error {
	if introspectJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Consistency Check Results\n")
	fmt.Printf("=========================\n\n")
	fmt.Printf("Duration: %s\n\n", result.Duration)

	if result.MetadataScanRan {
		fmt.Printf("Metadata Scan:\n")
		fmt.Printf("  Orphaned files (on disk but not in DB):  %d\n", result.OrphanedFiles)
		fmt.Printf("  Orphaned DB entries (in DB but not on disk): %d\n", result.OrphanedDBEntries)
		fmt.Printf("  Errors: %d\n", result.MetadataScanErrors)
	} else {
		fmt.Printf("Metadata Scan: skipped\n")
	}

	if result.DataScanRan {
		fmt.Printf("\nData Scan:\n")
		fmt.Printf("  Objects verified:     %d\n", result.ObjectsVerified)
		fmt.Printf("  Bytes verified:       %s (%d bytes)\n", utils.HumanBytes(result.BytesVerified), result.BytesVerified)
		fmt.Printf("  Checksum mismatches:  %d\n", result.ChecksumMismatches)
		fmt.Printf("  Errors: %d\n", result.DataScanErrors)
	} else {
		fmt.Printf("\nData Scan: skipped\n")
	}

	if result.Error != "" {
		fmt.Printf("\nErrors encountered: %s\n", result.Error)
	}

	return nil
}

// Helper functions

func truncateETag(etag string, maxLen int) string {
	if etag == "" {
		return "(none)"
	}
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
