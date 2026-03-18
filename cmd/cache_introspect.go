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
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	cacheIntrospectCmd = &cobra.Command{
		Use:   "introspect",
		Short: "Introspect the local cache database",
		Long: `Inspect the contents of the local persistent cache.

These commands allow administrators to examine cached objects, their metadata,
and verify data integrity without starting the full cache server.

The cache directory is read from LocalCache.BaseDir configuration.`,
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
		Args: cobra.ExactArgs(1),
		RunE: runCacheIntrospectEtags,
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
		Args: cobra.MaximumNArgs(1),
		RunE: runCacheIntrospectMetadata,
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
		Args: cobra.MaximumNArgs(1),
		RunE: runCacheIntrospectVerify,
	}

	cacheIntrospectListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all cached objects",
		Long: `List all objects currently in the cache.

Warning: For large caches, this may return many results. Use --limit
to restrict the number of entries returned.

Example:
  pelican cache introspect list --limit=100`,
		RunE: runCacheIntrospectList,
	}

	// Flags
	introspectEtag     string
	introspectInstance string
	introspectJSON     bool
	introspectLimit    int
	introspectCacheDir string
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

	// Metadata/verify specific flags
	cacheIntrospectMetadataCmd.Flags().StringVar(&introspectEtag, "etag", "", "Specify ETag of the version to inspect")
	cacheIntrospectMetadataCmd.Flags().StringVar(&introspectInstance, "instance", "", "Specify instance hash directly")
	cacheIntrospectVerifyCmd.Flags().StringVar(&introspectEtag, "etag", "", "Specify ETag of the version to verify")
	cacheIntrospectVerifyCmd.Flags().StringVar(&introspectInstance, "instance", "", "Specify instance hash directly")

	// List specific flags
	cacheIntrospectListCmd.Flags().IntVar(&introspectLimit, "limit", 100, "Maximum number of objects to list")
}

// getCacheDir returns the cache directory, either from flag or config
func getCacheDir() (string, error) {
	if introspectCacheDir != "" {
		return introspectCacheDir, nil
	}

	// Initialize config to read LocalCache.DataLocation
	if err := config.InitClient(); err != nil {
		return "", errors.Wrap(err, "failed to initialize config")
	}

	cacheDir := param.LocalCache_DataLocation.GetString()
	if cacheDir == "" {
		return "", errors.New("LocalCache.DataLocation is not configured. Use --cache-dir to specify the cache directory")
	}

	return cacheDir, nil
}

// openIntrospectAPI opens the cache database for introspection
func openIntrospectAPI() (*local_cache.IntrospectAPIOpen, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	// Check directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return nil, errors.Errorf("cache directory does not exist: %s", cacheDir)
	}

	// Initialize issuer keys for database decryption
	// The cache's encryption keys are derived from issuer keys
	ctx := context.Background()
	if err := config.InitServer(ctx, server_structs.CacheType); err != nil {
		return nil, errors.Wrap(err, "failed to initialize server config (needed for encryption keys)")
	}

	return local_cache.NewIntrospectAPI(cacheDir)
}

func runCacheIntrospectEtags(cmd *cobra.Command, args []string) error {
	objectURL := args[0]

	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	instances, err := api.ListObjectInstances(objectURL)
	if err != nil {
		return errors.Wrap(err, "failed to list object instances")
	}

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
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	var details *local_cache.ObjectDetails

	if introspectInstance != "" {
		// Look up by instance hash
		details, err = api.GetObjectDetails(introspectInstance)
	} else if len(args) > 0 {
		// Look up by URL (and optional ETag)
		details, err = api.GetObjectDetailsByURL(args[0], introspectEtag)
	} else {
		return errors.New("either <object-url> or --instance is required")
	}

	if err != nil {
		return errors.Wrap(err, "failed to get object details")
	}

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
	api, err := openIntrospectAPI()
	if err != nil {
		return err
	}
	defer api.Close()

	instances, err := api.ListAllObjects(introspectLimit)
	if err != nil {
		return errors.Wrap(err, "failed to list cached objects")
	}

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
