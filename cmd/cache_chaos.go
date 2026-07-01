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
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/local_cache"
)

var (
	chaosEtag      string
	chaosInstance  string
	chaosJSON      bool
	chaosBlock     uint32
	chaosBytes     int
	chaosChunk     int
	chaosDropBytes int64

	cacheChaosCmd = &cobra.Command{
		Use:   "chaos",
		Short: "Inject corruption into cached objects (fault-injection testing)",
		Long: `Deliberately corrupt cached object data to exercise the cache's
integrity-detection paths (the read-time AES-GCM check and the periodic
data-integrity scan).

This is a destructive testing/"chaos engineering" tool. It operates against a
running cache server through its admin API, so the corruption is applied
in-process (BadgerDB is single-process, so a CLI cannot touch the cache's
database directly while the server holds it open).

The endpoint is only available when the cache server is started with
Cache.EnableChaosAPI set to true.`,
		SilenceUsage: true,
	}

	cacheChaosCorruptCmd = &cobra.Command{
		Use:   "corrupt <object-url>",
		Short: "Flip bytes in a cached object's block",
		Long: `Flip bytes in the on-disk (encrypted) representation of a block so that
its authentication tag no longer validates. The cache detects this on the next
cold read of the block or during the periodic data scan, which invalidates and
re-fetches the object.

By default the latest cached version is targeted; use --etag or --instance to
select a specific version.

Examples:
  pelican cache chaos corrupt pelican://my-federation/data/file.dat
  pelican cache chaos corrupt /data/file.dat --block 3 --bytes 32
  pelican cache chaos corrupt --instance <hash> --block 0`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runCacheChaosCorrupt,
		SilenceUsage: true,
	}

	cacheChaosTruncateCmd = &cobra.Command{
		Use:   "truncate <object-url>",
		Short: "Truncate a cached object's on-disk data",
		Long: `Remove bytes from the end of one of a cached object's on-disk chunk files,
dropping trailing block(s). The cache detects the missing/short data on a cold
read or during the data scan.

By default the last chunk is truncated by one block; use --chunk and
--drop-bytes to control which chunk and how much is removed.

Examples:
  pelican cache chaos truncate pelican://my-federation/data/file.dat
  pelican cache chaos truncate /data/file.dat --drop-bytes 65536
  pelican cache chaos truncate --instance <hash> --chunk 0`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runCacheChaosTruncate,
		SilenceUsage: true,
	}
)

func init() {
	cacheCmd.AddCommand(cacheChaosCmd)
	cacheChaosCmd.AddCommand(cacheChaosCorruptCmd)
	cacheChaosCmd.AddCommand(cacheChaosTruncateCmd)

	cacheChaosCmd.PersistentFlags().StringVar(&chaosEtag, "etag", "", "Select the object version by ETag (default: latest)")
	cacheChaosCmd.PersistentFlags().StringVar(&chaosInstance, "instance", "", "Select the object version by instance hash")
	cacheChaosCmd.PersistentFlags().BoolVar(&chaosJSON, "json", false, "Output in JSON format")
	cacheChaosCmd.PersistentFlags().StringVarP(&introspectToken, "token", "t", "", "Path to admin token file (auto-generated if not provided)")

	cacheChaosCorruptCmd.Flags().Uint32Var(&chaosBlock, "block", 0, "Zero-based block number to corrupt")
	cacheChaosCorruptCmd.Flags().IntVar(&chaosBytes, "bytes", 0, "Number of bytes to flip (default: the authentication-tag size)")

	cacheChaosTruncateCmd.Flags().IntVar(&chaosChunk, "chunk", -1, "Chunk index to truncate (default: the last chunk)")
	cacheChaosTruncateCmd.Flags().Int64Var(&chaosDropBytes, "drop-bytes", 0, "Bytes to remove from the end of the chunk file (default: one block)")
}

// chaosServerURL returns the running cache server's URL, or an error if the
// cache is not running.  The chaos API operates exclusively against a live
// cache server (there is no offline mode: BadgerDB is single-process).
func chaosServerURL() (string, error) {
	if err := initIntrospectConfig(); err != nil {
		return "", errors.Wrap(err, "failed to initialize cache server config")
	}
	serverURL := discoverServerURL()
	if serverURL == "" {
		return "", errors.New("could not find a running cache server; the chaos API operates against a running cache (ensure the cache is up and started with Cache.EnableChaosAPI=true)")
	}
	return serverURL, nil
}

// chaosObjectQuery builds the object-selection query parameters shared by the
// corrupt and truncate subcommands.
func chaosObjectQuery(objectURL string) (url.Values, error) {
	q := url.Values{}
	if chaosInstance != "" {
		q.Set("instance", chaosInstance)
	} else if objectURL != "" {
		q.Set("url", objectURL)
		if chaosEtag != "" {
			q.Set("etag", chaosEtag)
		}
	} else {
		return nil, errors.New("either <object-url> or --instance is required")
	}
	return q, nil
}

func postChaos(query url.Values) (*local_cache.ChaosResult, error) {
	serverURL, err := chaosServerURL()
	if err != nil {
		return nil, err
	}
	body, err := introspectHTTPPost(serverURL, "/api/v1.0/cache/introspect/chaos", query)
	if err != nil {
		return nil, err
	}
	var result local_cache.ChaosResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, "failed to parse response")
	}
	return &result, nil
}

func printChaosResult(result *local_cache.ChaosResult) error {
	if chaosJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return errors.Wrap(err, "failed to marshal result")
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("Injected %s into cached object:\n", result.Operation)
	fmt.Printf("  Instance:    %s\n", result.InstanceHash)
	if result.SourceURL != "" {
		fmt.Printf("  Source URL:  %s\n", result.SourceURL)
	}
	if result.ETag != "" {
		fmt.Printf("  ETag:        %s\n", result.ETag)
	}
	fmt.Printf("  Chunk file:  %s (chunk %d)\n", result.FilePath, result.ChunkIndex)
	switch result.Operation {
	case "corrupt-block":
		fmt.Printf("  Block:       %d (disk offset %d, flipped %d byte(s))\n", result.BlockNum, result.DiskOffset, result.BytesChanged)
	case "truncate":
		fmt.Printf("  Truncated:   %d -> %d bytes\n", result.OldFileSize, result.NewFileSize)
	}
	return nil
}

func runCacheChaosCorrupt(cmd *cobra.Command, args []string) error {
	objectURL := ""
	if len(args) > 0 {
		objectURL = args[0]
	}
	query, err := chaosObjectQuery(objectURL)
	if err != nil {
		return err
	}
	query.Set("op", "corrupt")
	query.Set("block", strconv.FormatUint(uint64(chaosBlock), 10))
	if chaosBytes > 0 {
		query.Set("bytes", strconv.Itoa(chaosBytes))
	}

	result, err := postChaos(query)
	if err != nil {
		return errors.Wrap(err, "failed to corrupt block")
	}
	return printChaosResult(result)
}

func runCacheChaosTruncate(cmd *cobra.Command, args []string) error {
	objectURL := ""
	if len(args) > 0 {
		objectURL = args[0]
	}
	query, err := chaosObjectQuery(objectURL)
	if err != nil {
		return err
	}
	query.Set("op", "truncate")
	query.Set("chunk", strconv.Itoa(chaosChunk))
	if chaosDropBytes > 0 {
		query.Set("drop-bytes", strconv.FormatInt(chaosDropBytes, 10))
	}

	result, err := postChaos(query)
	if err != nil {
		return errors.Wrap(err, "failed to truncate object")
	}
	return printChaosResult(result)
}
