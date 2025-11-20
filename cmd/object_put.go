/***************************************************************
*
* Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	putCmd = &cobra.Command{
		Use:   "put {source ...} {destination}",
		Short: "Send a file to a Pelican federation",
		Run:   putMain,
	}
)

func init() {
	flagSet := putCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively upload a collection.  Forces methods to only be http to get the freshest collection contents")
	flagSet.String("checksum-algorithm", "", "Checksum algorithm to use for upload and validation")
	flagSet.Bool("require-checksum", false, "Require the server to return a checksum for the uploaded file (uses crc32c algorithm if no specific algorithm is specified)")
	flagSet.String("checksums", "", "Verify files against a checksums manifest. The format is ALGORITHM:FILENAME")
	flagSet.String("transfer-stats", "", "File to write transfer stats to")
	flagSet.String("pack", "", "Package transfer using remote packing functionality (same as '?pack=' query). Options: auto, tar, tar.gz, tar.xz, zip. Default: auto when flag is provided without an explicit value")
	objectCmd.AddCommand(putCmd)
}

type manifestEntry struct {
	checksum string
	filePath string
}

func parseManifest(filePath string) ([]manifestEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []manifestEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, errors.Errorf("invalid manifest line format: %s", line)
		}
		entries = append(entries, manifestEntry{checksum: parts[0], filePath: parts[1]})
	}

	return entries, scanner.Err()
}

func verifyFileChecksum(filePath, expectedChecksum string, alg client.ChecksumType) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var h hash.Hash
	switch alg {
	case client.AlgMD5:
		h = md5.New()
	case client.AlgSHA1:
		h = sha1.New()
	case client.AlgCRC32:
		h = crc32.NewIEEE()
	case client.AlgCRC32C:
		crc32cTable := crc32.MakeTable(crc32.Castagnoli)
		h = crc32.New(crc32cTable)
	default:
		return errors.Errorf("unsupported checksum algorithm: %v", alg)
	}

	if _, err := io.Copy(h, file); err != nil {
		return err
	}

	computedChecksum := hex.EncodeToString(h.Sum(nil))

	if !strings.EqualFold(computedChecksum, expectedChecksum) {
		return errors.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, computedChecksum)
	}

	return nil
}

func putMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	// Set up signal handlers to flush logs on SIGTERM
	client.SetupSignalHandlers()

	err := config.InitClient()
	if err != nil {
		log.Errorln(err)
		if client.IsRetryable(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		} else {
			os.Exit(1)
		}
	}

	var options []client.TransferOption

	// Set the progress bars to the command line option
	tokenLocation, _ := cmd.Flags().GetString("token")

	// Add checksum options if requested
	checksumAlgorithm, _ := cmd.Flags().GetString("checksum-algorithm")
	requireChecksum, _ := cmd.Flags().GetBool("require-checksum")
	if requireChecksum || checksumAlgorithm != "" {
		options = append(options, client.WithRequireChecksum())
	}
	if checksumAlgorithm != "" {
		checksumType := client.ChecksumFromHttpDigest(checksumAlgorithm)
		if checksumType == client.AlgUnknown {
			log.Errorln("Unknown checksum algorithm:", checksumAlgorithm)
			var validAlgorithms []string
			for _, alg := range client.KnownChecksumTypes() {
				validAlgorithms = append(validAlgorithms, client.HttpDigestFromChecksum(alg))
			}
			log.Errorln("Valid algorithms are:", strings.Join(validAlgorithms, ", "))
			os.Exit(1)
		}
		options = append(options, client.WithRequestChecksums([]client.ChecksumType{checksumType}))
	}

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	if len(args) < 2 {
		log.Errorln("No Source or Destination")
		if err := cmd.Help(); err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}
	source := args[:len(args)-1]
	dest := args[len(args)-1]

	// Handle --pack flag by appending the appropriate query parameter to the destination URL
	packOption, _ := cmd.Flags().GetString("pack")
	if cmd.Flags().Changed("pack") {
		if packOption == "" {
			packOption = "auto"
		}
		if _, err := client.GetBehavior(packOption); err != nil {
			log.Errorln(err)
			os.Exit(1)
		}
		var err error
		dest, err = addPackQuery(dest, packOption)
		if err != nil {
			log.Errorln("Failed to process --pack option:", err)
			os.Exit(1)
		}
	}

	checksumsFile, _ := cmd.Flags().GetString("checksums")
	if checksumsFile != "" {
		parts := strings.SplitN(checksumsFile, ":", 2)
		if len(parts) != 2 {
			log.Errorln("invalid format for --checksums. Expected ALGORITHM:FILENAME")
			os.Exit(1)
		}
		algName, manifestPath := parts[0], parts[1]
		checksumType := client.ChecksumFromHttpDigest(algName)
		if checksumType == client.AlgUnknown {
			log.Errorln("Unknown checksum algorithm:", algName)
			var validAlgorithms []string
			for _, alg := range client.KnownChecksumTypes() {
				validAlgorithms = append(validAlgorithms, client.HttpDigestFromChecksum(alg))
			}
			log.Errorln("Valid algorithms are:", strings.Join(validAlgorithms, ", "))
			os.Exit(1)
		}
		log.Debugln("Parsing manifest file:", manifestPath)
		manifestEntries, err := parseManifest(manifestPath)
		if err != nil {
			log.Errorf("failed to parse manifest file %s: %v", manifestPath, err)
			os.Exit(1)
		}

		manifestMap := make(map[string]string)
		for _, entry := range manifestEntries {
			manifestMap[entry.filePath] = entry.checksum
		}

		for _, src := range source {
			expectedChecksum, ok := manifestMap[src]
			if !ok {
				log.Errorf("source file %s not found in checksums manifest", src)
				os.Exit(1)
			}
			if err := verifyFileChecksum(src, expectedChecksum, checksumType); err != nil {
				log.Errorf("checksum validation failed for %s: %v", src, err)
				os.Exit(1)
			}
			log.Infof("Checksum verified for %s", src)
		}
	}

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)

	var result error
	lastSrc := ""

	options = append(options, client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation))
	finalResults := make([][]client.TransferResults, 0)

	for _, src := range source {
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		transferResults, result := client.DoPut(ctx, src, dest, isRecursive, options...)
		if result != nil {
			lastSrc = src
			break
		}
		finalResults = append(finalResults, transferResults)
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := result.Error()
		var te *client.TransferErrors
		if errors.As(result, &te) {
			errMsg = te.UserError()
		}
		log.Errorln("Failure putting " + lastSrc + ": " + errMsg)
		if client.ShouldRetry(result) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

	transferStatsFile, _ := cmd.Flags().GetString("transfer-stats")
	if transferStatsFile != "" {
		transferStats, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			log.Errorln("Failed to marshal transfer results:", err)
		}
		err = os.WriteFile(transferStatsFile, transferStats, 0644)
		if err != nil {
			log.Errorln("Failed to write transfer stats to file:", err)
		}
	}

}
