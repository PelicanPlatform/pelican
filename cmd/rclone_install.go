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
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	rcloneInstallCmd = &cobra.Command{
		Use:   "install",
		Short: "Download and install rclone",
		Long: `Download and install the latest stable release of rclone from
https://downloads.rclone.org.

By default the binary is placed in ~/.local/bin (or ~/bin if it exists
and ~/.local/bin does not). Use --prefix to choose a different location:

  pelican rclone install --prefix /usr/local/bin

If rclone is already installed on your PATH, the command exits with a
message showing the installed version.`,
		RunE:         rcloneInstallMain,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	rcloneInstallPrefix string
)

func init() {
	rcloneCmd.AddCommand(rcloneInstallCmd)

	rcloneInstallCmd.Flags().StringVar(&rcloneInstallPrefix, "prefix", "",
		"Directory in which to place the rclone binary (default: ~/.local/bin)")
}

// defaultInstallPrefix returns a sensible user-writable directory.
// It prefers directories that are already on the user's $PATH, then falls
// back to existing directories, and finally defaults to ~/.local/bin.
func defaultInstallPrefix() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/usr/local/bin"
	}

	candidates := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, "bin"),
	}

	// Build a set of directories currently on $PATH.
	pathSet := make(map[string]bool)
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		pathSet[d] = true
	}

	// First pass: prefer a candidate that is already on the PATH.
	for _, dir := range candidates {
		if pathSet[dir] {
			return dir
		}
	}

	// Second pass: prefer a candidate that already exists as a directory.
	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}

	// Neither exists — default to ~/.local/bin (we'll create it).
	return candidates[0]
}

// mapArch converts Go's GOARCH values to the names used in rclone
// release archives.
func mapArch(goarch string) string {
	switch goarch {
	case "arm":
		return "arm-v7"
	default:
		return goarch
	}
}

// mapOS converts Go's GOOS values to the names used in rclone release
// archives.
func mapOS(goos string) string {
	switch goos {
	case "darwin":
		return "osx"
	default:
		return goos
	}
}

func rcloneInstallMain(cmd *cobra.Command, _ []string) error {
	// Initialise colors (defined in rclone_setup.go).
	initColors()

	// If rclone is already installed, tell the user and exit.
	if existingPath, err := exec.LookPath("rclone"); err == nil {
		verOut, _ := exec.Command(existingPath, "version").Output()
		version := strings.SplitN(strings.TrimSpace(string(verOut)), "\n", 2)[0]
		fmt.Fprintf(os.Stderr, "%s%srclone is already installed:%s %s (%s)\n", colorBold, colorGreen, colorReset, existingPath, version)
		return nil
	}

	// Resolve the target prefix.
	prefix := rcloneInstallPrefix
	if prefix == "" {
		prefix = defaultInstallPrefix()
	}

	osName := mapOS(runtime.GOOS)
	arch := mapArch(runtime.GOARCH)

	archiveName := fmt.Sprintf("rclone-current-%s-%s", osName, arch)
	downloadURL := fmt.Sprintf("https://downloads.rclone.org/%s.zip", archiveName)

	fmt.Fprintf(os.Stderr, "Downloading rclone from %s%s%s ...\n", colorCyan, downloadURL, colorReset)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return errors.Wrap(err, "failed to download rclone")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, downloadURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read download")
	}

	// Open the zip archive from memory.
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return errors.Wrap(err, "failed to open zip archive")
	}

	// Find the rclone binary inside the archive.
	binaryName := "rclone"
	if runtime.GOOS == "windows" {
		binaryName = "rclone.exe"
	}

	var binaryEntry *zip.File
	for _, f := range zipReader.File {
		baseName := filepath.Base(f.Name)
		if baseName == binaryName && !f.FileInfo().IsDir() {
			binaryEntry = f
			break
		}
	}

	if binaryEntry == nil {
		return fmt.Errorf("could not find %s in the downloaded archive", binaryName)
	}

	// Ensure the target directory exists.
	if err := os.MkdirAll(prefix, 0755); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied creating directory %s\n\n"+
				"Try a user-writable prefix:\n\n"+
				"  pelican rclone install --prefix ~/.local/bin", prefix)
		}
		return errors.Wrapf(err, "failed to create directory %s", prefix)
	}

	// Stream the binary from the zip entry to a temporary file in the target
	// directory, then atomically rename it into place. This avoids a race
	// where another process could execute a partially-written binary.
	destPath := filepath.Join(prefix, binaryName)
	rc, err := binaryEntry.Open()
	if err != nil {
		return errors.Wrap(err, "failed to open rclone binary in archive")
	}
	defer rc.Close()

	tmpFile, err := os.CreateTemp(prefix, ".rclone-install-*")
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied writing to %s\n\n"+
				"Try a user-writable prefix:\n\n"+
				"  pelican rclone install --prefix ~/.local/bin", prefix)
		}
		return errors.Wrapf(err, "failed to create temporary file in %s", prefix)
	}
	tmpPath := tmpFile.Name()

	// Clean up the temp file on any error path.
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0755); err != nil {
		tmpFile.Close()
		return errors.Wrap(err, "failed to set permissions on temporary file")
	}
	if _, err := io.Copy(tmpFile, rc); err != nil {
		tmpFile.Close()
		return errors.Wrapf(err, "failed to write rclone binary to %s", tmpPath)
	}
	if err := tmpFile.Close(); err != nil {
		return errors.Wrapf(err, "failed to finalize temporary file %s", tmpPath)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return errors.Wrapf(err, "failed to install rclone binary to %s", destPath)
	}
	success = true

	fmt.Fprintf(os.Stderr, "%s%srclone installed to:%s %s\n", colorBold, colorGreen, colorReset, destPath)

	// Quick sanity check.
	verOut, err := exec.Command(destPath, "version").Output()
	if err == nil {
		version := strings.SplitN(strings.TrimSpace(string(verOut)), "\n", 2)[0]
		fmt.Fprintf(os.Stderr, "%s\n", version)
	}

	// Hint if the prefix is not on PATH.
	pathDirs := filepath.SplitList(os.Getenv("PATH"))
	onPath := false
	for _, d := range pathDirs {
		if d == prefix {
			onPath = true
			break
		}
	}
	if !onPath {
		isTTY := term.IsTerminal(int(os.Stderr.Fd()))
		fmt.Fprintln(os.Stderr, "")
		if isTTY {
			fmt.Fprintf(os.Stderr, "%s%sNOTE:%s %s is not on your PATH.\n", colorBold, colorYellow, colorReset, prefix)
			fmt.Fprintf(os.Stderr, "Add it with:  %sexport PATH=\"%s:$PATH\"%s\n", colorCyan, prefix, colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "NOTE: %s is not on your PATH.\n", prefix)
			fmt.Fprintf(os.Stderr, "Add it with:  export PATH=\"%s:$PATH\"\n", prefix)
		}
	}

	return nil
}
