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
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// ANSI color helpers — only emit escape codes when stderr is a terminal.
var (
	colorReset  = ""
	colorBold   = ""
	colorGreen  = ""
	colorYellow = ""
	colorCyan   = ""
)

func initColors() {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		colorReset = "\033[0m"
		colorBold = "\033[1m"
		colorGreen = "\033[32m"
		colorYellow = "\033[33m"
		colorCyan = "\033[36m"
	}
}

var (
	rcloneSetupCmd = &cobra.Command{
		Use:   "setup <pelican-url>",
		Short: "Generate an rclone configuration for a Pelican namespace",
		Long: `Generate an rclone configuration that can be used to sync files
to and from a Pelican namespace.

The generated section is automatically appended to the rclone configuration
file (typically ~/.config/rclone/rclone.conf), creating the file if it does
not already exist. The configuration is also printed to stdout for reference.
Use --output to write to a different file instead.

The configuration includes a bearer_token_command that automatically fetches
fresh tokens when needed. When rclone receives an HTTP 401 Unauthorized
response (indicating token expiry), it re-runs the bearer_token_command to
get a fresh token and retries the request.

The Pelican Director inspects bearer tokens in client requests and returns
HTTP 401 if a token has expired. This triggers rclone's automatic token
refresh, ensuring seamless operation with long-running sync jobs.

Examples:
  # Generate config for reading from a namespace
  pelican rclone setup --read pelican://federation.example.org/namespace/path

  # Generate config for reading and writing to a namespace
  pelican rclone setup --write pelican://federation.example.org/namespace/path

  # Generate config with a custom remote name
  pelican rclone setup --name my-pelican --write pelican://federation.example.org/namespace/path

If rclone is not installed, the command will suggest running
'pelican rclone install' to install it.`,
		RunE: rcloneSetupMain,
		Args: cobra.ExactArgs(1),
	}

	rcloneSetupRemoteName     string
	rcloneSetupReadOnly       bool
	rcloneSetupReadWrite      bool
	rcloneSetupOutputFile     string
	rcloneSetupNoPasswordFile bool
)

func init() {
	rcloneCmd.AddCommand(rcloneSetupCmd)

	rcloneSetupCmd.Flags().StringVarP(&rcloneSetupRemoteName, "name", "n", "", "Name for the rclone remote (default: derived from namespace)")
	rcloneSetupCmd.Flags().BoolVarP(&rcloneSetupReadOnly, "read", "r", false, "Configure for read-only access")
	rcloneSetupCmd.Flags().BoolVarP(&rcloneSetupReadWrite, "write", "w", false, "Configure for write access (implies read)")
	rcloneSetupCmd.Flags().StringVarP(&rcloneSetupOutputFile, "output", "o", "", "Output file for the configuration (default: stdout)")
	rcloneSetupCmd.Flags().BoolVar(&rcloneSetupNoPasswordFile, "no-password-file", false, "Do not create a separate passwordless credential file for rclone")
}

// deriveRemoteName creates a reasonable rclone remote name from a namespace path
func deriveRemoteName(namespacePath string) string {
	// Remove leading slash and replace remaining slashes with dashes
	name := strings.TrimPrefix(namespacePath, "/")
	name = strings.ReplaceAll(name, "/", "-")

	// If empty, use a default
	if name == "" {
		name = "pelican"
	}

	return name
}

// checkRcloneInstalled returns true if rclone is found on the PATH
func checkRcloneInstalled() bool {
	_, err := exec.LookPath("rclone")
	return err == nil
}

// getRcloneConfigFile returns the path to the rclone configuration file.
// If rclone is installed, it asks rclone directly; otherwise it falls back
// to the default XDG / home directory location.
func getRcloneConfigFile() (string, error) {
	// Ask rclone if it's available — the last non-empty line of
	// "rclone config file" output is the path.
	cmd := exec.Command("rclone", "config", "file")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) > 0 {
			last := strings.TrimSpace(lines[len(lines)-1])
			if last != "" {
				return last, nil
			}
		}
	}

	// Fall back to default locations
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "rclone", "rclone.conf"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to determine home directory")
	}

	return filepath.Join(homeDir, ".config", "rclone", "rclone.conf"), nil
}

// remoteExistsInConfig checks whether a remote name already exists in the
// given rclone config file content.
func remoteExistsInConfig(content, remoteName string) bool {
	target := fmt.Sprintf("[%s]", remoteName)
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == target {
			return true
		}
	}
	return false
}

// getPelicanExecutable returns the path to the current pelican executable
func getPelicanExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", errors.Wrap(err, "failed to get executable path")
	}

	// Resolve any symlinks
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", errors.Wrap(err, "failed to resolve executable path")
	}

	return executable, nil
}

// createPasswordlessCredentialFile creates a passwordless credential file
// containing only the OAuth2 entry for the given namespace prefix.
// The file is placed alongside the main credential file with a per-prefix name.
func createPasswordlessCredentialFile(nsPrefix string) (string, error) {
	// Get current config
	osdfConfig, err := config.GetCredentialConfigContents()
	if err != nil {
		return "", errors.Wrap(err, "failed to read credential configuration")
	}

	// Filter to only include the entry for this prefix
	var filtered []config.PrefixEntry
	for _, entry := range osdfConfig.OSDF.OauthClient {
		if entry.Prefix == nsPrefix {
			filtered = append(filtered, entry)
			break
		}
	}
	if len(filtered) == 0 {
		return "", errors.Errorf("no credential entry found for prefix %s", nsPrefix)
	}
	filteredConfig := config.OSDFConfig{}
	filteredConfig.OSDF.OauthClient = filtered

	// Create a new file in the same directory as the main credential file,
	// named after the prefix so each prefix gets its own file.
	mainCredFile, err := config.GetEncryptedConfigName()
	if err != nil {
		return "", err
	}

	credDir := filepath.Dir(mainCredFile)
	// Turn the prefix (e.g. "/ospool/ap40") into a safe filename component
	safeName := strings.ReplaceAll(strings.Trim(nsPrefix, "/"), "/", "_")
	if safeName == "" {
		safeName = "default"
	}
	rcloneCredFile := filepath.Join(credDir, fmt.Sprintf("rclone-credentials-%s.pem", safeName))

	// Save with empty password (unencrypted)
	if err := config.SaveConfigContentsToFile(&filteredConfig, rcloneCredFile, false); err != nil {
		return "", err
	}

	return rcloneCredFile, nil
}

func rcloneSetupMain(cmd *cobra.Command, args []string) error {
	err := config.InitClient()
	if err != nil {
		return errors.Wrap(err, "failed to initialize client configuration")
	}

	// Parse the Pelican URL
	rawUrl := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawUrl)
	if err != nil {
		return errors.Wrapf(err, "failed to parse URL: %s", rawUrl)
	}

	// Get federation and namespace info from the director.
	// For writes, query with PUT so the director returns the writable origin;
	// for reads, query with GET.
	httpMethod := http.MethodGet
	if rcloneSetupReadWrite {
		httpMethod = http.MethodPut
	}
	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return errors.Wrapf(err, "failed to get director info for %s", rawUrl)
	}

	// Determine the access mode.
	// --write implies read: the remote can be used for both reads and writes.
	// When only --read is specified, the remote is configured for read-only
	// access through the Director (which provides caching).
	accessMode := "read"
	if rcloneSetupReadWrite {
		accessMode = "read+write"
	} else if !rcloneSetupReadOnly {
		// Default to read if neither specified
		rcloneSetupReadOnly = true
	}

	// Determine remote name
	remoteName := rcloneSetupRemoteName
	if remoteName == "" {
		remoteName = deriveRemoteName(pUrl.Path)
	}

	// Get the target URL from the director response.
	// For write access (which implies read), rclone needs the origin URL
	// directly because HTTP PUT does not follow 307 redirects. Reads through
	// the origin still work — they just bypass caching.
	// For read-only access, rclone uses the director URL — the director's
	// ShortcutMiddleware routes GET requests to the best cache (307) and
	// PROPFIND to the origin (307), both of which rclone follows transparently.
	var webdavURL string
	if rcloneSetupReadWrite {
		var originHost, originScheme string
		if len(dirResp.ObjectServers) > 0 {
			originScheme = dirResp.ObjectServers[0].Scheme
			originHost = dirResp.ObjectServers[0].Host
		} else if dirResp.Location != nil {
			originScheme = dirResp.Location.Scheme
			originHost = dirResp.Location.Host
		} else {
			return errors.New("no origin servers found in director response")
		}
		webdavURL = fmt.Sprintf("%s://%s%s", originScheme, originHost, pUrl.Path)
	} else {
		// Read mode: use the director URL so it can pick the best cache.
		directorURL := pUrl.FedInfo.DirectorEndpoint
		if directorURL == "" {
			return errors.New("could not determine the director URL for this federation")
		}
		webdavURL = fmt.Sprintf("%s%s", directorURL, pUrl.Path)
	}

	// For public prefixes, skip credential file handling entirely
	requiresToken := dirResp.XPelNsHdr.RequireToken
	var credentialFileFlag string
	if requiresToken {
		// Check if credentials have a password
		hasPassword, err := config.HasEncryptedPassword()
		if err != nil {
			log.Warnf("Could not check credential file password status: %v", err)
		}

		// Warn about password and offer alternative
		if hasPassword && !rcloneSetupNoPasswordFile {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "WARNING: Your credential file is password-protected.")
			fmt.Fprintln(os.Stderr, "Rclone's bearer_token_command runs non-interactively, so password prompts will fail.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Creating a separate passwordless credential file for rclone...")

			credFile, err := createPasswordlessCredentialFile(dirResp.XPelNsHdr.Namespace)
			if err != nil {
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintf(os.Stderr, "ERROR: Failed to create passwordless credential file: %v\n", err)
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintln(os.Stderr, "You may need to manually handle token acquisition or use --no-password-file")
				fmt.Fprintln(os.Stderr, "and set up an alternative token source.")
			} else {
				fmt.Fprintf(os.Stderr, "Created: %s (permissions set to 0600)\n", credFile)
				credentialFileFlag = fmt.Sprintf(" --credential-file %s", credFile)
			}
			fmt.Fprintln(os.Stderr, "")
		}
	}

	// Get pelican executable path
	pelicanExe, err := getPelicanExecutable()
	if err != nil {
		return errors.Wrap(err, "failed to determine pelican executable path")
	}

	// Build the federation discovery URL
	fedDiscoveryUrl := param.Federation_DiscoveryUrl.GetString()
	if fedDiscoveryUrl == "" {
		// Derive from the pelican URL
		fedDiscoveryUrl = fmt.Sprintf("https://%s", pUrl.Host)
	}

	// Generate the configuration
	var configBuilder strings.Builder

	configBuilder.WriteString(fmt.Sprintf("# Rclone configuration for Pelican path: %s\n", pUrl.Path))
	configBuilder.WriteString("# Generated by: pelican rclone setup\n")
	configBuilder.WriteString(fmt.Sprintf("# Access mode: %s\n", accessMode))
	configBuilder.WriteString("#\n")
	configBuilder.WriteString(fmt.Sprintf("# Usage: rclone ls %s:\n", remoteName))
	configBuilder.WriteString("#\n")
	configBuilder.WriteString(fmt.Sprintf("[%s]\n", remoteName))
	configBuilder.WriteString("type = webdav\n")
	configBuilder.WriteString(fmt.Sprintf("url = %s\n", webdavURL))
	configBuilder.WriteString("vendor = other\n")

	// Add bearer token command for automatic token refresh (only if the prefix
	// requires tokens; public prefixes need no authentication).
	if requiresToken {
		// The token command uses --write (which implies read+list) or --read.
		tokenAccessFlag := "read"
		if rcloneSetupReadWrite {
			tokenAccessFlag = "write"
		}
		tokenCmd := fmt.Sprintf("%s -f %s rclone token --%s%s %s",
			pelicanExe, fedDiscoveryUrl, tokenAccessFlag, credentialFileFlag, pUrl.String())
		configBuilder.WriteString(fmt.Sprintf("bearer_token_command = %s\n", tokenCmd))
	}

	// Output the configuration
	output := configBuilder.String()

	initColors()

	if rcloneSetupOutputFile != "" {
		// Write to the specified file
		if err := os.WriteFile(rcloneSetupOutputFile, []byte(output), 0600); err != nil {
			return errors.Wrapf(err, "failed to write configuration to %s", rcloneSetupOutputFile)
		}
		fmt.Fprintf(os.Stderr, "%s%sConfiguration written to:%s %s\n", colorBold, colorGreen, colorReset, rcloneSetupOutputFile)
	} else {
		// Append to the rclone config file and print to stdout
		confPath, err := getRcloneConfigFile()
		if err != nil {
			log.Warnf("Could not determine rclone config file path: %v", err)
		} else {
			// Read existing content to check for duplicate remote names
			existing, _ := os.ReadFile(confPath)
			if remoteExistsInConfig(string(existing), remoteName) {
				fmt.Fprintf(os.Stderr, "%s%sWARNING:%s Remote [%s] already exists in %s — skipping append.\n", colorBold, colorYellow, colorReset, remoteName, confPath)
				fmt.Fprintln(os.Stderr, "Remove or rename the existing remote and re-run this command, or use --name to pick a different name.")
			} else {
				// Ensure the directory exists
				if err := os.MkdirAll(filepath.Dir(confPath), 0700); err != nil {
					log.Warnf("Could not create config directory: %v", err)
				} else {
					// Append with a leading newline to separate from any existing content
					payload := output
					if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
						payload = "\n" + payload
					}
					f, err := os.OpenFile(confPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
					if err != nil {
						log.Warnf("Could not open rclone config file for writing: %v", err)
					} else {
						_, writeErr := f.WriteString(payload)
						closeErr := f.Close()
						if writeErr != nil {
							log.Warnf("Failed to write config: %v", writeErr)
						} else if closeErr != nil {
							log.Warnf("Failed to close config file: %v", closeErr)
						} else {
							fmt.Fprintf(os.Stderr, "%s%sConfiguration appended to:%s %s\n", colorBold, colorGreen, colorReset, confPath)
						}
					}
				}
			}
		}

		// Print the config to stderr inside fenced block for visual separation
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "%s```%s\n", colorCyan, colorReset)
		fmt.Fprint(os.Stderr, output)
		fmt.Fprintf(os.Stderr, "%s```%s\n", colorCyan, colorReset)
	}

	// Check whether rclone is installed
	if !checkRcloneInstalled() {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "%s%sWARNING:%s rclone was not found on your PATH.\n", colorBold, colorYellow, colorReset)
		fmt.Fprintln(os.Stderr, "Install it by running:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "  %spelican rclone install%s\n", colorCyan, colorReset)
		fmt.Fprintln(os.Stderr, "")
	}

	// Print usage hints
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "%s%sQuick start:%s\n", colorBold, colorGreen, colorReset)
	fmt.Fprintf(os.Stderr, "  %srclone ls %s:%s           # List files\n", colorCyan, remoteName, colorReset)
	if rcloneSetupReadWrite {
		fmt.Fprintf(os.Stderr, "  %srclone copy %s: ./local%s  # Download files\n", colorCyan, remoteName, colorReset)
		fmt.Fprintf(os.Stderr, "  %srclone copy ./local %s:%s  # Upload files\n", colorCyan, remoteName, colorReset)
		fmt.Fprintf(os.Stderr, "  %srclone sync ./local %s:%s  # Sync local to remote\n", colorCyan, remoteName, colorReset)
	} else {
		fmt.Fprintf(os.Stderr, "  %srclone copy %s: ./local%s  # Download files\n", colorCyan, remoteName, colorReset)
	}

	return nil
}
