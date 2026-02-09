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

package ssh_posixv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// signalEscalationTimeout is the duration to wait after SIGTERM before sending SIGKILL
const signalEscalationTimeout = 3 * time.Second

// terminateSession sends SIGTERM to a session, and if it doesn't terminate within
// the timeout, escalates to SIGKILL.
func terminateSession(session *ssh.Session, done <-chan error) {
	// First try SIGTERM for graceful shutdown
	if err := session.Signal(ssh.SIGTERM); err != nil {
		log.Debugf("Failed to send SIGTERM: %v", err)
	}

	// Wait for process to exit or timeout
	select {
	case <-done:
		// Process exited gracefully
		return
	case <-time.After(signalEscalationTimeout):
		// Escalate to SIGKILL
		log.Debugf("Process did not exit after SIGTERM, sending SIGKILL")
		if err := session.Signal(ssh.SIGKILL); err != nil {
			log.Debugf("Failed to send SIGKILL: %v", err)
		}
	}
}

// normalizeArch normalizes architecture names to Go's GOARCH format
func normalizeArch(arch string) string {
	arch = strings.TrimSpace(strings.ToLower(arch))
	switch arch {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i686", "x86":
		return "386"
	case "armv7l", "armhf":
		return "arm"
	case "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	default:
		return arch
	}
}

// normalizeOS normalizes OS names to Go's GOOS format
func normalizeOS(os string) string {
	os = strings.TrimSpace(strings.ToLower(os))
	switch os {
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	case "freebsd":
		return "freebsd"
	case "windows", "cygwin", "mingw64_nt-10.0":
		return "windows"
	default:
		return os
	}
}

// DetectRemotePlatform probes the remote system to detect OS and architecture
func (c *SSHConnection) DetectRemotePlatform(ctx context.Context) (*PlatformInfo, error) {
	if c.client == nil {
		return nil, errors.New("SSH client not connected")
	}

	// Run uname -s for OS
	osOutput, err := c.RunCommandArgs(ctx, []string{"uname", "-s"})
	if err != nil {
		return nil, errors.Wrap(err, "failed to detect remote OS")
	}

	// Run uname -m for architecture
	archOutput, err := c.RunCommandArgs(ctx, []string{"uname", "-m"})
	if err != nil {
		return nil, errors.Wrap(err, "failed to detect remote architecture")
	}

	platformInfo := &PlatformInfo{
		OS:   normalizeOS(osOutput),
		Arch: normalizeArch(archOutput),
	}

	c.platformInfo = platformInfo
	log.Infof("Detected remote platform: %s/%s", platformInfo.OS, platformInfo.Arch)

	return platformInfo, nil
}

// RunCommandArgs runs a command on the remote host with arguments passed as a slice.
// Each argument is properly quoted using go-shellquote to prevent shell injection attacks.
func (c *SSHConnection) RunCommandArgs(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("no command provided")
	}

	cmd := shellquote.Join(args...)

	session, err := c.client.NewSession()
	if err != nil {
		return "", errors.Wrap(err, "failed to create SSH session")
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Use a goroutine to allow context cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		terminateSession(session, done)
		return "", ctx.Err()
	case err := <-done:
		if err != nil {
			return "", errors.Wrapf(err, "command failed: %s (stderr: %s)", cmd, stderr.String())
		}
	}

	return strings.TrimSpace(stdout.String()), nil
}

// NeedsBinaryTransfer checks if we need to transfer a binary to the remote host.
// This is true unless there's a pre-configured remote binary override for the
// detected platform. Even when local and remote platforms match, the binary must
// be transferred because the remote host accesses it via its own filesystem.
func (c *SSHConnection) NeedsBinaryTransfer() bool {
	if c.platformInfo == nil {
		return true // Need to detect platform first
	}

	// Check if there's a pre-configured remote binary for this platform
	platformKey := fmt.Sprintf("%s/%s", c.platformInfo.OS, c.platformInfo.Arch)
	if _, ok := c.config.RemotePelicanBinaryOverrides[platformKey]; ok {
		return false // Use pre-deployed binary
	}

	// Always need to transfer — even when platforms match, the remote host
	// needs the binary available on its own filesystem.
	return true
}

// GetRemoteBinaryPath returns the path to the Pelican binary on the remote host
func (c *SSHConnection) GetRemoteBinaryPath() (string, error) {
	if c.platformInfo == nil {
		return "", errors.New("platform info not detected")
	}

	// Check for pre-configured binary override
	platformKey := fmt.Sprintf("%s/%s", c.platformInfo.OS, c.platformInfo.Arch)
	if override, ok := c.config.RemotePelicanBinaryOverrides[platformKey]; ok {
		log.Debugf("Using pre-configured binary for %s: %s", platformKey, override)
		return override, nil
	}

	// If we haven't transferred a binary yet, we need to do so
	if c.remoteBinaryPath == "" {
		return "", errors.New("binary not transferred to remote host")
	}

	return c.remoteBinaryPath, nil
}

// computeFileChecksum computes the SHA256 checksum of a file and returns it as a hex string
func computeFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// setupRemoteBinaryPath determines the best path for the remote binary
// Returns (path, isCached, error)
// If isCached is true, the binary should NOT be cleaned up on disconnect
// Uses XDG Base Directory Specification for cache location:
//   - $XDG_CACHE_HOME/pelican/binaries if XDG_CACHE_HOME is set
//   - $HOME/.cache/pelican/binaries otherwise
func (c *SSHConnection) setupRemoteBinaryPath(ctx context.Context, checksum string) (string, bool, error) {
	// Try to determine cache directory following XDG spec
	cacheDir, err := c.RunCommandArgs(ctx, []string{"sh", "-c", `echo "${XDG_CACHE_HOME:-$HOME/.cache}"`})
	if err != nil {
		log.Debugf("Failed to determine cache directory: %v", err)
	} else {
		cacheDir = strings.TrimSpace(cacheDir)
		if cacheDir != "" && cacheDir != "/.cache" { // Ensure we got a valid path
			pelicanCacheDir := filepath.Join(cacheDir, "pelican", "binaries")

			// Try to create the directory with secure permissions
			// Use shellquote.Join for safe quoting of the path in the shell command
			quotedPath := shellquote.Join(pelicanCacheDir)
			_, err := c.RunCommandArgs(ctx, []string{"sh", "-c", "mkdir -p " + quotedPath + " && chmod 700 " + quotedPath})
			if err == nil {
				// Use checksum-based filename for caching
				binaryPath := filepath.Join(pelicanCacheDir, fmt.Sprintf("pelican-%s", checksum[:16]))
				log.Debugf("Using XDG cache directory for binary: %s", binaryPath)
				return binaryPath, true, nil
			}
			log.Debugf("Failed to create cache directory %s: %v", pelicanCacheDir, err)
		}
	}

	// Fallback: create a secure temp directory
	tmpDir, err := c.RunCommandArgs(ctx, []string{"mktemp", "-d", "-t", "pelican-tmp-XXXXXX"})
	if err != nil {
		return "", false, errors.Wrap(err, "failed to create temp directory on remote host")
	}
	tmpDir = strings.TrimSpace(tmpDir)

	// Set restrictive permissions on the temp directory
	_, err = c.RunCommandArgs(ctx, []string{"chmod", "700", tmpDir})
	if err != nil {
		log.Warnf("Failed to set permissions on temp directory: %v", err)
	}

	c.remoteTempDir = tmpDir
	binaryPath := filepath.Join(tmpDir, "pelican")
	return binaryPath, false, nil
}

// TransferBinary transfers the Pelican binary to the remote host
// Uses checksum-based caching to avoid repeated transfers:
// - Tries ~/.pelican/pelican-<checksum> first (cached, not cleaned up)
// - Falls back to /tmp/pelican-<random> if ~/.pelican fails (cleaned up on exit)
func (c *SSHConnection) TransferBinary(ctx context.Context) error {
	if c.client == nil {
		return errors.New("SSH client not connected")
	}

	// Determine source binary path
	localBinaryPath := c.config.PelicanBinaryPath
	if localBinaryPath == "" {
		// Use current executable
		var err error
		localBinaryPath, err = os.Executable()
		if err != nil {
			return errors.Wrap(err, "failed to get current executable path")
		}
	}

	// Check if we need to use a different binary for the target platform
	if c.platformInfo != nil {
		platformKey := fmt.Sprintf("%s/%s", c.platformInfo.OS, c.platformInfo.Arch)

		// First check for configured overrides
		if override, ok := c.config.RemotePelicanBinaryOverrides[platformKey]; ok {
			// Verify the override binary exists and is executable on the remote
			_, err := c.RunCommandArgs(ctx, []string{"test", "-x", override})
			if err != nil {
				return errors.Wrapf(err, "configured binary override %s is not executable on remote host", override)
			}
			c.remoteBinaryPath = override
			c.remoteBinaryIsCached = true // Don't clean up configured overrides
			log.Infof("Using configured binary override: %s", override)
			return nil
		}

		// Check if local platform differs from remote
		if c.platformInfo.OS != runtime.GOOS || c.platformInfo.Arch != runtime.GOARCH {
			// Try to find a platform-specific binary in the same directory
			dir := filepath.Dir(localBinaryPath)
			base := filepath.Base(localBinaryPath)

			// Try common naming patterns
			candidates := []string{
				filepath.Join(dir, fmt.Sprintf("%s-%s-%s", base, c.platformInfo.OS, c.platformInfo.Arch)),
				filepath.Join(dir, fmt.Sprintf("pelican-%s-%s", c.platformInfo.OS, c.platformInfo.Arch)),
				filepath.Join(dir, fmt.Sprintf("pelican_%s_%s", c.platformInfo.OS, c.platformInfo.Arch)),
			}

			found := false
			for _, candidate := range candidates {
				if _, err := os.Stat(candidate); err == nil {
					localBinaryPath = candidate
					found = true
					log.Infof("Found platform-specific binary for %s: %s", platformKey, candidate)
					break
				}
			}

			if !found {
				return errors.Errorf("no binary available for remote platform %s (local platform: %s/%s). "+
					"Please configure Origin.SSH.RemotePelicanBinaryOverrides or place a binary at one of: %v",
					platformKey, runtime.GOOS, runtime.GOARCH, candidates)
			}
		}
	}

	// Compute checksum of the local binary
	checksum, err := computeFileChecksum(localBinaryPath)
	if err != nil {
		return errors.Wrap(err, "failed to compute binary checksum")
	}
	log.Debugf("Local binary checksum: %s", checksum)

	// Try to use ~/.pelican directory for cached binaries
	remotePath, isCached, err := c.setupRemoteBinaryPath(ctx, checksum)
	if err != nil {
		return errors.Wrap(err, "failed to set up remote binary path")
	}

	// Check if a binary with this checksum already exists
	if isCached {
		// Using shell to get EXISTS/MISSING output is okay since remotePath is checksum-based
		// Use shellquote.Join for safe quoting of the path
		existsOutput, err := c.RunCommandArgs(ctx, []string{"sh", "-c", "test -x " + shellquote.Join(remotePath) + " && echo EXISTS || echo MISSING"})
		if err == nil && strings.TrimSpace(existsOutput) == "EXISTS" {
			log.Infof("Binary with checksum %s already exists at %s, skipping transfer", checksum[:12], remotePath)
			c.remoteBinaryPath = remotePath
			c.remoteBinaryIsCached = true
			return nil
		}
	}

	// Open the local file
	localFile, err := os.Open(localBinaryPath)
	if err != nil {
		return errors.Wrap(err, "failed to open local binary")
	}
	defer localFile.Close()

	// Get file info for permissions and size
	fileInfo, err := localFile.Stat()
	if err != nil {
		return errors.Wrap(err, "failed to stat local binary")
	}

	log.Infof("Transferring binary %s (%d bytes) to remote host at %s",
		localBinaryPath, fileInfo.Size(), remotePath)

	// Use SCP to transfer the file
	err = c.scpFile(ctx, localFile, remotePath, fileInfo.Size(), 0755)
	if err != nil {
		return errors.Wrap(err, "failed to transfer binary via SCP")
	}

	// Verify the transfer
	_, err = c.RunCommandArgs(ctx, []string{"test", "-x", remotePath})
	if err != nil {
		return errors.Wrap(err, "transferred binary is not executable on remote host")
	}

	c.remoteBinaryPath = remotePath
	c.remoteBinaryIsCached = isCached
	log.Infof("Binary successfully transferred to %s (cached: %v)", remotePath, isCached)

	return nil
}

// scpFile uses SCP protocol to transfer a file to the remote host
func (c *SSHConnection) scpFile(ctx context.Context, src io.Reader, destPath string, size int64, mode os.FileMode) error {
	session, err := c.client.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create SSH session")
	}
	defer session.Close()

	// Get stdin pipe to write file content
	stdin, err := session.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "failed to get stdin pipe")
	}

	// Get stdout/stderr for error messages
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Start the SCP command - use shellquote for safe directory escaping
	destDir := filepath.Dir(destPath)
	destFile := filepath.Base(destPath)

	// Validate filename doesn't contain characters that could break SCP protocol
	// The SCP protocol header format is "C<mode> <size> <filename>\n"
	// so newlines or null bytes in filename would cause protocol issues
	if strings.ContainsAny(destFile, "\n\r\x00") {
		return errors.Errorf("invalid filename for SCP transfer: contains control characters")
	}

	if err := session.Start("scp -t " + shellquote.Join(destDir)); err != nil {
		return errors.Wrap(err, "failed to start SCP command")
	}

	// Send the file header
	// Format: C<mode> <size> <filename>\n
	header := fmt.Sprintf("C%04o %d %s\n", mode, size, destFile)
	if _, err := stdin.Write([]byte(header)); err != nil {
		return errors.Wrap(err, "failed to write SCP header")
	}

	// Send the file content
	n, err := io.Copy(stdin, src)
	if err != nil {
		return errors.Wrap(err, "failed to copy file content")
	}
	if n != size {
		return errors.Errorf("incomplete file transfer: sent %d of %d bytes", n, size)
	}

	// Send the end marker
	if _, err := stdin.Write([]byte{0}); err != nil {
		return errors.Wrap(err, "failed to write SCP end marker")
	}

	// Close stdin to signal we're done
	if err := stdin.Close(); err != nil {
		return errors.Wrap(err, "failed to close stdin pipe")
	}

	// Wait for the command to complete
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		terminateSession(session, done)
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return errors.Wrapf(err, "SCP failed (stderr: %s)", stderr.String())
		}
	}

	return nil
}

// CleanupRemoteBinary removes the transferred binary from the remote host
// Only cleans up temp directories, not cached binaries in ~/.pelican
func (c *SSHConnection) CleanupRemoteBinary(ctx context.Context) error {
	if c.remoteBinaryPath == "" {
		return nil // Nothing to clean up
	}

	// Don't clean up cached binaries - they're meant to persist
	if c.remoteBinaryIsCached {
		log.Debugf("Leaving cached binary at %s", c.remoteBinaryPath)
		c.remoteBinaryPath = ""
		return nil
	}

	// Only clean up temp directories (contain random suffix)
	dir := filepath.Dir(c.remoteBinaryPath)
	if c.remoteTempDir != "" && strings.HasPrefix(dir, c.remoteTempDir) {
		// Remove the entire temp directory we created
		_, err := c.RunCommandArgs(ctx, []string{"rm", "-rf", c.remoteTempDir})
		if err != nil {
			log.Warnf("Failed to cleanup remote temp directory %s: %v", c.remoteTempDir, err)
			return err
		}
		log.Debugf("Cleaned up temp directory %s", c.remoteTempDir)
	} else if strings.Contains(dir, "pelican-tmp-") {
		// Fallback: clean up if it looks like our temp directory pattern
		_, err := c.RunCommandArgs(ctx, []string{"rm", "-rf", dir})
		if err != nil {
			log.Warnf("Failed to cleanup remote binary directory %s: %v", dir, err)
			return err
		}
	}

	c.remoteBinaryPath = ""
	c.remoteTempDir = ""
	return nil
}
