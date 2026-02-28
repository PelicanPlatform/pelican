//go:build !windows

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

package xrootd

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MinXrootdVersion is the minimum required XRootD version for Pelican cache and origin components.
// This version must be kept in sync with the version specified in .goreleaser.yml (two locations: RPM and DEB dependencies).
const MinXrootdVersion = "5.8.2"

var (
	xrootdVersionOnce   sync.Once
	xrootdVersionOutput string
	xrootdVersionErr    error
)

// ResetXrootdVersionForTesting resets the cached XRootD version output.
// This should only be used in tests.
func ResetXrootdVersionForTesting() {
	xrootdVersionOnce = sync.Once{}
	xrootdVersionOutput = ""
	xrootdVersionErr = nil
}

// getXrootdVersionOutput runs 'xrootd -v' once and caches the result.
// Subsequent calls return the cached output without re-executing the command.
func getXrootdVersionOutput() (string, error) {
	xrootdVersionOnce.Do(func() {
		// Execute xrootd -v to get version information
		// Note: xrootd outputs version to stderr, not stdout
		cmd := exec.Command("xrootd", "-v")
		output, err := cmd.CombinedOutput()
		if err != nil {
			xrootdVersionErr = err
			return
		}
		xrootdVersionOutput = strings.TrimSpace(string(output))
	})
	return xrootdVersionOutput, xrootdVersionErr
}

// GetXrootdMajorVersion returns the major version number of the installed XRootD
// (e.g., "5" or "6"). Returns an empty string if the version cannot be determined.
// The result is cached after the first call.
func GetXrootdMajorVersion() string {
	output, err := getXrootdVersionOutput()
	if err != nil || output == "" {
		return ""
	}

	re := regexp.MustCompile(`v?(\d+)\.\d+\.\d+`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

/*
* CheckXrootdVersion checks if the installed XRootD version meets the minimum requirement.
* It executes 'xrootd -v' to retrieve the version and compares it against MinXrootdVersion.
* The xrootd binary is only invoked once; subsequent calls use the cached result.
* Returns an error if:
*   - The xrootd binary is not found in PATH
*   - The version cannot be determined
*   - The version is below the minimum requirement
 */
func CheckXrootdVersion() error {
	output, err := getXrootdVersionOutput()
	if err != nil {
		// Check if this is a "command not found" error
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Debugf("XRootD version check failed with exit code %d: %v", exitErr.ExitCode(), err)
		}
		// If exec.LookPath would fail, exec.Command returns a specific error
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found") {
			return errors.New("XRootD binary not found in PATH. Please install XRootD version " + MinXrootdVersion + " or later. " +
				"See installation instructions at https://xrootd.org/")
		}
		return errors.Wrap(err, "failed to execute 'xrootd -v' to determine XRootD version")
	}

	// Parse the version output
	log.Debugf("XRootD version output: %s", output)

	// Remove leading 'v' if present (e.g., "v5.8.2" -> "5.8.2")
	versionStr := strings.TrimPrefix(output, "v")

	// Parse the version string
	xrootdVer, err := version.NewVersion(versionStr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse XRootD version string '%s'. Please ensure XRootD is properly installed", versionStr)
	}

	// Normalize to core version (strips pre-release suffixes like -rc1, +git123)
	xrootdVer = xrootdVer.Core()

	// Parse the minimum required version
	requiredVersion, err := version.NewVersion(MinXrootdVersion)
	if err != nil {
		// This should never happen unless MinXrootdVersion constant is malformed
		return errors.Wrapf(err, "internal error: failed to parse minimum version constant '%s'", MinXrootdVersion)
	}

	// Compare versions
	if xrootdVer.LessThan(requiredVersion) {
		return errors.Errorf("XRootD version %s is insufficient (minimum required: %s). "+
			"Please upgrade XRootD to version %s or later. "+
			"This requirement is necessary for proper operation of Pelican Cache and Origin servers.",
			xrootdVer.String(), MinXrootdVersion, MinXrootdVersion)
	}

	log.Debugf("XRootD version check passed: %s >= %s", xrootdVer.String(), MinXrootdVersion)
	return nil
}
