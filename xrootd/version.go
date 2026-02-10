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
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MinXrootdVersion is the minimum required XRootD version for Pelican cache and origin components.
// This version must be kept in sync with the version specified in .goreleaser.yml (two locations: RPM and DEB dependencies).
const MinXrootdVersion = "5.8.2"

/*
* CheckXrootdVersion checks if the installed XRootD version meets the minimum requirement.
* It executes 'xrootd -v' to retrieve the version and compares it against MinXrootdVersion.
* Returns an error if:
*   - The xrootd binary is not found in PATH
*   - The version cannot be determined
*   - The version is below the minimum requirement
 */
func CheckXrootdVersion() error {
	// Execute xrootd -v to get version information
	// Note: xrootd outputs version to stderr, not stdout
	cmd := exec.Command("xrootd", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if this is a "command not found" error
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Debugf("XRootD version check failed with exit code %d: %v", exitErr.ExitCode(), err)
		}
		// If exec.LookPath would fail, exec.Command returns a specific error
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found") {
			return errors.New("XRootD binary not found in PATH. Please install XRootD version " + MinXrootdVersion + " or later. " +
				"See installation instructions at https://xrootd.slac.stanford.edu/")
		}
		return errors.Wrap(err, "failed to execute 'xrootd -v' to determine XRootD version")
	}

	// Parse the version output
	versionStr := strings.TrimSpace(string(output))
	log.Debugf("XRootD version output: %s", versionStr)

	// Remove leading 'v' if present (e.g., "v5.8.2" -> "5.8.2")
	versionStr = strings.TrimPrefix(versionStr, "v")

	// Parse the version string
	xrootdVersion, err := version.NewVersion(versionStr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse XRootD version string '%s'. Please ensure XRootD is properly installed", versionStr)
	}

	// Normalize to core version (strips pre-release suffixes like -rc1, +git123)
	xrootdVersion = xrootdVersion.Core()

	// Parse the minimum required version
	requiredVersion, err := version.NewVersion(MinXrootdVersion)
	if err != nil {
		// This should never happen unless MinXrootdVersion constant is malformed
		return errors.Wrapf(err, "internal error: failed to parse minimum version constant '%s'", MinXrootdVersion)
	}

	// Compare versions
	if xrootdVersion.LessThan(requiredVersion) {
		return errors.Errorf("XRootD version %s is insufficient (minimum required: %s). "+
			"Please upgrade XRootD to version %s or later. "+
			"This requirement is necessary for proper operation of Pelican cache and origin servers.",
			xrootdVersion.String(), MinXrootdVersion, MinXrootdVersion)
	}

	log.Debugf("XRootD version check passed: %s >= %s", xrootdVersion.String(), MinXrootdVersion)
	return nil
}
