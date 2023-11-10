//go:build linux

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Different distros have different default CACertificate locations. Instead of trying to figure out
// the version of linux we use, check all the well-known places until we find one that exists.
func findLinuxCACert() (string, error) {
	// These values pulled from the same place x509 package looks:
	// https://go.dev/src/crypto/x509/root_linux.go
	certFileLocations := []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
		"/etc/pki/tls/cert.pem",                             // One RHEL-based possibility
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Another RHEL-based possibility
		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		"/etc/pki/tls/cacert.pem",                           // OpenELEC
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Often the think previous RHEL options symlink to
		"/etc/ssl/cert.pem",                                 // Alpine Linux
	}

	for _, certLoc := range certFileLocations {
		if file, err := os.Open(certLoc); err == nil {
			file.Close()
			return certLoc, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}

	// If we didn't find a cert in a well-known location, we'll wind up creating one later.
	// In that case, we need to make sure it's someplace we have permission to write to, so we'll
	// put it where we put other Pelican certs
	configDir := viper.GetString("ConfigDir")
	return filepath.Join(configDir, "certificates", "cert.pem"), nil
}

func InitServerOSDefaults() error {
	if certLoc, err := findLinuxCACert(); err == nil {
		viper.SetDefault("Server.TLSCACertificateFile", certLoc)
		return nil
	} else {
		return err
	}
}
