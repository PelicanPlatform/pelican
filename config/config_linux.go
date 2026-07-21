//go:build linux

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

package config

import (
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// ApplyOSDefaultsOverride is a no-op on Linux. The generated defaults in
// parameter_defaults.go -- /run/pelican/... when root, $XDG_RUNTIME_DIR/...
// when unprivileged -- expand correctly under systemd (which always
// populates XDG_RUNTIME_DIR for logged-in users) and under root. The
// non-Linux implementation rebases sub-paths whose $XDG_RUNTIME_DIR
// expansion collapsed to "/pelican/..." when the env var is empty; see
// config_default.go for the details.
func ApplyOSDefaultsOverride(v *viper.Viper, runtimeDir string) {}

// osShortRuntimeTempBase returns the empty string on Linux. Linux's
// os.TempDir() is /tmp, which is already short enough for AF_UNIX socket
// paths to fit under the 108-byte limit even with XRootD's admin-path
// suffix. See config_default.go for the darwin override.
func osShortRuntimeTempBase() string { return "" }

func InitServerOSDefaults(v *viper.Viper) error {
	// For Linux, even if we have well-known system CAs, we don't want to
	// use them, because we want to always generate our own CA if Server_TLSCertificateChain (host certificate chain)
	// is not explicitly set so that we can sign our host cert by our CA instead of self-signing
	configDir := v.GetString(param.ConfigBase.GetName())
	v.SetDefault(param.Server_TLSCACertificateFile.GetName(), filepath.Join(configDir, "certificates", "tlsca.pem"))
	return nil
}
