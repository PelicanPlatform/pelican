//go:build linux

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

package config

import (
	"path/filepath"

	"github.com/spf13/viper"
)

func InitServerOSDefaults(v *viper.Viper) error {
	// For Linux, even if we have well-known system CAs, we don't want to
	// use them, because we want to always generate our own CA if Server_TLSCertificate (host certificate)
	// is not explicitly set so that we can sign our host cert by our CA instead of self-signing
	configDir := v.GetString("ConfigDir")
	v.SetDefault("Server.TLSCACertificateFile", filepath.Join(configDir, "certificates", "tlsca.pem"))
	return nil
}
