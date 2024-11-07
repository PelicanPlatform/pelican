//go:build !linux

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
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

func InitServerOSDefaults(v *viper.Viper) error {
	// Windows / Mac don't have a default set of CAs installed at
	// a well-known location as is expected by XRootD. We want to always generate our own CA
	// if Server_TLSCertificate (host certificate) is not explicitly set so that
	// we can sign our host cert by our CA instead of self-signing
	tlscaFile := filepath.Join(v.GetString("ConfigDir"), "certificates", "tlsca.pem")
	v.SetDefault(param.Server_TLSCACertificateFile.GetName(), tlscaFile)

	tlscaKeyFile := filepath.Join(v.GetString("ConfigDir"), "certificates", "tlscakey.pem")
	v.SetDefault(param.Server_TLSCAKey.GetName(), tlscaKeyFile)

	if err := os.MkdirAll(filepath.Dir(tlscaFile), 0755); err != nil {
		return err
	}

	// Note: creating an empty file is insufficient for XRootD
	/*
		fp, err := os.OpenFile(tlscaFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer fp.Close()
	*/
	return nil
}
