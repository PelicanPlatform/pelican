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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tg123/go-htpasswd"
)

var (
	keygenCmd = &cobra.Command{
		Use:   "keygen",
		Short: "Generate a public-private key-pair for Pelican issuer",
		Long: `Generate a public-private key-pair for a Pelican server.
The private key is a ECDSA key with P256 curve. The corresponding public key
is a JWKS in JSON. The public key follows OIDC protocol and can be used
for JWT signature verification.
		`,
		RunE: keygenMain,
	}
	outPath          string // The output path for the generated public key
	genAdminPassword bool
	password         string
)

func init() {
	keygenCmd.Flags().StringVarP(&outPath, "output", "o", "", "The path to the generated keys. By default it's the current working directory")
	keygenCmd.Flags().BoolVarP(&genAdminPassword, "admin-password", "a", false, "Generate the password file (htpasswd) for the admin website")
	keygenCmd.Flags().StringVarP(&password, "password", "p", "", "The admin password to be added to the password file (required with --admin-password flag)")
}

func handlePassword() error {
	if password == "" {
		return errors.New("--password is required")
	}
	passwordFile := filepath.Join(outPath, "server-web-passwd")
	viper.Set(param.Server_UIPasswordFile.GetName(), passwordFile)
	file, err := os.OpenFile(passwordFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	file.Close()

	_, err = htpasswd.New(passwordFile, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	if err != nil {
		return err
	}
	err = web_ui.WritePasswordEntry("admin", password)
	if err != nil {
		return errors.Wrap(err, "failed to write password to the file")
	}
	fmt.Printf("Successfully generated the admin password file at: %s\n", passwordFile)
	return nil
}

func handleKeyGen() error {
	privKeyPath := filepath.Join(outPath, "issuer.jwk")
	pubKeyPath := filepath.Join(outPath, "issuer-pub.jwks")
	viper.Set(param.IssuerKey.GetName(), privKeyPath)

	// GetIssuerPublicJWKS will generate the private key at IssuerKey if it does not exist
	// and parse the private key and generate the corresponding public key for us
	pubkey, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(pubkey, "", "	")
	if err != nil {
		return errors.Wrap(err, "failed to generate json from jwks")
	}
	output, err := os.OpenFile(pubKeyPath, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return errors.Wrap(err, "failed to open the file for the generated public key")
	}
	defer output.Close()
	if _, err := output.Write(bytes); err != nil {
		return errors.Wrap(err, "fail to write the public key to the file")
	}
	fmt.Printf("Successfully generated keys at: \nPrivate key: %s\nPublic Key: %s\n", privKeyPath, pubKeyPath)
	return nil
}

func keygenMain(cmd *cobra.Command, args []string) error {
	if outPath == "" {
		wd, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve the current working directory")
		}
		outPath = wd
	}
	err := os.MkdirAll(outPath, 0750)
	if err != nil {
		return errors.Wrapf(err, "failed to create output directory at %s", outPath)
	}
	if genAdminPassword {
		return handlePassword()
	} else {
		return handleKeyGen()
	}
}
