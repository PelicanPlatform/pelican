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
	"github.com/spf13/cobra"
)

var (
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate credentials for Pelican server",
		Long:  "",
	}

	passwordCmd = &cobra.Command{
		Use:   "password",
		Short: "Generate a Pelican admin website password file (htpasswd)",
		Long: `Given a password for the admin website, generate the htpasswd file that Pelican server
uses to store the password and authenticate the admin user. You may put the generated file under
/etc/pelican with name "server-web-passwd", or change Server.UIPasswordFile
to the path to generated file to initialize the admin website.
`,
		RunE:         passwordMain,
		SilenceUsage: true,
	}

	keygenCmd = &cobra.Command{
		Use:   "keygen",
		Short: "Generate a public-private key-pair for Pelican OIDC issuer",
		Long: `Generate a public-private key-pair for a Pelican server.
The private key is a ECDSA key with P256 curve. The corresponding public key
is a JWKS in JSON. The public key follows OIDC protocol and can be used
for JWT signature verification.
		`,
		RunE:         keygenMain,
		SilenceUsage: true,
	}

	outPasswordPath string
	inPasswordPath  string

	privateKeyPath string
	publicKeyPath  string
)

func init() {
	generateCmd.AddCommand(keygenCmd, passwordCmd)

	passwordCmd.Flags().StringVarP(&outPasswordPath, "output", "o", "", "The path to the generate htpasswd password file. Default: ./server-web-passwd")
	passwordCmd.Flags().StringVarP(&inPasswordPath, "password", "p", "", "The path to the file containing the password. Will take from terminal input if not provided")

	keygenCmd.Flags().StringVar(&privateKeyPath, "private-key", "", "The path to the generate private key file. Default: ./issuer.jwk")
	keygenCmd.Flags().StringVar(&publicKeyPath, "public-key", "", "The path to the generate public key file. Default: ./issuer-pub.jwks")
}
