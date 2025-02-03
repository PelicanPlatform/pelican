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
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

func createJWKS(privKey crypto.PrivateKey) (jwk.Set, error) {
	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate JWK from private key")
	}
	jwks := jwk.NewSet()

	pkey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate public key from key %s", key.KeyID())
	}

	if err = jwks.AddKey(pkey); err != nil {
		return nil, errors.Wrapf(err, "Failed to add public key %s to new JWKS", key.KeyID())
	}

	return jwks, nil
}

func keygenMain(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "failed to get the current working directory")
	}
	if privateKeyPath == "" {
		privateKeyPath = filepath.Join(wd, "issuer.jwk")
	} else {
		privateKeyPath = filepath.Clean(strings.TrimSpace(privateKeyPath))
	}

	if err = os.MkdirAll(filepath.Dir(privateKeyPath), 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory for private key at %s", filepath.Dir(privateKeyPath))
	}

	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(wd, "issuer-pub.jwks")
	} else {
		publicKeyPath = filepath.Clean(strings.TrimSpace(publicKeyPath))
	}

	if err = os.MkdirAll(filepath.Dir(publicKeyPath), 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory for public key at %s", filepath.Dir(publicKeyPath))
	}

	_, err = os.Stat(privateKeyPath)
	if err == nil {
		return fmt.Errorf("file exists for private key under %s", privateKeyPath)
	}

	_, err = os.Stat(publicKeyPath)
	if err == nil {
		return fmt.Errorf("file exists for public key under %s", publicKeyPath)
	}

	if err := config.GeneratePrivateKey(privateKeyPath, elliptic.P256(), false); err != nil {
		return errors.Wrapf(err, "failed to generate new private key at %s", privateKeyPath)
	}
	privKey, err := config.LoadPrivateKey(privateKeyPath, false)
	if err != nil {
		return errors.Wrapf(err, "failed to load private key from %s", privateKeyPath)
	}

	pubJWKS, err := createJWKS(privKey)
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(pubJWKS, "", "	")
	if err != nil {
		return errors.Wrap(err, "failed to generate json from jwks")
	}
	if err = os.WriteFile(publicKeyPath, bytes, 0644); err != nil {
		return errors.Wrap(err, "fail to write the public key to the file")
	}
	fmt.Printf("Successfully generated keys at: \nPrivate key: %s\nPublic Key: %s\n", privateKeyPath, publicKeyPath)
	return nil
}
