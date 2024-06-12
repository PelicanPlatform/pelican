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
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetSecret(t *testing.T) {
	viper.Reset()

	t.Cleanup(func() {
		viper.Reset()
	})
	t.Run("generate-32B-hash", func(t *testing.T) {
		tmp := t.TempDir()
		keyName := filepath.Join(tmp, "issuer.key")
		viper.Set(param.IssuerKey.GetName(), keyName)

		get, err := GetSecret()
		require.NoError(t, err)
		assert.Len(t, get, 32)
	})
}

func TestEncryptString(t *testing.T) {
	viper.Reset()

	t.Cleanup(func() {
		viper.Reset()
	})

	t.Run("encrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyName := filepath.Join(tmp, "issuer.key")
		viper.Set(param.IssuerKey.GetName(), keyName)

		get, err := EncryptString("Some secret to encrypt")
		require.NoError(t, err)
		assert.NotEmpty(t, get)
	})
}

func TestDecryptString(t *testing.T) {
	viper.Reset()

	t.Cleanup(func() {
		viper.Reset()
	})
	t.Run("decrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyName := filepath.Join(tmp, "issuer.key")
		viper.Set(param.IssuerKey.GetName(), keyName)

		secret := "Some secret to encrypt"

		getEncrypt, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, getEncrypt)

		getDecrypt, err := DecryptString(getEncrypt)
		require.NoError(t, err)
		assert.Equal(t, secret, getDecrypt)
	})

	t.Run("diff-secrets-yield-diff-result", func(t *testing.T) {
		tmp := t.TempDir()
		keyName := filepath.Join(tmp, "issuer.key")
		viper.Set(param.IssuerKey.GetName(), keyName)

		secret := "Some secret to encrypt"

		getEncrypt, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, getEncrypt)

		newKeyName := filepath.Join(tmp, "new-issuer.key")
		viper.Set(param.IssuerKey.GetName(), newKeyName)

		getDecrypt, err := DecryptString(getEncrypt)
		require.NoError(t, err)
		assert.NotEqual(t, secret, getDecrypt)
	})
}
