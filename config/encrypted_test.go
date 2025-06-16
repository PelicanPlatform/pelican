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
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"os"

	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
)

func TestGetSecret(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})
	t.Run("generate-32B-hash", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		currentIssuerKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		get, err := GetSecret(currentIssuerKey)
		require.NoError(t, err)
		assert.Len(t, get, 32)
	})
}

func TestEncryptString(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("encrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		encrypted, err := EncryptString("Some secret to encrypt")
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		// Verify format is $KEYID.$NONCE.$MESSAGE
		parts := strings.Split(encrypted, ".")
		require.Len(t, parts, 3)
		assert.NotEmpty(t, parts[0]) // keyID
		assert.NotEmpty(t, parts[1]) // nonce
		assert.NotEmpty(t, parts[2]) // message
	})
}

func TestDecryptString(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("decrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := DecryptString(encrypted)
		require.NoError(t, err)
		assert.Equal(t, secret, decrypted)
	})

	t.Run("decrypt-with-another-valid-key", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)

		// Mock key rotation after encryption: change the key ID in the encrypted string
		parts := strings.Split(encrypted, ".")
		parts[0] = "another-valid-key-id"
		encrypted = strings.Join(parts, ".")

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		decrypted, err := DecryptString(encrypted)
		require.NoError(t, err)
		assert.Equal(t, secret, decrypted)
		assert.Contains(t, logOutput.String(), "The key used in encryption (id: another-valid-key-id) is not the current issuer key")
	})

	t.Run("decrypt-with-invalid-format", func(t *testing.T) {
		_, err := DecryptString("invalid.format")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid encrypted string format")
	})

	t.Run("decrypt-with-invalid-nonce", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)

		// Change the nonce in the encrypted string
		parts := strings.Split(encrypted, ".")
		parts[1] = "invalid-nonce"
		encrypted = strings.Join(parts, ".")

		_, err = DecryptString(encrypted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode nonce")
	})

	t.Run("decrypt-with-multiple-keys", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		// Encrypt with the first key
		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		// Simulate key rotation: add a new key to the issuer keys directory
		_, err = GeneratePEM(keyDir)
		require.NoError(t, err)

		keyChanged, err := RefreshKeys()
		require.NoError(t, err)
		assert.True(t, keyChanged)

		// Now DecryptString should still be able to decrypt using the old key
		decrypted, err := DecryptString(encrypted)
		require.NoError(t, err)
		assert.Equal(t, secret, decrypted)
	})
}
