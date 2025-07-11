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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encrypt should be ecdsa|rsa
// keyFormat should be pkcs1|pkcs8
func generatePrivateKey(keyLocation string, encrypt string, keyFormat string) error {
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, "Failed to create new private key file")
	}
	defer file.Close()
	if encrypt == "ecdsa" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		bytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		priv_block := pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
		if err = pem.Encode(file, &priv_block); err != nil {
			return err
		}
	} else if encrypt == "rsa" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		if keyFormat == "pkcs8" {
			bytes, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				return err
			}
			priv_block := pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
			if err = pem.Encode(file, &priv_block); err != nil {
				return err
			}
		} else if keyFormat == "pkcs1" {
			bytes := x509.MarshalPKCS1PrivateKey(priv)
			priv_block := pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes}
			if err = pem.Encode(file, &priv_block); err != nil {
				return err
			}
		} else {
			return errors.Errorf("unsupported key format: %s", keyFormat)
		}
	} else {
		return errors.Errorf("unsupported encrypt: %s", encrypt)
	}
	return nil
}

func TestLoadPrivateKey(t *testing.T) {
	t.Run("ecdsa-key", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "ecdsa.key")
		err := generatePrivateKey(keyLocation, "ecdsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *ecdsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs8-key-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, true)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *rsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs1-key-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs1")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, true)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *rsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs1-key-not-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs1")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RSA type private key is not allowed for")
		require.Nil(t, privateKey)
	})

	t.Run("rsa-pkcs8-key-not-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RSA type private key in PKCS #8 form is not allowed for")
		require.Nil(t, privateKey)
	})
}

func TestMultiPrivateKey(t *testing.T) {
	t.Run("generate-and-load-single-key", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")

		key, err := loadIssuerPrivateKey(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("second-private-key", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")

		key, err := loadIssuerPrivateKey(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, key)

		// Create another private key
		secondKey, err := generatePEMandSetIssuerKey(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, secondKey)
		assert.NotEqual(t, key.KeyID(), secondKey.KeyID())

		// Check if the active private key points to the latest key
		latestKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		assert.Equal(t, secondKey.KeyID(), latestKey.KeyID())
	})

	// Inmitating private key rotation
	// See if the second key becomes the "current key" after the first key is removed
	t.Run("remove-first-key", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")

		// Generate three keys
		keys := []string{}
		for i := 0; i < 3; i++ {
			key, err := GeneratePEM(issuerKeysDir)
			require.NoError(t, err)
			keys = append(keys, key.KeyID())
		}

		// Load keys and verify the first key is the current key
		firstKey, err := loadPEMFiles(issuerKeysDir)
		require.NoError(t, err)
		assert.Equal(t, keys[0], firstKey.KeyID())

		// Remove the first key file
		firstKeyFile := filepath.Join(issuerKeysDir, "pelican_generated_*")
		firstKeyFiles, err := filepath.Glob(firstKeyFile)
		require.NoError(t, err)
		err = os.Remove(firstKeyFiles[0])
		require.NoError(t, err)

		// Reload keys and verify the second key is now the current key
		secondKey, err := loadPEMFiles(issuerKeysDir)
		require.NoError(t, err)
		assert.Equal(t, keys[1], secondKey.KeyID())

		allKeys := getIssuerPrivateKeysCopy()
		assert.Len(t, allKeys, 2)
	})
}

func TestSymlinkIssuerKeys(t *testing.T) {
	t.Run("load-symlinked-key", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")
		externalKeysDir := filepath.Join(tempDir, "external-keys")

		// Create directories
		err := os.MkdirAll(issuerKeysDir, 0750)
		require.NoError(t, err)
		err = os.MkdirAll(externalKeysDir, 0750)
		require.NoError(t, err)

		// Generate a key file outside the issuer keys directory
		externalKeyFile := filepath.Join(externalKeysDir, "external-key.pem")
		err = generatePrivateKey(externalKeyFile, "ecdsa", "pkcs8")
		require.NoError(t, err)

		// Load the external key to get its expected key ID
		expectedKey, err := LoadSinglePEM(externalKeyFile)
		require.NoError(t, err)

		// Create a symlink in the issuer keys directory pointing to the external key
		symlinkPath := filepath.Join(issuerKeysDir, "symlinked-key.pem")
		err = os.Symlink(externalKeyFile, symlinkPath)
		require.NoError(t, err)

		// Load the key and verify it works
		currentKey, err := loadPEMFiles(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, currentKey)
		require.Equal(t, expectedKey.KeyID(), currentKey.KeyID())

		// Verify the key is loaded correctly
		allKeys := getIssuerPrivateKeysCopy()
		assert.Len(t, allKeys, 1)
		assert.Contains(t, allKeys, expectedKey.KeyID())
	})

	t.Run("mixed-regular-and-symlinked-keys", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")
		externalKeysDir := filepath.Join(tempDir, "external-keys")

		// Create directories
		err := os.MkdirAll(issuerKeysDir, 0750)
		require.NoError(t, err)
		err = os.MkdirAll(externalKeysDir, 0750)
		require.NoError(t, err)

		// Generate a regular key file in the issuer keys directory
		regularKeyFile := filepath.Join(issuerKeysDir, "regular-key.pem")
		err = generatePrivateKey(regularKeyFile, "ecdsa", "pkcs8")
		require.NoError(t, err)

		// Generate a key file outside the issuer keys directory
		externalKeyFile := filepath.Join(externalKeysDir, "external-key.pem")
		err = generatePrivateKey(externalKeyFile, "ecdsa", "pkcs8")
		require.NoError(t, err)

		// Create a symlink in the issuer keys directory pointing to the external key
		symlinkPath := filepath.Join(issuerKeysDir, "symlinked-key.pem")
		err = os.Symlink(externalKeyFile, symlinkPath)
		require.NoError(t, err)

		// Load the keys and verify both are loaded
		key, err := loadPEMFiles(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, key)

		// Verify both keys are loaded
		allKeys := getIssuerPrivateKeysCopy()
		assert.Len(t, allKeys, 2)

		// Verify the current key is the one with the lexicographically first filename
		// "regular-key.pem" should come before "symlinked-key.pem"
		assert.Equal(t, "regular-key.pem", filepath.Base(regularKeyFile))
		assert.Equal(t, "symlinked-key.pem", filepath.Base(symlinkPath))
	})

	t.Run("broken-symlink-should-be-skipped", func(t *testing.T) {
		ResetConfig()
		defer ResetConfig()
		tempDir := t.TempDir()
		issuerKeysDir := filepath.Join(tempDir, "issuer-keys")

		// Create directory
		err := os.MkdirAll(issuerKeysDir, 0750)
		require.NoError(t, err)

		// Create a symlink pointing to a non-existent file
		brokenSymlinkPath := filepath.Join(issuerKeysDir, "broken-symlink.pem")
		err = os.Symlink("/non/existent/path/key.pem", brokenSymlinkPath)
		require.NoError(t, err)

		// Generate a valid key file
		validKeyFile := filepath.Join(issuerKeysDir, "valid-key.pem")
		err = generatePrivateKey(validKeyFile, "ecdsa", "pkcs8")
		require.NoError(t, err)

		// Load the keys - should skip the broken symlink and load the valid key
		key, err := loadPEMFiles(issuerKeysDir)
		require.NoError(t, err)
		require.NotNil(t, key)

		// Verify only the valid key is loaded
		allKeys := getIssuerPrivateKeysCopy()
		assert.Len(t, allKeys, 1)
		assert.Contains(t, allKeys, key.KeyID())
	})
}
