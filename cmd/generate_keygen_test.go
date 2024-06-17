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
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

// Create tmpdir, change cwd, and setup clean up functions
func setupTestRun(t *testing.T) string {
	config.ResetIssuerJWKPtr()
	wd, err := os.Getwd()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := os.Chdir(wd)
		require.NoError(t, err)
		viper.Reset()
		config.ResetIssuerJWKPtr()
	})
	return tmpDir
}

func checkKeys(t *testing.T, privateKey, publicKey string) {
	_, err := config.LoadPrivateKey(privateKey, false)
	require.NoError(t, err)

	jwks, err := jwk.ReadFile(publicKey)
	require.NoError(t, err)
	require.Equal(t, 1, jwks.Len())
	key, ok := jwks.Key(0)
	assert.True(t, ok)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestKeygenMain(t *testing.T) {
	config.ResetIssuerJWKPtr()

	t.Cleanup(func() {
		viper.Reset()
		config.ResetIssuerJWKPtr()
	})

	t.Run("no-args-gen-to-wd", func(t *testing.T) {
		tempDir := setupTestRun(t)

		privateKeyPath = ""
		publicKeyPath = ""
		err := keygenMain(nil, []string{})
		require.NoError(t, err)

		checkKeys(
			t,
			filepath.Join(tempDir, "issuer.jwk"),
			filepath.Join(tempDir, "issuer-pub.jwks"),
		)
	})

	t.Run("private-arg-present", func(t *testing.T) {
		tempWd := setupTestRun(t)
		tmpDir := filepath.Join(tempWd, "tmp")

		privateKeyPath = filepath.Join(tmpDir, "test.pk")
		publicKeyPath = ""
		err := keygenMain(nil, []string{})
		require.NoError(t, err)

		checkKeys(
			t,
			privateKeyPath,
			filepath.Join(tempWd, "issuer-pub.jwks"),
		)
	})

	t.Run("public-arg-present", func(t *testing.T) {
		tempWd := setupTestRun(t)
		tmpDir := filepath.Join(tempWd, "tmp")

		privateKeyPath = ""
		publicKeyPath = filepath.Join(tmpDir, "test.pub")
		err := keygenMain(nil, []string{})
		require.NoError(t, err)

		checkKeys(
			t,
			filepath.Join(tempWd, "issuer.jwk"),
			publicKeyPath,
		)
	})

	t.Run("private-arg-with-newline", func(t *testing.T) {
		tempWd := setupTestRun(t)
		tmpDir := filepath.Join(tempWd, "tmp")

		privateKeyPath = filepath.Join(tmpDir, "test.pk")
		privateKeyPath += "\n"
		publicKeyPath = ""
		err := keygenMain(nil, []string{})
		require.NoError(t, err)

		checkKeys(
			t,
			privateKeyPath,
			filepath.Join(tempWd, "issuer-pub.jwks"),
		)
	})

	t.Run("public-arg-with-newline", func(t *testing.T) {
		tempWd := setupTestRun(t)
		tmpDir := filepath.Join(tempWd, "tmp")

		privateKeyPath = ""
		publicKeyPath = filepath.Join(tmpDir, "test.pub")
		publicKeyPath += "\n"
		err := keygenMain(nil, []string{})
		require.NoError(t, err)

		checkKeys(
			t,
			filepath.Join(tempWd, "issuer.jwk"),
			publicKeyPath,
		)
	})

	t.Run("private-key-exists", func(t *testing.T) {
		tempDir := t.TempDir()

		err := os.WriteFile(filepath.Join(tempDir, "test.pk"), []byte{}, 0644)
		require.NoError(t, err)
		privateKeyPath = filepath.Join(tempDir, "test.pk")
		publicKeyPath = filepath.Join(tempDir, "test.pub")
		err = keygenMain(nil, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file exists")
	})

	t.Run("public-key-exists", func(t *testing.T) {
		tempDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tempDir, "test.pub"), []byte{}, 0644)
		require.NoError(t, err)
		privateKeyPath = filepath.Join(tempDir, "test.pk")
		publicKeyPath = filepath.Join(tempDir, "test.pub")
		err = keygenMain(nil, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file exists")
	})
}
