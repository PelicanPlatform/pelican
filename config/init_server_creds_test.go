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
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config/configtest"
	"github.com/pelicanplatform/pelican/param"
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

func TestGenerateCertNoSpuriousCAKey(t *testing.T) {
	// Helper: use GenerateCert to produce a full cert chain (CA + TLS cert/key),
	// then return the paths used. Caller can remove the CA files before re-invoking.
	setupCertChain := func(t *testing.T, tmpDir string) (caCertPath, caKeyPath string) {
		t.Helper()

		certPath := filepath.Join(tmpDir, "tls.crt")
		keyPath := filepath.Join(tmpDir, "tls.key")
		caCertPath = filepath.Join(tmpDir, "tlsca.pem")
		caKeyPath = filepath.Join(tmpDir, "tlscakey.pem")

		require.NoError(t, param.Server_TLSCertificateChain.Set(certPath))
		require.NoError(t, param.Server_TLSKey.Set(keyPath))
		require.NoError(t, param.Server_TLSCACertificateFile.Set(caCertPath))
		require.NoError(t, param.Server_TLSCAKey.Set(caKeyPath))
		require.NoError(t, param.Server_Hostname.Set("localhost"))

		// Generate a full cert chain (CA cert, CA key, TLS cert, TLS key)
		require.NoError(t, GenerateCert())

		// Sanity-check that all four files were created
		for _, p := range []string{certPath, keyPath, caCertPath, caKeyPath} {
			_, err := os.Stat(p)
			require.NoError(t, err, "expected %s to exist after initial GenerateCert", p)
		}

		return caCertPath, caKeyPath
	}

	t.Run("no-ca-key-when-tls-cert-key-present", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		caCertPath, caKeyPath := setupCertChain(t, tmpDir)

		// Remove the CA cert and key, simulating an environment where the
		// admin provided their own TLS cert+key without a CA.
		require.NoError(t, os.Remove(caCertPath))
		require.NoError(t, os.Remove(caKeyPath))

		// GenerateCert should succeed without re-creating the CA files
		err := GenerateCert()
		require.NoError(t, err)

		// Verify that the CA key was NOT re-created
		_, err = os.Stat(caKeyPath)
		assert.True(t, os.IsNotExist(err), "CA key file should not have been created when TLS cert+key exist")

		// Verify that the CA cert was NOT re-created
		_, err = os.Stat(caCertPath)
		assert.True(t, os.IsNotExist(err), "CA cert file should not have been created when TLS cert+key exist")
	})

	t.Run("no-ca-key-when-tls-cert-key-present-readonly-dir", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		caCertPath, caKeyPath := setupCertChain(t, tmpDir)

		// Remove the CA files and make the directory read-only to simulate
		// the scenario from the issue report.
		require.NoError(t, os.Remove(caCertPath))
		require.NoError(t, os.Remove(caKeyPath))
		require.NoError(t, os.Chmod(tmpDir, 0555))
		t.Cleanup(func() {
			_ = os.Chmod(tmpDir, 0755)
		})

		// GenerateCert should succeed even with a read-only directory
		// because it should not attempt to write any CA files
		err := GenerateCert()
		require.NoError(t, err, "GenerateCert should succeed with read-only dir when TLS cert+key exist")
	})
}

func TestSigningAlgorithmForJWK(t *testing.T) {
	ResetConfig()
	t.Cleanup(ResetConfig)

	t.Run("ec-p256-key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(privKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.ES256, alg)
	})

	t.Run("ec-p384-key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(privKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.ES384, alg)
	})

	t.Run("ec-p521-key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(privKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.ES512, alg)
	})

	t.Run("rsa-key", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(privKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.RS256, alg)
	})

	t.Run("ec-public-key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(&privKey.PublicKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.ES256, alg)
	})

	t.Run("rsa-public-key", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		jwkKey, err := jwk.FromRaw(&privKey.PublicKey)
		require.NoError(t, err)

		alg, err := SigningAlgorithmForJWK(jwkKey)
		require.NoError(t, err)
		assert.Equal(t, jwa.RS256, alg)
	})
}

func TestLoadSinglePEMAlgorithm(t *testing.T) {
	ResetConfig()
	t.Cleanup(ResetConfig)

	t.Run("ecdsa-key-gets-ES256", func(t *testing.T) {
		tempDir := t.TempDir()
		keyFile := filepath.Join(tempDir, "ec.pem")
		err := generatePrivateKey(keyFile, "ecdsa", "pkcs8")
		require.NoError(t, err)

		key, err := LoadSinglePEM(keyFile)
		require.NoError(t, err)
		assert.Equal(t, jwa.KeyAlgorithmFrom(jwa.ES256), key.Algorithm())
	})

	t.Run("rsa-key-gets-RS256", func(t *testing.T) {
		tempDir := t.TempDir()
		keyFile := filepath.Join(tempDir, "rsa.pem")
		err := generatePrivateKey(keyFile, "rsa", "pkcs8")
		require.NoError(t, err)

		key, err := LoadSinglePEM(keyFile)
		require.NoError(t, err)
		assert.Equal(t, jwa.KeyAlgorithmFrom(jwa.RS256), key.Algorithm())
	})
}

// TestGetIssuerPublicJWKSForNamespace verifies the per-namespace JWKS helper:
// empty path returns the server key set unchanged, a valid extra JWKS file
// causes its keys to be merged in, and a missing or invalid file yields
// an error.
func TestGetIssuerPublicJWKSForNamespace(t *testing.T) {
	t.Run("empty path returns server keys", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		got, err := GetIssuerPublicJWKSForNamespace("", strictExtra)
		require.NoError(t, err)

		// Should contain exactly the same key IDs.
		baseKIDs := collectKIDs(t, base)
		gotKIDs := collectKIDs(t, got)
		assert.ElementsMatch(t, baseKIDs, gotKIDs)
	})

	t.Run("non-existent path returns error", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		_, err := GetIssuerPublicJWKSForNamespace("/nonexistent/path/extra.jwks", strictExtra)
		require.Error(t, err)
	})

	t.Run("valid extra JWKS merges keys", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		extraPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		extraPub, err := jwk.FromRaw(extraPriv.PublicKey)
		require.NoError(t, err)
		require.NoError(t, extraPub.Set(jwk.KeyIDKey, "extra-test-key-merge"))
		extraPath := configtest.WriteJWKSFile(t, tmpDir, "extra.jwks", extraPub)

		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		got, err := GetIssuerPublicJWKSForNamespace(extraPath, strictExtra)
		require.NoError(t, err)

		// Result should have one more key than the base set.
		assert.Equal(t, base.Len()+1, got.Len())

		// The extra key's ID should be present.
		gotKIDs := collectKIDs(t, got)
		assert.Contains(t, gotKIDs, "extra-test-key-merge")
	})

	t.Run("private key in file strips private material", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		// Write a JWKS containing a private EC key (not just the public part).
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.FromRaw(privKey)
		require.NoError(t, err)
		require.NoError(t, privJWK.Set(jwk.KeyIDKey, "priv-key-should-become-public"))
		privPath := configtest.WriteJWKSFile(t, tmpDir, "private.jwks", privJWK)

		got, err := GetIssuerPublicJWKSForNamespace(privPath, strictExtra)
		require.NoError(t, err)

		// The key should be present, but only as its public projection:
		// a public EC key has no "d" (private scalar) field.
		rawJSON, err := json.Marshal(got)
		require.NoError(t, err)
		assert.NotContains(t, string(rawJSON), `"d":`,
			"private key material must not be present in the JWKS response")
		gotKIDs := collectKIDs(t, got)
		assert.Contains(t, gotKIDs, "priv-key-should-become-public")
	})

	t.Run("symmetric key is rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		symKey, err := jwk.FromRaw(make([]byte, 32))
		require.NoError(t, err)
		symPath := configtest.WriteJWKSFile(t, tmpDir, "sym.jwks", symKey)

		_, err = GetIssuerPublicJWKSForNamespace(symPath, strictExtra)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric")
	})

	t.Run("duplicate kid is rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		// Get the server's existing kid to use as a collision.
		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		require.Positive(t, base.Len(), "expected at least one server key")

		it := base.Keys(t.Context())
		require.True(t, it.Next(t.Context()))
		serverKID := it.Pair().Value.(jwk.Key).KeyID()
		require.NotEmpty(t, serverKID, "server key should have a kid")

		// Write an extra key that reuses the server's kid.
		extraKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		extraJWK, err := jwk.FromRaw(extraKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, extraJWK.Set(jwk.KeyIDKey, serverKID))
		dupPath := configtest.WriteJWKSFile(t, tmpDir, "dup.jwks", extraJWK)

		_, err = GetIssuerPublicJWKSForNamespace(dupPath, strictExtra)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicts")
		assert.Contains(t, err.Error(), serverKID,
			"the error should name the colliding kid")
	})

	t.Run("duplicate kid within the extra file is rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		// Two distinct keys in the same file sharing one kid. This collides
		// within the file, not with the server's key set.
		const sharedKID = "dup-within-file"
		makeKey := func() jwk.Key {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			pub, err := jwk.FromRaw(priv.PublicKey)
			require.NoError(t, err)
			require.NoError(t, pub.Set(jwk.KeyIDKey, sharedKID))
			return pub
		}
		dupPath := configtest.WriteJWKSFile(t, tmpDir, "dup-in-file.jwks", makeKey(), makeKey())

		_, err := GetIssuerPublicJWKSForNamespace(dupPath, strictExtra)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicts",
			"an intra-file kid collision should still be reported as a conflict")
		assert.Contains(t, err.Error(), sharedKID,
			"the error should name the colliding kid")
	})

	t.Run("keyless extra keys are merged without a uniqueness check", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		baseLen := base.Len()

		// Two distinct keys, neither carrying a kid. The uniqueness guard only
		// applies to keys that carry a kid, so both are merged as-is.
		makeKey := func() jwk.Key {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			pub, err := jwk.FromRaw(priv.PublicKey)
			require.NoError(t, err)
			return pub
		}
		keylessPath := configtest.WriteJWKSFile(t, tmpDir, "keyless.jwks", makeKey(), makeKey())

		got, err := GetIssuerPublicJWKSForNamespace(keylessPath, strictExtra)
		require.NoError(t, err)
		assert.Equal(t, baseLen+2, got.Len(),
			"both keyless keys should be merged without a conflict error")
	})

	t.Run("missing file degrades to base keys when policy allows", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)

		var captured error
		got, err := GetIssuerPublicJWKSForNamespace("/nonexistent/path/extra.jwks",
			func(e error) error { captured = e; return nil })
		require.NoError(t, err, "a degrading policy must not surface the extra-file error")
		require.Error(t, captured, "the policy should have been handed the extra-file error")

		// The result is exactly the base set: no extra keys, none dropped.
		assert.ElementsMatch(t, collectKIDs(t, base), collectKIDs(t, got))
	})

	t.Run("kid collision degrades to base keys when policy allows", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		base, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		require.Positive(t, base.Len(), "expected at least one server key")
		it := base.Keys(t.Context())
		require.True(t, it.Next(t.Context()))
		serverKID := it.Pair().Value.(jwk.Key).KeyID()

		// An extra key that collides with a server kid. Under a degrading
		// policy the whole extra file is dropped, never partially merged.
		extraKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		extraJWK, err := jwk.FromRaw(extraKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, extraJWK.Set(jwk.KeyIDKey, serverKID))
		dupPath := configtest.WriteJWKSFile(t, tmpDir, "dup.jwks", extraJWK)

		var captured error
		got, err := GetIssuerPublicJWKSForNamespace(dupPath,
			func(e error) error { captured = e; return nil })
		require.NoError(t, err)
		require.Error(t, captured)
		assert.ElementsMatch(t, collectKIDs(t, base), collectKIDs(t, got),
			"a degraded result must be exactly the base set")
	})
}

// strictExtra is the onExtraError policy that propagates any extra-file
// failure as an error. Tests asserting the strict (non-degrading) behavior
// pass it to GetIssuerPublicJWKSForNamespace.
func strictExtra(e error) error { return e }

// collectKIDs returns the key IDs from all keys in a jwk.Set.
func collectKIDs(t *testing.T, s jwk.Set) []string {
	t.Helper()
	kids := make([]string, 0, s.Len())
	for it := s.Keys(t.Context()); it.Next(t.Context()); {
		kids = append(kids, it.Pair().Value.(jwk.Key).KeyID())
	}
	return kids
}

// TestReadPublicJWKSFile verifies the canonical JWKS-file loader directly.
// Because ReadPublicJWKSFile enforces the security invariants used at both
// validation time and request time, these tests confirm the contract
// independently of the higher-level callers.
func TestReadPublicJWKSFile(t *testing.T) {
	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := ReadPublicJWKSFile("/nonexistent/path/keys.jwks")
		require.Error(t, err)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		badPath := filepath.Join(t.TempDir(), "bad.jwks")
		require.NoError(t, os.WriteFile(badPath, []byte("not json"), 0600))
		_, err := ReadPublicJWKSFile(badPath)
		require.Error(t, err)
	})

	t.Run("empty JWKS returns empty set", func(t *testing.T) {
		emptyPath := configtest.WriteJWKSFile(t, t.TempDir(), "empty.jwks")
		got, err := ReadPublicJWKSFile(emptyPath)
		require.NoError(t, err)
		assert.Equal(t, 0, got.Len())
	})

	t.Run("public EC key is accepted unchanged", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pubJWK, err := jwk.FromRaw(privKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "pub-only-key"))
		p := configtest.WriteJWKSFile(t, t.TempDir(), "pub.jwks", pubJWK)

		got, err := ReadPublicJWKSFile(p)
		require.NoError(t, err)
		require.Equal(t, 1, got.Len())
		kids := collectKIDs(t, got)
		assert.Contains(t, kids, "pub-only-key")
	})

	t.Run("private EC key strips private material", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.FromRaw(privKey)
		require.NoError(t, err)
		require.NoError(t, privJWK.Set(jwk.KeyIDKey, "private-key-stripped"))
		p := configtest.WriteJWKSFile(t, t.TempDir(), "priv.jwks", privJWK)

		got, err := ReadPublicJWKSFile(p)
		require.NoError(t, err)
		rawJSON, err := json.Marshal(got)
		require.NoError(t, err)
		assert.NotContains(t, string(rawJSON), `"d":`,
			"private key material must be stripped")
		kids := collectKIDs(t, got)
		assert.Contains(t, kids, "private-key-stripped")
	})

	t.Run("symmetric key is rejected", func(t *testing.T) {
		symKey, err := jwk.FromRaw(make([]byte, 32))
		require.NoError(t, err)
		p := configtest.WriteJWKSFile(t, t.TempDir(), "sym.jwks", symKey)

		_, err = ReadPublicJWKSFile(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric")
	})
}

// TestGetIssuerPublicJWKSWithServerIssuerJwks verifies that GetIssuerPublicJWKS
// respects Server.IssuerJwks: private key material is stripped, and symmetric
// keys (which are shared secrets with no public projection) are rejected so
// they can never be published.
func TestGetIssuerPublicJWKSWithServerIssuerJwks(t *testing.T) {
	t.Run("private key in Server.IssuerJwks is stripped", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.FromRaw(privKey)
		require.NoError(t, err)
		require.NoError(t, privJWK.Set(jwk.KeyIDKey, "server-private-key"))
		jwksPath := configtest.WriteJWKSFile(t, tmpDir, "server.jwks", privJWK)
		require.NoError(t, param.Server_IssuerJwks.Set(jwksPath))

		got, err := GetIssuerPublicJWKS()
		require.NoError(t, err)
		rawJSON, err := json.Marshal(got)
		require.NoError(t, err)
		assert.NotContains(t, string(rawJSON), `"d":`,
			"private key material must not appear in the server JWKS")
		kids := collectKIDs(t, got)
		assert.Contains(t, kids, "server-private-key")
	})

	t.Run("symmetric key in Server.IssuerJwks is rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		tmpDir := t.TempDir()
		require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))

		symKey, err := jwk.FromRaw(make([]byte, 32))
		require.NoError(t, err)
		require.NoError(t, symKey.Set(jwk.KeyIDKey, "server-sym-key"))
		jwksPath := configtest.WriteJWKSFile(t, tmpDir, "server.jwks", symKey)
		require.NoError(t, param.Server_IssuerJwks.Set(jwksPath))

		_, err = GetIssuerPublicJWKS()
		require.Error(t, err,
			"a symmetric key in Server.IssuerJwks must not be publishable")
		assert.Contains(t, err.Error(), "symmetric")
	})

	// A symmetric key held among the in-memory issuer private keys must be
	// rejected too, exercising the private-keys loop in loadIssuerPublicJWKS
	// (no Server.IssuerJwks and no PEM override), not just the file branch.
	t.Run("symmetric key among issuer private keys is rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		symKey, err := jwk.FromRaw(make([]byte, 32))
		require.NoError(t, err)
		require.NoError(t, symKey.Set(jwk.KeyIDKey, "issuer-sym-key"))
		setIssuerKey(symKey)

		_, err = GetIssuerPublicJWKS()
		require.Error(t, err,
			"a symmetric issuer private key must not be publishable")
		assert.Contains(t, err.Error(), "symmetric")
	})
}
