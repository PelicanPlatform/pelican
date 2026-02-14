/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package local_cache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"

	"github.com/pelicanplatform/pelican/config"
)

const (
	masterKeyFileName = "masterkey.json"
)

// EncryptionManager handles all encryption operations for the cache
type EncryptionManager struct {
	masterKey []byte
	baseDir   string
	mu        sync.RWMutex
}

// NewEncryptionManager creates a new encryption manager
// It loads or creates the master key from the specified directory.
//
// Requires issuer keys to be initialized via config.GetIssuerPublicJWKS() or
// InitIssuerKeyForTests() before calling this function.
func NewEncryptionManager(baseDir string) (*EncryptionManager, error) {
	em := &EncryptionManager{
		baseDir: baseDir,
	}

	// Try to load existing master key or create new one
	if err := em.loadOrCreateMasterKey(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption manager")
	}

	return em, nil
}

// loadOrCreateMasterKey loads the master key from disk or creates a new one
func (em *EncryptionManager) loadOrCreateMasterKey() error {
	keyPath := filepath.Join(em.baseDir, masterKeyFileName)

	// Check if master key file exists
	if data, err := os.ReadFile(keyPath); err == nil {
		// Try to load existing key
		key, err := em.decryptMasterKey(data)
		if err == nil {
			em.masterKey = key
			log.Debug("Loaded existing master key from disk")
			return nil
		}
		log.Warnf("Failed to decrypt existing master key: %v, will create new one", err)
	}

	// Create new master key
	em.masterKey = make([]byte, KeySize)
	if _, err := rand.Read(em.masterKey); err != nil {
		return errors.Wrap(err, "failed to generate master key")
	}

	// Save encrypted master key
	if err := em.saveMasterKey(); err != nil {
		return errors.Wrap(err, "failed to save master key")
	}

	log.Debug("Created and saved new master key")
	return nil
}

// decryptMasterKey decrypts the master key using available issuer private keys
func (em *EncryptionManager) decryptMasterKey(data []byte) ([]byte, error) {
	var keyFile MasterKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, errors.Wrap(err, "failed to parse master key file")
	}

	issuerKeys := config.GetIssuerPrivateKeys()
	if len(issuerKeys) == 0 {
		return nil, errors.New("no issuer private keys available")
	}

	// Try each issuer key to decrypt
	for kid, privKey := range issuerKeys {
		encryptedKey, exists := keyFile.Keys[kid]
		if !exists {
			continue
		}

		decrypted, err := decryptWithJWK(privKey, encryptedKey)
		if err != nil {
			log.Debugf("Failed to decrypt master key with key %s: %v", kid, err)
			continue
		}

		return decrypted, nil
	}

	return nil, errors.New("no issuer key could decrypt the master key")
}

// saveMasterKey encrypts and saves the master key to disk
func (em *EncryptionManager) saveMasterKey() error {
	issuerKeys := config.GetIssuerPrivateKeys()
	if len(issuerKeys) == 0 {
		return errors.New("no issuer private keys available to encrypt master key")
	}

	keyFile := MasterKeyFile{
		Keys: make(map[string][]byte),
	}

	// Encrypt master key with each issuer key
	for kid, privKey := range issuerKeys {
		encrypted, err := encryptWithJWK(privKey, em.masterKey)
		if err != nil {
			log.Warnf("Failed to encrypt master key with key %s: %v", kid, err)
			continue
		}
		keyFile.Keys[kid] = encrypted
	}

	if len(keyFile.Keys) == 0 {
		return errors.New("failed to encrypt master key with any issuer key")
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal master key file")
	}

	// Write atomically using temp file
	keyPath := filepath.Join(em.baseDir, masterKeyFileName)
	tmpPath := keyPath + ".tmp"

	// Write to temp file and sync to disk before rename to avoid corruption
	tmpFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to create temporary master key file")
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return errors.Wrap(err, "failed to write temporary master key file")
	}

	// Explicitly sync to ensure data is persisted before rename
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return errors.Wrap(err, "failed to sync temporary master key file")
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.Wrap(err, "failed to close temporary master key file")
	}

	if err := os.Rename(tmpPath, keyPath); err != nil {
		os.Remove(tmpPath)
		return errors.Wrap(err, "failed to rename master key file")
	}

	return nil
}

// UpdateMasterKeyEncryption re-encrypts the master key with current issuer keys
// This should be called when issuer keys change
func (em *EncryptionManager) UpdateMasterKeyEncryption() error {
	em.mu.Lock()
	defer em.mu.Unlock()

	return em.saveMasterKey()
}

// DeriveDBKey derives a separate encryption key for BadgerDB using HKDF.
// This ensures proper key separation: the master key encrypts data blocks,
// while this derived key encrypts BadgerDB's LSM tree and WAL files
// (protecting metadata such as ETags, URLs, and timestamps at rest).
func (em *EncryptionManager) DeriveDBKey() ([]byte, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	hkdfReader := hkdf.New(sha256.New, em.masterKey, nil, []byte("pelican-cache-badgerdb-encryption"))
	dbKey := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, dbKey); err != nil {
		return nil, errors.Wrap(err, "failed to derive BadgerDB encryption key")
	}
	return dbKey, nil
}

// GenerateDataKey generates a new random data encryption key (DEK)
func (em *EncryptionManager) GenerateDataKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.Wrap(err, "failed to generate data key")
	}
	return key, nil
}

// GenerateNonce generates a new random nonce for AES-GCM
func (em *EncryptionManager) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}
	return nonce, nil
}

// EncryptDataKey encrypts a DEK using the master key
func (em *EncryptionManager) EncryptDataKey(dek []byte) ([]byte, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	block, err := aes.NewCipher(em.masterKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, dek, nil)
	return ciphertext, nil
}

// DecryptDataKey decrypts a DEK using the master key
func (em *EncryptionManager) DecryptDataKey(encryptedDEK []byte) ([]byte, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	block, err := aes.NewCipher(em.masterKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedDEK) < nonceSize {
		return nil, errors.New("encrypted DEK too short")
	}

	nonce, ciphertext := encryptedDEK[:nonceSize], encryptedDEK[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// BlockEncryptor handles encryption/decryption of individual blocks
type BlockEncryptor struct {
	gcm       cipher.AEAD
	baseNonce []byte
}

// NewBlockEncryptor creates a new block encryptor with the given DEK and base nonce
func NewBlockEncryptor(dek, baseNonce []byte) (*BlockEncryptor, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	if len(baseNonce) != NonceSize {
		return nil, errors.Errorf("invalid nonce size: got %d, want %d", len(baseNonce), NonceSize)
	}

	return &BlockEncryptor{
		gcm:       gcm,
		baseNonce: baseNonce,
	}, nil
}

// blockNonce derives a unique nonce for a specific block
// We XOR the block number into the base nonce to get unique per-block nonces
func (be *BlockEncryptor) blockNonce(blockNum uint32) []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, be.baseNonce)

	// XOR block number into the last 4 bytes of the nonce
	blockBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(blockBytes, blockNum)
	for i := 0; i < 4; i++ {
		nonce[NonceSize-4+i] ^= blockBytes[i]
	}

	return nonce
}

// EncryptBlock encrypts a block of data and returns data + auth tag
// The input data must be exactly BlockDataSize bytes (or less for the last block)
// The output is BlockTotalSize bytes (data + 16 byte auth tag)
func (be *BlockEncryptor) EncryptBlock(blockNum uint32, data []byte) ([]byte, error) {
	if len(data) > BlockDataSize {
		return nil, errors.Errorf("block data too large: %d > %d", len(data), BlockDataSize)
	}

	nonce := be.blockNonce(blockNum)

	// Encrypt and append auth tag
	// The result is ciphertext || tag
	return be.gcm.Seal(nil, nonce, data, nil), nil
}

// DecryptBlock decrypts a block and verifies its authentication tag
// Input is BlockTotalSize bytes (ciphertext + auth tag)
// Returns the decrypted data (up to BlockDataSize bytes)
func (be *BlockEncryptor) DecryptBlock(blockNum uint32, encryptedBlock []byte) ([]byte, error) {
	nonce := be.blockNonce(blockNum)

	return be.gcm.Open(nil, nonce, encryptedBlock, nil)
}

// EncryptInline encrypts data for inline storage (small objects)
func (em *EncryptionManager) EncryptInline(data, dek, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	return gcm.Seal(nil, nonce, data, nil), nil
}

// DecryptInline decrypts inline data (small objects)
func (em *EncryptionManager) DecryptInline(encryptedData, dek, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	return gcm.Open(nil, nonce, encryptedData, nil)
}

// encryptWithJWK encrypts data using a JWK private key (using its public key)
func encryptWithJWK(key jwk.Key, data []byte) ([]byte, error) {
	var rawKey any
	if err := key.Raw(&rawKey); err != nil {
		return nil, errors.Wrap(err, "failed to get raw key")
	}

	switch k := rawKey.(type) {
	case *ecdsa.PrivateKey:
		return encryptWithECDSA(&k.PublicKey, data)
	case *rsa.PrivateKey:
		return encryptWithRSA(&k.PublicKey, data)
	default:
		return nil, errors.Errorf("unsupported key type: %T", rawKey)
	}
}

// decryptWithJWK decrypts data using a JWK private key
func decryptWithJWK(key jwk.Key, data []byte) ([]byte, error) {
	var rawKey any
	if err := key.Raw(&rawKey); err != nil {
		return nil, errors.Wrap(err, "failed to get raw key")
	}

	switch k := rawKey.(type) {
	case *ecdsa.PrivateKey:
		return decryptWithECDSA(k, data)
	case *rsa.PrivateKey:
		return decryptWithRSA(k, data)
	default:
		return nil, errors.Errorf("unsupported key type: %T", rawKey)
	}
}

// encryptWithRSA encrypts data using RSA-OAEP
func encryptWithRSA(pubKey *rsa.PublicKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, pubKey, data, nil)
}

// decryptWithRSA decrypts data using RSA-OAEP
func decryptWithRSA(privKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, privKey, data, nil)
}

// For ECDSA, we use ECIES (Elliptic Curve Integrated Encryption Scheme)
// This is a hybrid encryption scheme that uses ECDH for key agreement
// and AES-GCM for symmetric encryption

// encryptWithECDSA encrypts data using ECIES with the public key
func encryptWithECDSA(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	// Generate ephemeral key pair
	ephemeralKey, err := ecdsa.GenerateKey(pubKey.Curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ephemeral key")
	}

	// Perform ECDH
	sharedX, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, ephemeralKey.D.Bytes())

	// Derive symmetric key using SHA256
	sharedKey := sha256.Sum256(sharedX.Bytes())

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	// Serialize ephemeral public key
	ephemeralPubBytes := ellipticPointToBytes(ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y, pubKey.Curve.Params().BitSize)

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Return: ephemeral_pub_key || ciphertext
	result := make([]byte, len(ephemeralPubBytes)+len(ciphertext))
	copy(result, ephemeralPubBytes)
	copy(result[len(ephemeralPubBytes):], ciphertext)

	return result, nil
}

// decryptWithECDSA decrypts data using ECIES with the private key
func decryptWithECDSA(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	curve := privKey.Curve
	keySize := (curve.Params().BitSize + 7) / 8

	// Ephemeral public key is 2*keySize bytes (uncompressed point)
	ephemeralPubSize := 2 * keySize
	if len(data) < ephemeralPubSize+NonceSize+AuthTagSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract ephemeral public key
	ephemeralX, ephemeralY := bytesToEllipticPoint(data[:ephemeralPubSize], keySize)

	// Perform ECDH
	sharedX, _ := curve.ScalarMult(ephemeralX, ephemeralY, privKey.D.Bytes())

	// Derive symmetric key
	sharedKey := sha256.Sum256(sharedX.Bytes())

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	ciphertext := data[ephemeralPubSize:]
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short for nonce")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Helper functions for elliptic curve point serialization
func ellipticPointToBytes(x, y *big.Int, bitSize int) []byte {
	keySize := (bitSize + 7) / 8
	result := make([]byte, 2*keySize)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(result[keySize-len(xBytes):keySize], xBytes)
	copy(result[2*keySize-len(yBytes):], yBytes)
	return result
}

func bytesToEllipticPoint(data []byte, keySize int) (x, y *big.Int) {
	if len(data) != 2*keySize {
		return nil, nil
	}

	x = new(big.Int).SetBytes(data[:keySize])
	y = new(big.Int).SetBytes(data[keySize:])
	return x, y
}
