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

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateNonce generates a 32-byte random nonce and returns it as a hex-encoded string.
func GenerateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

// SignPayload signs the SHA-256 hash of the given payload using the provided ECDSA private key.
func SignPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(payload)
	signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifySignature verifies an ECDSA signature over the SHA-256 hash of the given payload.
func VerifySignature(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}
