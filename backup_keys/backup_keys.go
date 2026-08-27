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

// Package backup_keys derives backup encryption keys from a server's issuer
// keys.
//
// Several subsystems back themselves up, and each one faces the same problem:
// a backup has to be encrypted, and the key has to still exist when the backup
// is needed.  Asking an operator to generate and escrow a key per subsystem
// gets that wrong in both directions -- it is one more secret to lose, and
// nothing enforces that it was ever set.  A server already holds a secret it
// cannot function without and already protects carefully: its issuer keys.
// Deriving from those means the encryption cannot be skipped, and rotating an
// issuer key does not strand the archives written before the rotation.
//
// The derivation is one-way (HKDF-SHA256 over the issuer key's PKCS8 encoding),
// so a leaked backup key does not yield the issuer key it came from.
//
// # Domain separation
//
// The label is what keeps subsystems apart.  Without it, every subsystem that
// derived from the same issuer key would derive the *same* key pair, and
// possession of any one subsystem's escrowed backup key would open every other
// subsystem's archives.  Each caller passes its own label, so a key derived for
// one domain is unrelated to the key derived for another.
//
// Labels are permanent: an archive is sealed to the key its label produced, so
// changing a label makes every archive written under the old one unopenable.
// Add a label; never edit one.
package backup_keys

import (
	"crypto/sha256"
	"crypto/x509"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// LabelDatabase is the domain for the server database's backups.
	//
	// This value must never change: it is baked into every database backup
	// ever written, and an archive whose label no longer derives the same key
	// cannot be decrypted.
	LabelDatabase = "pelican-backup-encryption"

	// LabelPStore is the domain for a pstore origin's metadata snapshots.
	LabelPStore = "pelican-pstore-backup"
)

// DeriveKeyPair derives a Curve25519 key pair from an issuer JWK for one
// backup domain.
//
// The label provides domain separation, so a key derived for one subsystem
// cannot open another's archives.  The same issuer key and label always
// produce the same pair, which is what lets an operator print the private key
// once and use it years later against archives written in between.
func DeriveKeyPair(issuerKey jwk.Key, label string) (privateKey, publicKey *[32]byte, err error) {
	if issuerKey == nil {
		return nil, nil, errors.New("cannot derive a backup key pair from a nil issuer key")
	}
	if label == "" {
		return nil, nil, errors.New("cannot derive a backup key pair without a domain label")
	}

	var rawKey any
	if err := issuerKey.Raw(&rawKey); err != nil {
		return nil, nil, errors.Wrap(err, "failed to extract raw key from JWK")
	}

	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(rawKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal private key to PKCS8")
	}

	// Use HKDF-SHA256 to derive a 32-byte Curve25519 private key.  The info
	// string binds the derived key to one backup domain.
	hkdfReader := hkdf.New(sha256.New, derPrivateKey, nil, []byte(label))

	privateKey = new([32]byte)
	if _, err := io.ReadFull(hkdfReader, privateKey[:]); err != nil {
		return nil, nil, errors.Wrap(err, "failed to derive key via HKDF")
	}

	publicKey = new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)

	return privateKey, publicKey, nil
}

// KeyPairFromPrivate recovers the public half of a Curve25519 private key.
//
// This is the disaster-recovery entry point: an operator who saved the private
// key printed by a "backup-key" command can hand those 32 bytes back and open
// an archive without the issuer key it was derived from.
func KeyPairFromPrivate(private []byte) (privateKey, publicKey *[32]byte, err error) {
	if len(private) != 32 {
		return nil, nil, errors.Errorf("a backup private key must be 32 bytes, got %d", len(private))
	}
	privateKey = new([32]byte)
	copy(privateKey[:], private)
	publicKey = new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return privateKey, publicKey, nil
}
