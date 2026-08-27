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

package backup_keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

// fixedIssuerKey returns a JWK with no randomness in it, so a derivation from
// it can be pinned to a literal.
func fixedIssuerKey(t *testing.T) jwk.Key {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := jwk.FromRaw(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	return key
}

func randomIssuerKey(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	return key
}

// TestDatabaseLabelDerivationIsFrozen is the one test in this package that
// cannot be allowed to fail.
//
// Every database backup ever written was sealed to the key this derivation
// produces.  If a refactor changes the marshalling, the hash, the salt, the
// info string, or the order of any of it, those archives become undecryptable
// -- and nothing else in the test suite would notice, because a round trip
// through the changed code still round-trips.  The vector below was computed
// with the original implementation in database/backup.go.
func TestDatabaseLabelDerivationIsFrozen(t *testing.T) {
	const (
		wantPriv = "5951391ef185965fd0288a26f5995400e7ba67de89653be3cd4652933621a8e0"
		wantPub  = "ff4a23a5047c2edc15da7f4c7288a566a34d3cc8a45c88a2fce0e15c9551d172"
	)

	priv, pub, err := DeriveKeyPair(fixedIssuerKey(t), LabelDatabase)
	require.NoError(t, err)
	assert.Equal(t, wantPriv, hex.EncodeToString(priv[:]),
		"the database backup derivation changed; every existing database backup is now unreadable")
	assert.Equal(t, wantPub, hex.EncodeToString(pub[:]),
		"the database backup derivation changed; every existing database backup is now unreadable")

	// The label constant itself is part of the frozen contract: an archive
	// records nothing about which label sealed it, so renaming the value is
	// indistinguishable from changing the algorithm.
	assert.Equal(t, "pelican-backup-encryption", LabelDatabase)
}

// TestLabelsAreSeparateDomains is the point of taking a label at all: an
// escrowed pstore backup key must not open a database archive.
func TestLabelsAreSeparateDomains(t *testing.T) {
	key := randomIssuerKey(t)

	dbPriv, dbPub, err := DeriveKeyPair(key, LabelDatabase)
	require.NoError(t, err)
	psPriv, psPub, err := DeriveKeyPair(key, LabelPStore)
	require.NoError(t, err)

	assert.NotEqual(t, *dbPriv, *psPriv, "one issuer key must yield unrelated keys per domain")
	assert.NotEqual(t, *dbPub, *psPub, "one issuer key must yield unrelated keys per domain")

	// Not merely different bytes: a message sealed in one domain must not open
	// in the other.  This is the property an operator relies on when they hand
	// a backup custodian one subsystem's key.
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	sealed := box.Seal(nil, []byte("database secret"), &nonce, dbPub, dbPriv)

	opened, ok := box.Open(nil, sealed, &nonce, dbPub, dbPriv)
	require.True(t, ok, "the sealing domain must open its own message")
	assert.Equal(t, "database secret", string(opened))

	_, ok = box.Open(nil, sealed, &nonce, psPub, psPriv)
	assert.False(t, ok, "a pstore-domain key must not open a database-domain message")
}

// TestDerivationIsDeterministicAndKeyBound covers the two properties every
// caller depends on: re-running the derivation reproduces the key (so it can be
// printed once and escrowed), and a different issuer key yields a different one.
func TestDerivationIsDeterministicAndKeyBound(t *testing.T) {
	key := randomIssuerKey(t)

	first, firstPub, err := DeriveKeyPair(key, LabelPStore)
	require.NoError(t, err)
	second, secondPub, err := DeriveKeyPair(key, LabelPStore)
	require.NoError(t, err)
	assert.Equal(t, *first, *second)
	assert.Equal(t, *firstPub, *secondPub)

	other, _, err := DeriveKeyPair(randomIssuerKey(t), LabelPStore)
	require.NoError(t, err)
	assert.NotEqual(t, *first, *other)
}

// TestKeyPairFromPrivate checks the disaster-recovery entry point reproduces
// the public half, so an escrowed private key alone can open an archive.
func TestKeyPairFromPrivate(t *testing.T) {
	priv, pub, err := DeriveKeyPair(randomIssuerKey(t), LabelPStore)
	require.NoError(t, err)

	recoveredPriv, recoveredPub, err := KeyPairFromPrivate(priv[:])
	require.NoError(t, err)
	assert.Equal(t, *priv, *recoveredPriv)
	assert.Equal(t, *pub, *recoveredPub)

	_, _, err = KeyPairFromPrivate(priv[:31])
	assert.Error(t, err, "a short key must be refused rather than silently padded")
}

// TestDeriveKeyPairRejectsBadInput keeps the two mistakes that would otherwise
// produce a usable-looking key from being silent.
func TestDeriveKeyPairRejectsBadInput(t *testing.T) {
	_, _, err := DeriveKeyPair(nil, LabelPStore)
	assert.Error(t, err)

	_, _, err = DeriveKeyPair(randomIssuerKey(t), "")
	assert.Error(t, err, "an empty label would silently merge every domain into one")
}
