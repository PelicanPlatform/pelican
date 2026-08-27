//go:build server

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

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/backup_keys"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/pstore"
)

// TestPStoreBackupKeyIsDerivedNotGenerated is the behavior change the command
// exists to express.
//
// It used to mint a fresh random key, which meant an operator who lost the file
// lost every backup taken with it. It now re-derives the key from the origin's
// issuer keys, so printing it twice on the same origin gives the same answer
// and a lost copy can simply be reprinted. A test that only checked the key
// parsed would have passed under both behaviors.
func TestPStoreBackupKeyIsDerivedNotGenerated(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	first, err := pstoreEscrowBackupKey()
	require.NoError(t, err)
	second, err := pstoreEscrowBackupKey()
	require.NoError(t, err)
	assert.Equal(t, first, second,
		"the key is derived, so re-running the command must reprint the same one")

	// What the command writes to stdout has to be what --key-file accepts.
	parsed, err := pstore.ParseBackupKey(pstore.FormatBackupKey(first))
	require.NoError(t, err)
	assert.Equal(t, first, parsed)
}

// TestPStoreBackupKeyDiffersFromTheDatabaseBackupKey is the domain separation
// the repository owner asked for, checked at the level an operator sees: the
// key printed for pstore backups is not the key that opens a server database
// backup, so escrowing one does not hand over the other.
func TestPStoreBackupKeyDiffersFromTheDatabaseBackupKey(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	pstoreKey, err := pstoreEscrowBackupKey()
	require.NoError(t, err)

	issuerKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	databaseKey, _, err := backup_keys.DeriveKeyPair(issuerKey, backup_keys.LabelDatabase)
	require.NoError(t, err)

	assert.NotEqual(t, databaseKey[:], pstoreKey,
		"the pstore backup key must not be the database backup key")
}

// TestPStoreCLIBackupKeysResolution covers the three ways the CLI decides what
// a backup is sealed to or opened with: the origin's issuer keys by default,
// the backup key in --key-file, and the one archive's own key in --file-key.
func TestPStoreCLIBackupKeysResolution(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	t.Cleanup(func() { pstoreKeyFile, pstoreFileKeyFile = "", "" })

	pstoreKeyFile, pstoreFileKeyFile = "", ""
	keys, err := pstoreBackupKeys()
	require.NoError(t, err)
	assert.Empty(t, keys.BackupKey)
	assert.Empty(t, keys.FileKey)
	assert.NotEmpty(t, keys.IssuerKeys, "the default path seals to the origin's issuer keys")

	escrowed, err := pstoreEscrowBackupKey()
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "pstore-backup.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(pstore.FormatBackupKey(escrowed)+"\n"), 0600))

	pstoreKeyFile = keyPath
	keys, err = pstoreBackupKeys()
	require.NoError(t, err)
	assert.Equal(t, escrowed, keys.BackupKey)
	assert.Empty(t, keys.IssuerKeys, "a key file replaces the issuer keys rather than joining them")

	// --file-key is the narrowest thing an operator can be holding, so it wins
	// over both: if they passed it, it is what they meant.
	pstoreFileKeyFile = keyPath
	keys, err = pstoreBackupKeys()
	require.NoError(t, err)
	assert.Equal(t, escrowed, keys.FileKey)
	assert.Empty(t, keys.BackupKey)
	assert.Empty(t, keys.IssuerKeys)

	pstoreFileKeyFile = ""
	pstoreKeyFile = filepath.Join(t.TempDir(), "missing.key")
	_, err = pstoreBackupKeys()
	assert.Error(t, err, "a key file that cannot be read must fail rather than fall back")
}

// pstoreTestArchive writes a sealed metadata backup of a small store and
// returns its path, standing in for a file an operator is holding.
func pstoreTestArchive(t *testing.T, name string) string {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)

	store, err := pstore.Open(ctx, egrp, pstore.Config{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.MkdirAll("/data"))

	path := filepath.Join(t.TempDir(), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer f.Close()

	_, err = store.BackupEncrypted(f, pstore.BackupKeys{IssuerKeys: config.GetIssuerPrivateKeys()})
	require.NoError(t, err)
	return path
}

// TestPStoreBackupKeyForAFile is the distinction the repository owner asked to
// be made obvious: naming a file must print THAT file's key, not the origin's
// backup key.
//
// A command that quietly printed the backup key either way would pass every
// "the key opens the file" assertion while handing out a key that opens the
// whole series, so both halves are checked -- the key works on its own file,
// and it is neither the backup key nor the neighbouring file's key.
func TestPStoreBackupKeyForAFile(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	t.Cleanup(func() { pstoreKeyFile, pstoreFileKeyFile = "", "" })
	pstoreKeyFile, pstoreFileKeyFile = "", ""

	first := pstoreTestArchive(t, "first.pmb")
	second := pstoreTestArchive(t, "second.pmb")

	firstKey, err := pstoreFileBackupKey(first)
	require.NoError(t, err)
	secondKey, err := pstoreFileBackupKey(second)
	require.NoError(t, err)

	backupKey, err := pstoreEscrowBackupKey()
	require.NoError(t, err)
	assert.NotEqual(t, backupKey, firstKey,
		"naming a file must print that file's key, not the origin's backup key")
	assert.NotEqual(t, firstKey, secondKey, "two archives must not share a key")

	// The no-file form is stable across runs, which is what makes escrowing it
	// worth anything.
	again, err := pstoreEscrowBackupKey()
	require.NoError(t, err)
	assert.Equal(t, backupKey, again)

	// And the printed key really is the one that opens that file -- and only
	// that file.
	opens := func(t *testing.T, archive string, key []byte) error {
		t.Helper()
		f, oErr := os.Open(archive)
		require.NoError(t, oErr)
		defer f.Close()
		target, oErr := pstore.OpenMaintenance(t.Context(), t.TempDir(), true)
		require.NoError(t, oErr)
		defer target.Close()
		return target.Restore(f, pstore.BackupKeys{FileKey: key})
	}
	assert.NoError(t, opens(t, first, firstKey))
	assert.Error(t, opens(t, second, firstKey),
		"one archive's key must not open its sibling")

	t.Run("an operator holding only the escrowed backup key gets the same answer",
		func(t *testing.T) {
			// The issuer keys are deliberately not consulted here: --key-file is
			// the path for a machine that has never held them.
			keyPath := filepath.Join(t.TempDir(), "escrowed.key")
			require.NoError(t, os.WriteFile(keyPath,
				[]byte(pstore.FormatBackupKey(backupKey)+"\n"), 0600))

			pstoreKeyFile = keyPath
			t.Cleanup(func() { pstoreKeyFile = "" })

			viaEscrow, dErr := pstoreFileBackupKey(first)
			require.NoError(t, dErr)
			assert.Equal(t, firstKey, viaEscrow)
		})
}
