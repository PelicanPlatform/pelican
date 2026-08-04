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

// Backup encryption: the envelope and the cipher.
//
// backup.go owns the container and the policy -- what a snapshot is, when one is
// taken, how it is published and pruned, and the rule that every one of them is
// sealed.  This file owns what makes sealing possible: the envelope that carries
// the key to each recipient, and the AEAD that protects the body under it.
//
// A store is encrypted at rest, but BadgerDB's backup is a *logical* dump:
// values come back decrypted, so a raw snapshot is cleartext.  It contains
// every object path, all the metadata, and the hash salt that makes on-disk
// filenames unguessable.  Writing that to a backup directory would undo the
// at-rest protection the store exists to provide.
//
// **There is therefore no way to write an unencrypted snapshot.**  Making
// encryption conditional on an operator having generated and configured a key,
// and warning in the log when they had not, would be the weakest control there
// is for a file that leaks the whole namespace: nobody reads the warning, and
// the failure is silent and permanent.  A backup either encrypts or fails.
//
// # The key hierarchy
//
// There are three levels, and possession of *any* one of them opens an archive.
// That is the point of the arrangement: a recovery happens on whatever the
// operator still has, and which of the three that is cannot be predicted in
// advance.
//
//	 1. The **master keys** are the origin's issuer keys.  They are what the
//	    origin cannot run without and already protects carefully, so nothing new
//	    has to be created, configured, or remembered.
//
//	 2. The **backup key** is derived from an issuer key with
//	    backup_keys.DeriveKeyPair(key, LabelPStore) -- HKDF-SHA256 over the
//	    issuer key's PKCS8 encoding, read out as a Curve25519 private key.  It is
//	    deterministic, so `pelican-server origin pstore metadata-backup-key` re-derives
//	    and prints the same 32 bytes every time and an operator can escrow them.
//	    The label domain-separates it from the server database's backup key, so
//	    escrowing one does not hand over the other, and the derivation is one-way,
//	    so a leaked backup key does not yield the issuer key behind it.
//
//	 3. The **per-file key** is HKDF-SHA256 over the backup key, salted with 32
//	    random bytes drawn for that one snapshot and stored in its header, under
//	    a different info label from the one that produced the backup key.  It is
//	    what the body is actually encrypted under.  Every snapshot therefore has
//	    a key of its own, and holding one snapshot's key reveals nothing about
//	    any other snapshot -- so a single archive can be handed to someone
//	    without handing them the whole series.
//
// The consequence worth stating outright: **losing the origin's issuer keys does
// not lose the archives, provided the backup key was escrowed.**  Level 2 is
// reachable without level 1, and level 3 is reachable from level 2.
//
// The backup key is **embedded in the archive, encrypted**: one envelope block
// per recipient, each a NaCl box sealed to the key pair derived from one of the
// origin's current issuer keys.  Each box is sealed to itself, so the private
// half alone opens it and there is no separate sender key to keep.  That is what
// makes rotation free -- an archive opens with any issuer key that was current
// when it was written, so retiring a key does not strand the archives that
// overlapped it -- and it is what lets an issuer key reach the per-file key at
// all.
//
// The archive's backup key is the one derived from the first issuer key in
// sorted order, and it is itself one of the recipients.  That last detail is
// what makes the second and third recovery paths uniform: whichever escrowed
// backup key an operator produces, it opens *its own* envelope block, which
// yields the archive's backup key, which derives the per-file key.  When the key
// produced happens to be the archive's own, that block hands it straight back.
//
// # The three ways in
//
//	an issuer key   -> derive its key pair -> open the envelope -> backup key
//	                   -> HKDF with the salt in the header -> per-file key
//	a backup key    -> open the envelope with it -> the archive's backup key
//	                   -> HKDF with the salt in the header -> per-file key
//	a per-file key  -> decrypt.  No derivation, no envelope, no issuer key.
//
// Object *contents* are not exposed by any of this -- each object's data key is
// stored already wrapped by the master key, so the block files stay protected
// even if a snapshot leaks.  The namespace is what needs covering here.
//
// Snapshots are compressed before they are sealed, which is the only order that
// works: ciphertext is incompressible, so compressing afterwards would achieve
// nothing.  A catalog compresses extremely well -- it is mostly repetitive path
// strings and structurally similar metadata records -- and smaller snapshots
// mean retention costs less, so more of them can be kept.
//
// Compressing before encrypting can leak information through ciphertext length
// when an attacker chooses part of the plaintext and observes the result
// repeatedly.  That is not this: a snapshot is written once, from data the
// attacker does not control interactively, and there is no oracle to query.
//
// # The layout on disk
//
//	magic     "PELICAN-PSTORE-BACKUP\0" and a one-byte format version
//	salt      32 random bytes, drawn for this snapshot
//	envelope  a uint16 recipient count, then per recipient a length-prefixed key
//	          ID and the length-prefixed backup key sealed to it
//	body      sealed chunks, each behind its sealed length and an end marker
//
// # Nonces, and what is authenticated
//
// The per-file key is unique to one archive, because the salt it is derived from
// is drawn fresh for every snapshot.  A GCM nonce therefore only has to be
// unique *within* an archive, so it can be a pure chunk counter -- there is no
// random nonce prefix to collide across archives, and so no birthday bound on
// how many snapshots may be taken under the same key.
//
// The whole header -- magic, salt, and every envelope block -- is passed as
// additional authenticated data on every chunk.  So the salt cannot be swapped
// (which would silently change which key the file claims to want), the envelope
// cannot be stripped, extended, or lifted from another archive, and no chunk can
// be spliced from one archive into another.  The terminating chunk is marked in
// both the framing and the nonce, so a truncated stream cannot be re-sealed as
// if it had ended where it was cut.
//
// # Format versions
//
// The magic ends in a version byte and the reader dispatches on it, so changing
// the format later has somewhere to go and old readers report the mismatch
// instead of misparsing.  Exactly one version is understood at a time: a file
// carrying any other is refused by number -- what it is, and what this build
// reads -- rather than decoded on a guess.

package pstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"

	"github.com/pelicanplatform/pelican/backup_keys"
)

const (
	// backupKeySize is the AES-256 key length, and also the length of a
	// Curve25519 private key -- the two happen to coincide, which is why one
	// key file format serves the backup keys and the per-file keys alike.
	backupKeySize = 32

	// backupMagicPrefix opens every snapshot, whatever its version.
	//
	// Matching the family rather than the exact version is what lets a snapshot
	// this build cannot read be reported as a version mismatch -- "find the
	// build that wrote this" -- instead of collapsing into "this is not a
	// backup", which sends an operator looking for the wrong file.
	backupMagicPrefix = "PELICAN-PSTORE-BACKUP\x00"

	// backupFormatVersion is the container version this build writes, and the
	// only one it reads.  It is the last byte of the magic.
	backupFormatVersion = 1

	// backupMagic opens every snapshot in the current format: a per-snapshot
	// salt, the archive's backup key sealed to one or more recipients, and a
	// body encrypted under a per-file key derived from the two.
	//
	// Its last byte must be backupFormatVersion; Go cannot express that as a
	// constant, so TestAnUnsupportedFormatVersionIsRefused asserts it instead.
	backupMagic = backupMagicPrefix + "\x01"

	// backupChunkSize is the plaintext size of each sealed chunk.  Chunking
	// keeps memory flat for a snapshot of any size.
	backupChunkSize = 64 << 10

	// backupSaltSize is the per-snapshot HKDF salt.
	backupSaltSize = 32

	// backupFileKeyInfo domain-separates the per-file key from the backup key
	// it is derived from.
	//
	// It must differ from backup_keys.LabelPStore, which produced that backup
	// key: sharing an info string across levels of a hierarchy is how a
	// hierarchy stops being one.
	backupFileKeyInfo = "pelican pstore metadata backup file key v1"

	// backupNonceCounterOffset leaves the first four bytes of the nonce zero.
	// The key is already unique per snapshot, so the nonce only has to be
	// unique within one -- and 2^63 chunks of 64 KiB is more archive than any
	// filesystem will hold.
	backupNonceCounterOffset = 4

	// backupMaxRecipients bounds the envelope so a corrupt header cannot make
	// a reader allocate without limit.  An origin with more than this many
	// live issuer keys has a different problem.
	backupMaxRecipients = 64

	// backupMaxKeyIDLen and backupMaxSealedLen bound the two variable-length
	// fields in a recipient block for the same reason.
	backupMaxKeyIDLen  = 256
	backupMaxSealedLen = 1024
)

// ErrNoMatchingKey reports a snapshot that none of the supplied keys open.
//
// SealedKeyIDs names the keys it *was* sealed to, which is the only thing that
// tells an operator holding the wrong keyring what to go and find.
type ErrNoMatchingKey struct {
	SealedKeyIDs []string
}

func (e *ErrNoMatchingKey) Error() string {
	if len(e.SealedKeyIDs) == 0 {
		return "the snapshot could not be decrypted: it names no keys at all, so it is damaged"
	}
	return fmt.Sprintf("the snapshot could not be decrypted: none of the available keys match; "+
		"it was sealed to key(s): %s", strings.Join(e.SealedKeyIDs, ", "))
}

// BackupKeys names the keys a snapshot is sealed to, or opened with.
//
// The three fields are the three levels of the hierarchy, and on the reading
// side any one of them is enough.  They are passed in rather than read from
// configuration so that pstore stays free of the config package: the caller
// resolves the origin's issuer keys and hands them over, and a test supplies
// whatever keys it likes.
type BackupKeys struct {
	// IssuerKeys are the origin's current issuer keys, by key ID (level 1).
	// The archive's backup key is sealed to the pstore-domain key pair derived
	// from each, and any one of them opens it -- so a snapshot written before a
	// rotation still opens afterwards, as long as one of the keys it was
	// written under survives.
	IssuerKeys map[string]jwk.Key

	// BackupKey is a raw 32-byte Curve25519 private key from level 2: the
	// escrowed key printed by `pelican-server origin pstore metadata-backup-key`, or
	// an independent key for backups that must be restorable somewhere that
	// will never hold this origin's issuer keys.
	//
	// When writing, it *replaces* the issuer-derived recipients rather than
	// joining them.  When reading, it opens the envelope and yields the
	// archive's own backup key, from which the per-file key is derived.
	BackupKey []byte

	// FileKey is one archive's own key (level 3), as printed by
	// `metadata-backup-key <file>`.  It decrypts that archive's body directly:
	// no derivation, no envelope, and no issuer key need be present.  It opens
	// nothing else, which is the point of having it.
	//
	// It is read-only.  Sealing a new archive requires a backup key to embed,
	// and a per-file key is downstream of one.
	FileKey []byte
}

// Empty reports whether there is nothing here to *seal* to.
//
// FileKey is deliberately not consulted: it opens one existing archive and
// cannot write a new one, so a caller holding only that has nothing to back up
// with.
func (k BackupKeys) Empty() bool {
	return len(k.BackupKey) == 0 && len(k.IssuerKeys) == 0
}

// backupRecipient is one key an archive's backup key is sealed to.
//
// Both halves are derived from the same secret and the box is sealed to
// itself, so holding the private key is all it takes to open -- there is no
// separate sender key to keep.
type backupRecipient struct {
	keyID string
	priv  *[32]byte
	pub   *[32]byte
}

// recipients resolves the keys an archive is sealed to, refusing to produce an
// empty list: a snapshot with no recipients would be a snapshot nobody can
// read, and writing one is worse than failing.
//
// The first entry is the archive's backup key, so the order candidates() puts
// them in is load-bearing rather than cosmetic.
func (k BackupKeys) recipients() ([]backupRecipient, error) {
	out, err := k.candidates()
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		if len(k.FileKey) > 0 {
			return nil, errors.New("a per-file key opens the one snapshot it belongs to and " +
				"cannot seal a new one; supply the origin's issuer keys or a backup key")
		}
		return nil, errors.New("no keys are available to encrypt the metadata snapshot; " +
			"a snapshot is a logical dump of the namespace and is never written in the clear")
	}
	return out, nil
}

// candidates resolves the configured keys into key pairs, in a deterministic
// order so two runs over the same keys produce headers that differ only in
// their random parts.  An empty result is not an error here -- on the reading
// side it simply means nothing can open the archive, which the caller reports
// along with the keys it was sealed to.
func (k BackupKeys) candidates() ([]backupRecipient, error) {
	if len(k.BackupKey) > 0 {
		priv, pub, err := backup_keys.KeyPairFromPrivate(k.BackupKey)
		if err != nil {
			return nil, err
		}
		return []backupRecipient{{keyID: suppliedKeyID(pub), priv: priv, pub: pub}}, nil
	}

	keyIDs := make([]string, 0, len(k.IssuerKeys))
	for keyID := range k.IssuerKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)

	out := make([]backupRecipient, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		priv, pub, err := backup_keys.DeriveKeyPair(k.IssuerKeys[keyID], backup_keys.LabelPStore)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to derive the backup key for issuer key %s", keyID)
		}
		out = append(out, backupRecipient{keyID: keyID, priv: priv, pub: pub})
	}
	return out, nil
}

// suppliedKeyID labels an explicitly supplied backup key so that a snapshot
// sealed to one says which, rather than only that it was not an issuer key.
//
// It is a fingerprint of the public half: it identifies the key without
// revealing anything about it.
func suppliedKeyID(pub *[32]byte) string {
	sum := sha256.Sum256(pub[:])
	return "backup-key:" + hex.EncodeToString(sum[:8])
}

// generateBackupKey returns a new random 32-byte key, base64-encoded.
//
// Only tests need this: the operator-facing key is derived rather than
// generated.  An operator who wants an independent backup key can produce 32
// random bytes with anything.
func generateBackupKey() (string, error) {
	key := make([]byte, backupKeySize)
	if _, err := rand.Read(key); err != nil {
		return "", errors.Wrap(err, "failed to generate a backup key")
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ParseBackupKey decodes a base64 backup or per-file key and checks its length.
func ParseBackupKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.Wrap(err, "the backup key is not valid base64")
	}
	if len(key) != backupKeySize {
		return nil, errors.Errorf("the backup key must be %d bytes, got %d",
			backupKeySize, len(key))
	}
	return key, nil
}

// FormatBackupKey renders a raw backup or per-file key the way a key file holds
// it.
func FormatBackupKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DeriveBackupKey returns the level-2 pstore backup private key for one issuer
// key, which is what `metadata-backup-key` prints for escrow.
//
// The same issuer key always yields the same backup key, so printing it twice
// gives the same answer -- that is the property that makes escrowing it useful.
// It opens every snapshot this origin writes; for the key that opens exactly
// one of them, see DeriveFileKey.
func DeriveBackupKey(issuerKey jwk.Key) ([]byte, error) {
	priv, _, err := backup_keys.DeriveKeyPair(issuerKey, backup_keys.LabelPStore)
	if err != nil {
		return nil, err
	}
	return priv[:], nil
}

// DeriveFileKey returns the level-3 key that opens exactly the archive in r,
// and nothing else.
//
// It reads only the header, so r may be a file opened purely for this.  keys
// supplies whatever the caller has: the origin's issuer keys, or an escrowed
// backup key -- either reaches the same answer, because the archive carries its
// own backup key sealed to both.
func DeriveFileKey(r io.Reader, keys BackupKeys) ([]byte, error) {
	magic, err := readBackupMagic(r)
	if err != nil {
		return nil, err
	}
	fileKey, _, err := openBackupHeader(r, magic, keys)
	return fileKey, err
}

// readBackupMagic consumes the container magic and checks that this build can
// read what follows it.
//
// A file whose version byte is not the one supported is refused by number
// rather than decoded: the layout behind the magic is version-specific, so
// reading on would either fail with a cryptographic error that names nothing
// useful or, worse, parse into the wrong shape.
func readBackupMagic(r io.Reader) ([]byte, error) {
	magic := make([]byte, len(backupMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, errors.Wrap(err, "failed to read the backup header")
	}
	if string(magic[:len(backupMagicPrefix)]) != backupMagicPrefix {
		return nil, errors.New("this file is not an encrypted pstore snapshot")
	}
	if version := magic[len(backupMagicPrefix)]; version != backupFormatVersion {
		return nil, errors.Errorf("this snapshot is in pstore backup format version %d, "+
			"but this build reads only version %d", version, backupFormatVersion)
	}
	return magic, nil
}

// newBackupAEAD builds the cipher used for both directions.
func newBackupAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != backupKeySize {
		return nil, errors.Errorf("a snapshot key must be %d bytes, got %d",
			backupKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize the backup cipher")
	}
	aead, err := cipher.NewGCM(block)
	return aead, errors.Wrap(err, "failed to initialize the backup cipher")
}

// deriveFileKey produces one snapshot's own encryption key from the backup key
// it is sealed under and the salt drawn for it.
//
// The salt is what makes the result unique per snapshot, and the info label is
// what keeps this level distinct from the one that produced backupKey: derive
// twice with the same inputs and the same 32 bytes come back, which is what
// lets `metadata-backup-key <file>` reproduce a key that was never stored.
func deriveFileKey(backupKey, salt []byte) ([]byte, error) {
	if len(backupKey) != backupKeySize {
		return nil, errors.Errorf("a backup key must be %d bytes, got %d",
			backupKeySize, len(backupKey))
	}
	fileKey := make([]byte, backupKeySize)
	reader := hkdf.New(sha256.New, backupKey, salt, []byte(backupFileKeyInfo))
	if _, err := io.ReadFull(reader, fileKey); err != nil {
		return nil, errors.Wrap(err, "failed to derive the snapshot's own key")
	}
	return fileKey, nil
}

// encryptBackup copies src to dst, sealing it to keys.
//
// The output is the magic, the salt, the envelope carrying the backup key, then
// a sequence of sealed chunks each prefixed with its sealed length.  Every chunk
// is bound to its position by a counter in the nonce and to this archive by the
// whole header as additional data, and the final chunk is marked, so reordering,
// dropping, truncating, or splicing chunks between archives is detected rather
// than silently producing a short restore.
func encryptBackup(dst io.Writer, src io.Reader, keys BackupKeys) error {
	recipients, err := keys.recipients()
	if err != nil {
		return err
	}

	// The archive's backup key is the first recipient's, which candidates()
	// fixes deterministically.  It is itself a recipient, so an operator
	// holding any escrowed backup key reaches it the same way an issuer key
	// does.
	backupKey := recipients[0].priv[:]

	// The salt is what makes this snapshot's key its own, and it is the reason
	// the nonce can be a bare counter: two archives share a key only if the
	// CSPRNG repeats.
	salt := make([]byte, backupSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return errors.Wrap(err, "failed to generate a snapshot salt")
	}

	fileKey, err := deriveFileKey(backupKey, salt)
	if err != nil {
		return err
	}
	aead, err := newBackupAEAD(fileKey)
	if err != nil {
		return err
	}

	header, err := buildBackupHeader(backupKey, salt, recipients)
	if err != nil {
		return err
	}
	if _, err := dst.Write(header); err != nil {
		return errors.Wrap(err, "failed to write the backup header")
	}

	buf := make([]byte, backupChunkSize)
	var counter uint64
	for {
		n, rErr := io.ReadFull(src, buf)
		last := rErr == io.EOF || rErr == io.ErrUnexpectedEOF
		if rErr != nil && !last {
			return errors.Wrap(rErr, "failed to read the snapshot")
		}

		nonce := backupNonce(counter, last)
		sealed := aead.Seal(nil, nonce, buf[:n], header)
		var chunkHeader [5]byte
		binary.BigEndian.PutUint32(chunkHeader[:4], uint32(len(sealed)))
		if last {
			chunkHeader[4] = 1
		}
		if _, wErr := dst.Write(chunkHeader[:]); wErr != nil {
			return errors.Wrap(wErr, "failed to write the backup")
		}
		if _, wErr := dst.Write(sealed); wErr != nil {
			return errors.Wrap(wErr, "failed to write the backup")
		}
		if last {
			return nil
		}
		counter++
	}
}

// buildBackupHeader lays out the magic, the salt, and one block per recipient.
//
// The whole thing is authenticated as additional data on every chunk, so the
// salt cannot be swapped and a recipient cannot be removed, added, or lifted
// from another archive without the body failing to open.
func buildBackupHeader(backupKey, salt []byte, recipients []backupRecipient) ([]byte, error) {
	header := make([]byte, 0, len(backupMagic)+len(salt)+2+len(recipients)*128)
	header = append(header, backupMagic...)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint16(header, uint16(len(recipients)))

	for _, r := range recipients {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, errors.Wrap(err, "failed to generate a key nonce")
		}
		// Sealed to itself: the private key alone opens it, so an escrowed key
		// needs no counterpart.
		sealed := box.Seal(nonce[:], backupKey, &nonce, r.pub, r.priv)

		if len(r.keyID) > backupMaxKeyIDLen {
			return nil, errors.Errorf("the key ID %q is too long to record in a snapshot", r.keyID)
		}
		header = binary.BigEndian.AppendUint16(header, uint16(len(r.keyID)))
		header = append(header, r.keyID...)
		header = binary.BigEndian.AppendUint16(header, uint16(len(sealed)))
		header = append(header, sealed...)
	}
	return header, nil
}

// sealedBlock is one recipient's envelope as it was read back off disk.
type sealedBlock struct {
	keyID string
	data  []byte
}

// readEnvelope reads the recipient blocks, returning both the parsed blocks and
// the raw bytes they occupied, because the reader has to reassemble the exact
// header it authenticates against.
func readEnvelope(src io.Reader) (blocks []sealedBlock, raw []byte, err error) {
	var countBuf [2]byte
	if _, err := io.ReadFull(src, countBuf[:]); err != nil {
		return nil, nil, errors.Wrap(err, "failed to read the backup header")
	}
	raw = append(raw, countBuf[:]...)
	count := int(binary.BigEndian.Uint16(countBuf[:]))
	if count == 0 || count > backupMaxRecipients {
		return nil, nil, errors.New("the backup is malformed: implausible number of keys")
	}

	blocks = make([]sealedBlock, 0, count)
	for i := 0; i < count; i++ {
		keyID, rawKeyID, rErr := readLengthPrefixed(src, backupMaxKeyIDLen)
		if rErr != nil {
			return nil, nil, rErr
		}
		raw = append(raw, rawKeyID...)
		sealed, rawSealed, rErr := readLengthPrefixed(src, backupMaxSealedLen)
		if rErr != nil {
			return nil, nil, rErr
		}
		raw = append(raw, rawSealed...)
		blocks = append(blocks, sealedBlock{keyID: string(keyID), data: sealed})
	}
	return blocks, raw, nil
}

// unsealEnvelope recovers the archive's backup key from the envelope, using any
// key the caller holds.
//
// The key IDs are matched first, because that is the common case and it is the
// cheap one; every block is then tried against every candidate, so an archive
// sealed to a supplied backup key still opens when the operator hands over
// those bytes without knowing the fingerprint they were recorded under.
func unsealEnvelope(blocks []sealedBlock, keys BackupKeys) ([]byte, error) {
	candidates, err := keys.candidates()
	if err != nil {
		return nil, err
	}

	open := func(b sealedBlock, r backupRecipient) ([]byte, bool) {
		if len(b.data) <= 24 {
			return nil, false
		}
		var nonce [24]byte
		copy(nonce[:], b.data[:24])
		key, ok := box.Open(nil, b.data[24:], &nonce, r.pub, r.priv)
		if !ok || len(key) != backupKeySize {
			return nil, false
		}
		return key, true
	}

	byID := make(map[string]backupRecipient, len(candidates))
	for _, r := range candidates {
		byID[r.keyID] = r
	}
	for _, b := range blocks {
		if r, found := byID[b.keyID]; found {
			if key, ok := open(b, r); ok {
				return key, nil
			}
		}
	}
	for _, b := range blocks {
		for _, r := range candidates {
			if key, ok := open(b, r); ok {
				return key, nil
			}
		}
	}

	sealedTo := make([]string, 0, len(blocks))
	for _, b := range blocks {
		sealedTo = append(sealedTo, b.keyID)
	}
	return nil, &ErrNoMatchingKey{SealedKeyIDs: sealedTo}
}

// openBackupHeader reads the salt and the envelope and produces the archive's
// own key, along with the exact header bytes that authenticate its body.
//
// A caller holding the per-file key short-circuits the envelope entirely: the
// header is still parsed, because the body is authenticated against it and the
// body does not start until it ends, but nothing in it has to be opened.
func openBackupHeader(src io.Reader, magic []byte, keys BackupKeys) (fileKey, header []byte, err error) {
	header = append(header, magic...)

	salt := make([]byte, backupSaltSize)
	if _, err := io.ReadFull(src, salt); err != nil {
		return nil, nil, errors.Wrap(err, "failed to read the backup header")
	}
	header = append(header, salt...)

	blocks, raw, err := readEnvelope(src)
	if err != nil {
		return nil, nil, err
	}
	header = append(header, raw...)

	if len(keys.FileKey) > 0 {
		if len(keys.FileKey) != backupKeySize {
			return nil, nil, errors.Errorf("a per-file key must be %d bytes, got %d",
				backupKeySize, len(keys.FileKey))
		}
		return keys.FileKey, header, nil
	}

	backupKey, err := unsealEnvelope(blocks, keys)
	if err != nil {
		return nil, nil, err
	}
	fileKey, err = deriveFileKey(backupKey, salt)
	if err != nil {
		return nil, nil, err
	}
	return fileKey, header, nil
}

// readLengthPrefixed reads one uint16-prefixed field, returning both its
// contents and the raw bytes it occupied so the caller can reassemble the
// header it has to authenticate.
func readLengthPrefixed(src io.Reader, max int) (value, raw []byte, err error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		return nil, nil, errors.Wrap(err, "failed to read the backup header")
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n > max {
		return nil, nil, errors.New("the backup is malformed: implausible header field length")
	}
	value = make([]byte, n)
	if _, err := io.ReadFull(src, value); err != nil {
		return nil, nil, errors.Wrap(err, "failed to read the backup header")
	}
	raw = append(append([]byte{}, lenBuf[:]...), value...)
	return value, raw, nil
}

// decryptBackup copies src to dst, opening it with keys.
//
// The header is read first and in full, because it is both where the key comes
// from and what every chunk is authenticated against.
func decryptBackup(dst io.Writer, src io.Reader, keys BackupKeys) error {
	magic, err := readBackupMagic(src)
	if err != nil {
		return err
	}
	fileKey, aad, err := openBackupHeader(src, magic, keys)
	if err != nil {
		return err
	}
	aead, err := newBackupAEAD(fileKey)
	if err != nil {
		return err
	}

	var counter uint64
	for {
		var chunkHeader [5]byte
		if _, err := io.ReadFull(src, chunkHeader[:]); err != nil {
			// Running out of input before the final chunk means the file was
			// truncated; the marker is what tells us the stream ended
			// legitimately.
			return errors.Wrap(err, "the backup ended before its final chunk; it is truncated")
		}
		size := binary.BigEndian.Uint32(chunkHeader[:4])
		last := chunkHeader[4] == 1
		if size > backupChunkSize+uint32(aead.Overhead()) {
			return errors.New("the backup is malformed: implausible chunk length")
		}

		sealed := make([]byte, size)
		if _, err := io.ReadFull(src, sealed); err != nil {
			return errors.Wrap(err, "the backup is truncated")
		}
		nonce := backupNonce(counter, last)
		plain, err := aead.Open(nil, nonce, sealed, aad)
		if err != nil {
			return errors.New("the backup could not be decrypted: wrong key, " +
				"or the file has been altered")
		}
		if _, err := dst.Write(plain); err != nil {
			return errors.Wrap(err, "failed to write the decrypted snapshot")
		}
		if last {
			return nil
		}
		counter++
	}
}

// backupNonce derives a chunk's nonce from its position and whether it
// terminates the stream.
//
// Binding the terminator into the nonce is what makes truncation detectable:
// a stream cut short cannot be re-sealed as if it had ended there.
func backupNonce(counter uint64, last bool) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[backupNonceCounterOffset:], counter)
	if last {
		// Flip the high bit of the counter space for the terminating chunk so
		// it can never collide with a non-final chunk's nonce.
		nonce[backupNonceCounterOffset] |= 0x80
	}
	return nonce
}

// looksEncrypted reports whether a file begins with the container magic, so
// Restore can tell a snapshot from whatever else an operator may have named.
//
// It matches the family prefix rather than the exact version, so a snapshot
// whose version this build does not read still reaches the reader that refuses
// it by number, instead of being turned away as "not a backup".
func looksEncrypted(header []byte) bool {
	return len(header) >= len(backupMagicPrefix) &&
		string(header[:len(backupMagicPrefix)]) == backupMagicPrefix
}
