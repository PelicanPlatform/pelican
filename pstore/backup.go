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

// Metadata backup and restore: the container and the policy.
//
// This file owns what a snapshot *is* -- when one is taken, what goes in it,
// how it is published, pruned, and loaded back.  backup_crypto.go owns the
// other half: the envelope that carries the key and the AES-256-GCM sealing of
// the body under it.  The split is one of policy and mechanism, and the rule
// that lives here is that there is exactly one container and it is sealed:
// there is no unencrypted path out of this package, and nothing to dispatch on.
//
// For a cache, losing the database is an inconvenience: every object in it can
// be fetched again from an origin.  For an origin it is data loss.  The block
// files on disk are named by hash and encrypted, and everything needed to
// interpret them -- the namespace, each object's data key, its size, its
// checksums -- lives in the catalog.  A store whose catalog is gone is a
// directory of unreadable bytes.
//
// So the catalog -- the metadata -- is backed up separately from the data,
// and far more often than its size would suggest is necessary.  It is small (megabytes against
// terabytes of objects) and BadgerDB can stream a consistent snapshot of it
// while the origin is running, so a periodic snapshot costs almost nothing.
//
// A backup is only useful alongside two other things, and the CLI says so
// rather than letting an operator discover it during a recovery:
//
//   - the block files, which ordinary filesystem backup tools handle; and
//   - masterkey.json, which wraps the key everything is encrypted under.  It
//     is itself encrypted under the origin's issuer keys, so those must
//     survive too.
//
// # What a sealed snapshot contains, and what opens it
//
// An archive is not merely ciphertext: it carries the material needed to open
// itself, to anyone who holds one of three keys.  Its header holds
//
//   - a 32-byte salt drawn for this snapshot alone, and
//   - one envelope block per recipient, each carrying **the archive's backup
//     key sealed to one of the origin's current issuer keys** (or, when
//     BackupKeys.BackupKey is supplied, to that key instead).
//
// The body is encrypted under a per-file key = HKDF(backup key, salt), so the
// three ways into an archive are:
//
//   - an **issuer key** -- derive its pstore key pair, open its envelope block,
//     recover the backup key, derive the per-file key;
//   - the **escrowed backup key** -- open its own envelope block, which yields
//     the archive's backup key, and derive from there;
//   - that **one archive's file key** -- decrypt directly, with no envelope and
//     no issuer key present anywhere.
//
// The property this buys, and the reason the backup key is embedded rather than
// left implicit: **losing the origin's issuer keys does not lose the archives,
// provided the backup key was escrowed.**  An archive also survives a key
// rotation, because it opens with any issuer key that was current when it was
// written.  See backup_crypto.go for the derivation, the envelope layout, and
// what is authenticated.
//
// These three keys open the *catalog*, and nothing else.  They are unrelated to
// masterkey.json, which is what makes the block files readable and which is
// sealed to the issuer keys directly -- so an escrowed backup key on its own
// recovers the namespace but not one byte of object data.  recover.go states
// the whole of what a recovery needs; it is the thing to read before deciding
// what to escrow.
//
// # Why a backup is not just BadgerDB's stream
//
// BadgerDB's backup is a sequence of length-prefixed protobuf frames, and its
// loader treats a clean EOF at any frame boundary as the end of a complete
// backup.  Written straight to a file, a snapshot truncated at a frame
// boundary -- a full disk, a killed process, a partial copy off the host --
// restores with no error and fewer objects than it had, or none at all.  For a
// primary store that is the worst possible failure: it is silent, and it is
// discovered during a recovery.
//
// So a metadata backup is a container, and the container gets that property
// from its AEAD construction: chunks are bound to their position and the last
// one is marked, so truncation and splicing both fail to open rather than
// restoring part of a catalog.  Every snapshot this package publishes uses it,
// because a snapshot is a logical dump of the namespace and must never be
// written in the clear.

package pstore

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
)

// BackupEncrypted writes a snapshot sealed to keys.
//
// This is the only way to write a snapshot.  Encryption is not optional and
// there is no key to forget to configure: the archive's backup key is derived
// from the origin's issuer keys unless one is supplied outright, and a caller
// that can produce neither gets an error rather than a cleartext dump of the
// namespace.
//
// **What ends up in the file** is the compressed catalog encrypted under a key
// belonging to this snapshot alone, preceded by a header that carries the salt
// that key was derived from *and the archive's backup key sealed once per
// recipient* -- one recipient per issuer key in keys.IssuerKeys, or the single
// supplied keys.BackupKey when there is one.  Embedding the sealed backup key
// is what makes the file self-opening: any of those issuer keys reaches it, and
// so does the escrowed backup key on a machine that has never held them.  An
// operator who escrowed the backup key can restore this file after the issuer
// keys are gone.  See backup_crypto.go for the derivation and the envelope.
//
// Truncation and tampering are detected by the AEAD construction itself, so
// there is no second framing layer inside the sealed one.
func (s *Store) BackupEncrypted(w io.Writer, keys BackupKeys) (uint64, error) {
	// BadgerDB writes the snapshot rather than handing it back, so bridge the
	// two with a pipe instead of buffering a whole catalog in memory.
	pr, pw := io.Pipe()

	var (
		version uint64
		bErr    error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Compress on the way to the sealer: a catalog is mostly repeated
		// path strings and near-identical metadata records, so it shrinks a
		// great deal, and ciphertext would not compress at all afterwards.
		zw := gzip.NewWriter(pw)
		version, bErr = s.bdb.Backup(zw, 0)
		if bErr == nil {
			bErr = zw.Close()
		}
		pw.CloseWithError(bErr)
	}()

	if err := encryptBackup(w, pr, keys); err != nil {
		pr.CloseWithError(err)
		<-done
		return 0, err
	}
	<-done
	if bErr != nil {
		return 0, errors.Wrap(bErr, "failed to back up the pstore metadata")
	}
	return version, nil
}

// restoreEncrypted loads a snapshot sealed by BackupEncrypted.
func (s *Store) restoreEncrypted(r io.Reader, keys BackupKeys) error {
	pr, pw := io.Pipe()

	// The decryption error is kept rather than only propagated through the
	// pipe, because it is the one an operator can act on.  A wrong key, an
	// unreadable format version and a damaged header all surface here as "gzip:
	// invalid header" on the reading side; reporting that instead would replace
	// a sentence naming the key IDs the archive needs with one naming a
	// compression library.
	var decErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		decErr = decryptBackup(pw, r, keys)
		pw.CloseWithError(decErr)
	}()

	zr, err := gzip.NewReader(pr)
	if err != nil {
		pr.CloseWithError(err)
		<-done
		if decErr != nil {
			return decErr
		}
		return errors.Wrap(err, "the snapshot is not readable after decryption")
	}
	defer zr.Close()

	if err := s.restoreStream(zr); err != nil {
		pr.CloseWithError(err)
		<-done
		return err
	}
	<-done
	return nil
}

// Restore loads a metadata backup into this store.
//
// There is one container and it is sealed, so the only question the file itself
// answers is whether it is a pstore snapshot at all: a file without the magic is
// refused as "not a backup", and one whose format version this build does not
// read is refused by number rather than misparsed.  The two are separate
// messages on purpose -- they send an operator to different places.
//
// **Any one of three keys opens an archive**, and keys may carry whichever the
// operator still has:
//
//   - keys.IssuerKeys -- the origin's issuer keys, the ordinary case on the
//     origin itself.  Any single key the archive was sealed to is enough, so a
//     rotation does not strand the archives that overlapped it.
//   - keys.BackupKey -- the escrowed backup key from DeriveBackupKey.  The
//     archive carries its own backup key sealed to this one, so this restores
//     on a machine that has never held the origin's issuer keys.  **Escrowing
//     it is what makes the loss of the issuer keys survivable.**
//   - keys.FileKey -- that one archive's own key from DeriveFileKey, which
//     opens it and nothing else.
//
// The store must be empty: restoring over live records would interleave two
// namespaces rather than replace one.
//
// **A failed restore is not a no-op.**  BadgerDB's loader writes as it reads,
// so a snapshot that turns out to be truncated or damaged part-way through
// leaves records in the directory and this handle unusable.  There is no way
// to unwind that from here; the directory has to be discarded and the restore
// started again into a fresh one.  This is why the container authenticates its
// header before a byte of the body is opened and marks its terminating chunk:
// most damage is caught before a single record is written, and what is caught
// late says plainly what state it left behind.
//
// **The store must be reopened afterwards.**  A restore replaces the whole
// database, including everything a store reads once at open and then caches:
// the hash salt that every instance hash is derived from, and the mapping
// from storage IDs to directories.  Continuing to use the handle would
// compute hashes that match nothing and look for block files under empty
// paths.  The salt is refreshed here so that a caller inspecting the
// namespace immediately after a restore sees the right thing, but reading
// object data requires a fresh open.
func (s *Store) Restore(r io.Reader, keys BackupKeys) error {
	// Cheapest precondition first: a store that cannot be written to will not
	// become restorable further down, and reporting "this file is too short"
	// for it would send an operator after the wrong problem.
	if err := s.checkWritable(); err != nil {
		return err
	}

	// Recognize the container before handing the file to the decryption
	// pipeline, so that a file which is not a snapshot at all is named as such.
	// Peek rather than read: the reader below wants its own magic back.
	//
	// This is the message an operator sees after pointing `metadata-restore` at
	// the wrong path, or at a bare BadgerDB dump -- which is the dangerous one,
	// because BadgerDB's loader would happily accept a truncated dump and
	// restore a fraction of a namespace without complaint.
	br := bufio.NewReader(r)
	magic, err := br.Peek(len(backupMagicPrefix))
	if err != nil && len(magic) < len(backupMagicPrefix) {
		return errors.Wrap(err, "this file is too short to be a pstore metadata backup")
	}
	if !looksEncrypted(magic) {
		return errors.New("this file is not a pstore metadata backup: it does not begin with " +
			"the container magic. Every snapshot pstore writes carries one, so this is either " +
			"not a snapshot -- a raw database dump, or another file entirely -- or a snapshot " +
			"that has lost its opening bytes")
	}
	return s.restoreEncrypted(br, keys)
}

// restoreStream loads an already-unwrapped BadgerDB stream.
//
// r must fail rather than report EOF when its input was truncated, which the
// sealed container's reader does: its terminating chunk is the only clean end
// of stream.
func (s *Store) restoreStream(r io.Reader) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	empty, err := s.isEmpty()
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("refusing to restore into a store that already holds objects; " +
			"restore into an empty directory instead")
	}
	if err := s.bdb.Load(r, restoreMaxPendingWrites); err != nil {
		// A load that stops part-way through leaves records behind *and*
		// leaves BadgerDB's transaction watermark short of the timestamps it
		// already wrote, so this handle will block on the next read and the
		// directory holds a fragment of a namespace.  Nothing here can undo
		// either; what it can do is say so, rather than let an operator retry
		// into the same directory and build a chimera out of two catalogs.
		return errors.Wrap(err,
			"failed to restore the pstore metadata; this directory now holds a partial "+
				"catalog and must be discarded -- restore into a fresh one")
	}

	// Load replaces the database wholesale, header keys included, so the
	// schema version that was checked when this store opened is not the one
	// now on disk.  A snapshot taken by a newer Pelican carries a newer
	// layout, and nothing else would notice: the open-time check has already
	// run.  Re-verify against what the restore actually wrote.
	if err := s.db.VerifySchemaVersion(); err != nil {
		return errors.Wrap(err,
			"the restored catalog was written by a newer Pelican; this directory must be "+
				"discarded and the restore repeated with a build that supports it")
	}

	// The restore replaced the database's contents, including the hash salt
	// every instance hash in it was derived from.  The salt cached when this
	// store opened is now the wrong one, and using it would compute hashes
	// that match nothing -- a restored catalog whose objects all appear
	// missing.
	if err := s.db.ReloadSalt(); err != nil {
		return err
	}

	// Detached-subtree state belongs to the restored catalog too.
	s.detached = newDetachedSet()
	return s.reloadDetached()
}

// restoreMaxPendingWrites bounds BadgerDB's write concurrency during a load.
const restoreMaxPendingWrites = 256

// isEmpty reports whether the namespace holds no entries.
func (s *Store) isEmpty() (bool, error) {
	entries, _, err := s.List("/", "", 1)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// ---------------------------------------------------------------------------
// The scheduled backup
// ---------------------------------------------------------------------------

// StartBackups snapshots the catalog to dir every interval, for as long as the
// context lives.
//
// Each pass writes a new timestamped file and prunes the oldest beyond keep,
// so a corrupted catalog can be rolled back to rather than only forward from.
// A failed pass is logged and retried at the next interval: a backup problem
// must not take the origin down.
//
// One snapshot is taken immediately.  Waiting for the first interval to elapse
// means an unwritable backup directory -- the wrong owner, a full filesystem, a
// typo in the configured path -- goes unreported for a whole interval, and a
// store that dies inside its first hour has no metadata backup at all, which is
// the case backups exist for.
//
// After that the interval is a gap, not a cadence: the next snapshot starts an
// interval after the previous one *finished*.  A snapshot of a large catalog is
// not instant, and the six-hour default is close enough to the time one can take
// that a fixed cadence would have the origin snapshotting back to back.  See
// runPeriodically in integrity.go.
func (s *Store) StartBackups(ctx context.Context, egrp *errgroup.Group, cfg BackupConfig) {
	if cfg.Dir == "" || cfg.Interval <= 0 {
		return
	}
	if cfg.Keys.Empty() {
		// Refusing outright is the point of the change that made encryption
		// mandatory.  The alternative -- warning and writing cleartext -- put a
		// dump of the whole namespace on disk for anyone who did not read the
		// log, which is everyone.
		log.Errorf("No keys are available to encrypt pstore metadata backups, so the "+
			"origin's metadata is NOT being backed up to %s. A snapshot is a logical dump "+
			"of the namespace and is never written unencrypted.", cfg.Dir)
		return
	}
	// Fail the obvious way at startup rather than an interval later.
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		log.Errorf("pstore metadata backup directory %s is not usable, so the origin's "+
			"metadata is NOT being backed up: %v", cfg.Dir, err)
	}
	egrp.Go(func() error {
		s.runBackupLoop(ctx, cfg, realSchedule())
		return nil
	})
	log.Infof("pstore metadata backups every %s to %s (keeping %d)",
		cfg.Interval, cfg.Dir, cfg.Keep)
}

// runBackupLoop takes the startup snapshot and then one per interval.
//
// Split out of StartBackups so the schedule can be driven by a test; everything
// above it is validation and logging that a test would only have to work
// around.
func (s *Store) runBackupLoop(ctx context.Context, cfg BackupConfig, sched schedule) {
	// The startup snapshot is observed exactly like a scheduled one.  Leaving
	// it out would mean a store whose very first backup fails looks like a
	// store that has simply not been up long enough to snapshot yet -- and the
	// startup snapshot exists precisely because that first hour is the window
	// backups are most often silently broken in.
	observedSnapshot := func() error {
		pass := beginPass(metrics.PStorePassMetadataBackup, cfg.Interval, sched)
		err := s.snapshotOnce(cfg)
		pass.finish(err == nil)
		return err
	}

	if err := observedSnapshot(); err != nil {
		// Loud: at startup this is almost always a misconfiguration the
		// operator can fix now, rather than discover during a recovery.
		log.Errorf("Initial pstore metadata backup failed: %v", err)
	}

	runPeriodically(ctx, cfg.Interval, sched, "metadata backup", func() {
		if err := observedSnapshot(); err != nil {
			log.Warnf("pstore metadata backup failed: %v", err)
		}
	})
}

// BackupConfig describes the periodic metadata backup.
type BackupConfig struct {
	// Dir receives the snapshot files.  Empty disables backups.
	Dir string
	// Interval between snapshots.
	Interval time.Duration
	// Keep bounds how many snapshots are retained; zero keeps them all.
	Keep int
	// Keys seal each snapshot.  They are supplied by the caller rather than
	// read from configuration here, so this package stays independent of
	// config and a test can seal to keys of its own.  Backups do not start
	// without them: a snapshot is a logical dump and is never written in the
	// clear.
	Keys BackupKeys
}

// metadataBackupPrefix names the metadata backups so pruning can recognize
// its own output and leave anything else in the directory alone.
const metadataBackupPrefix = "pstore-metadata-"

// snapshotOnce writes one snapshot and prunes older ones.
//
// It writes to a temporary name, flushes it to stable storage, and only then
// renames, so neither a crash nor a power cut can publish a truncated file
// under a name that pruning will count towards retention.  The rename alone
// is not enough: it orders nothing against the data, so a machine that loses
// power just after the rename can come back with the directory entry present
// and the file's contents partly unwritten.
func (s *Store) snapshotOnce(cfg BackupConfig) error {
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return errors.Wrapf(err, "failed to create the backup directory %s", cfg.Dir)
	}

	name := metadataBackupPrefix + time.Now().UTC().Format("20060102T150405Z") + ".pmb"
	final := filepath.Join(cfg.Dir, name)
	tmp := final + ".partial"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s", tmp)
	}
	_, bErr := s.BackupEncrypted(f, cfg.Keys)
	if bErr != nil {
		f.Close()
		_ = os.Remove(tmp)
		return bErr
	}
	if sErr := f.Sync(); sErr != nil {
		f.Close()
		_ = os.Remove(tmp)
		return errors.Wrapf(sErr, "failed to flush %s to disk", tmp)
	}
	// Read the size off the handle we already hold, before it is closed.  A
	// snapshot that keeps succeeding while shrinking against a growing store
	// is a real failure mode -- a backup that captures nothing -- and it has
	// no other symptom until a recovery.
	var size int64
	if fi, stErr := f.Stat(); stErr == nil {
		size = fi.Size()
	}
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(cErr, "failed to finish writing %s", tmp)
	}
	if rErr := os.Rename(tmp, final); rErr != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(rErr, "failed to publish %s", final)
	}
	// Only once the snapshot is published under its final name: a size for a
	// file that was never renamed describes a backup that does not exist.
	metrics.PStoreMetadataBackupLastSizeBytes.Set(float64(size))
	// Durably record the rename too, so the published name cannot outlive a
	// crash while pointing at a file the filesystem has forgotten.
	syncDir(cfg.Dir)

	log.Debugf("Wrote pstore metadata backup %s", final)
	return s.pruneSnapshots(cfg)
}

// syncDir flushes a directory's own entries.
//
// Best effort: some platforms (notably Windows) do not allow opening a
// directory for this, and there the rename's durability is the filesystem's
// business rather than ours.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// pruneSnapshots removes the oldest snapshots beyond the retention count.
func (s *Store) pruneSnapshots(cfg BackupConfig) error {
	if cfg.Keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return errors.Wrapf(err, "failed to read the backup directory %s", cfg.Dir)
	}

	var snapshots []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), metadataBackupPrefix) &&
			strings.HasSuffix(e.Name(), ".pmb") {
			snapshots = append(snapshots, e.Name())
		}
	}
	if len(snapshots) <= cfg.Keep {
		return nil
	}

	// The timestamp is fixed-width, so lexical order is chronological.
	sort.Strings(snapshots)
	for _, name := range snapshots[:len(snapshots)-cfg.Keep] {
		if rErr := os.Remove(filepath.Join(cfg.Dir, name)); rErr != nil {
			log.Warnf("Failed to prune old pstore metadata backup %s: %v", name, rErr)
		}
	}
	return nil
}
