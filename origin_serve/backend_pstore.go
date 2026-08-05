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

// pstoreBackend — OriginBackend for the Pelican store.
//
// The store exposes an afero.Fs, so this is the same shape as the local POSIX
// backend: wrap it in the shared aferoFileSystem adapter and hand the result
// to the generic WebDAV handler.  See docs/pstore-design.md.

package origin_serve

import (
	"context"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pstore"
	"github.com/pelicanplatform/pelican/server_utils"
)

// pstoreBackend serves an export from a pstore.Store.
//
// Several exports can share one store, each mapped onto a different subtree
// through its StoragePrefix, so the backend does not own the store it uses.
type pstoreBackend struct {
	store         *pstore.Store
	fs            webdav.FileSystem
	storagePrefix string
}

// openStores holds the stores opened during handler initialization, keyed by
// directory.
//
// A store takes an exclusive lock on its directory, so every export mapped
// onto the same location must share one -- opening a second would simply fail.
// InitializeHandlers runs single-threaded at startup, so a plain map suffices.
var openStores = map[string]*pstore.Store{}

// ResetPStoreState drops the shared stores between handler initializations.
// Only tests re-initialize handlers within one process.
func ResetPStoreState() {
	openStores = map[string]*pstore.Store{}
}

// newPStoreBackend opens the store for an export and starts its janitor.
//
// The store is opened once per export.  Each export gets its own directory
// tree, because a store assumes exclusive ownership of its directories.
func newPStoreBackend(
	ctx context.Context,
	export server_utils.OriginExport,
	logger func(*http.Request, error),
) (*pstoreBackend, error) {
	// The store spawns background workers (block-state flushing, the janitor)
	// that must live as long as the server, so they join the process-wide
	// error group the launcher stashes in the context.
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		return nil, errors.New("no error group in context; cannot start the pstore background workers")
	}

	dirs, err := local_cache.ParseStorageDirsValue(
		param.Origin_PStoreStorageDirs.GetRaw(), param.Origin_PStoreStorageDirs.GetName())
	if err != nil {
		return nil, err
	}

	baseDir := param.Origin_PStoreLocation.GetString()
	if baseDir == "" && len(dirs) > 0 {
		// The catalog lives alongside the first data directory when no
		// dedicated location is configured.
		baseDir = dirs[0].Path
	}
	if baseDir == "" {
		return nil, errors.Errorf("%s must be set when the origin storage type is 'pstore'",
			param.Origin_PStoreLocation.GetName())
	}

	// Exports mapped onto the same directory share a store; the first one
	// opens it and starts its background work.
	store, opened := openStores[baseDir]
	if !opened {
		store, err = pstore.Open(ctx, egrp, pstore.Config{
			BaseDir:        baseDir,
			StorageDirs:    dirs,
			InlineMaxBytes: param.Origin_PStoreInlineMaxBytes.GetInt(),
			NamespaceLabel: baseDir,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open the pstore at %s", baseDir)
		}
		openStores[baseDir] = store

		// Reclamation runs for the life of the server; without it, superseded
		// object versions and deleted subtrees would hold space indefinitely.
		store.StartJanitor(ctx, egrp)

		// Back up the metadata periodically.  Losing it is not recoverable
		// the way a cache's database is: the block files are unreadable
		// without it.
		backupKeys, kErr := pstoreBackupKeys()
		if kErr != nil {
			return nil, kErr
		}
		store.StartBackups(ctx, egrp, pstore.BackupConfig{
			Dir:      param.Origin_PStoreMetadataBackupLocation.GetString(),
			Interval: param.Origin_PStoreMetadataBackupInterval.GetDuration(),
			Keep:     param.Origin_PStoreMetadataBackupsToKeep.GetInt(),
			Keys:     backupKeys,
		})

		// Check the store against itself on a schedule.  An origin needs this
		// more than a cache does: a cache that finds a corrupt object
		// re-fetches it, and an origin has nowhere to re-fetch from.
		store.StartIntegrityChecks(ctx, egrp, pstore.IntegrityConfig{
			IndexInterval:       param.Origin_PStoreIndexCheckInterval.GetDuration(),
			DataInterval:        param.Origin_PStoreDataScanInterval.GetDuration(),
			DataScanBytesPerSec: int64(param.Origin_PStoreDataScanRate.GetByteRate()),
		})

		// Close the store when the server context is cancelled.
		//
		// Nothing in the origin's shutdown path knows about backends, so
		// without this the block store's TTL-cache workers -- which only stop
		// on StorageManager.Close -- outlive the server and the process error
		// group never drains, hanging shutdown indefinitely.
		egrp.Go(func() error {
			<-ctx.Done()
			if cErr := store.Close(); cErr != nil {
				log.Warnf("Failed to close the pstore at %s: %v", baseDir, cErr)
			}
			return nil
		})
	}

	// The export's StoragePrefix is a logical subtree inside the store rather
	// than a filesystem path, and the shared adapter already joins it onto
	// every request path.
	//
	// pstore.FS creates missing parents itself rather than using the shared
	// autoCreateDirFs wrapper: that wrapper derives the parent with filepath,
	// and a pstore path is a namespace path that is always slash-separated,
	// so on Windows it would ask for a directory named "\a\b\c".
	fs := newAferoFileSystem(pstore.NewFS(store), export.StoragePrefix, logger)

	return &pstoreBackend{store: store, fs: fs, storagePrefix: export.StoragePrefix}, nil
}

func (b *pstoreBackend) CheckAvailability() error      { return nil }
func (b *pstoreBackend) FileSystem() webdav.FileSystem { return b.fs }

// Checksummer serves Want-Digest from the checksums recorded at ingest.
func (b *pstoreBackend) Checksummer() server_utils.OriginChecksummer {
	return &pstoreChecksummer{store: b.store, storagePrefix: b.storagePrefix}
}

// pstoreChecksummer answers Want-Digest from stored metadata.
//
// Unlike the POSIX backend's xattr scheme this never reads the object: the
// digests were computed while the bytes were being written, so the response
// costs one metadata lookup no matter how large the object is.  The digests
// also belong to the specific version, so an overwrite cannot leave a stale
// value behind the way an mtime-validated xattr cache can.
type pstoreChecksummer struct {
	store         *pstore.Store
	storagePrefix string
}

// GetDigests returns RFC 3230 digest strings for the algorithms the client
// asked for, skipping any that were not recorded.
func (c *pstoreChecksummer) GetDigests(relativePath string, wantDigest string) ([]string, error) {
	if wantDigest == "" {
		return nil, nil
	}

	// The store holds objects under the export's storage prefix, which the
	// WebDAV layer strips before handing the path here.
	//
	// The join is re-confined rather than trusted: path.Join normalizes away
	// any ".." in the relative path, so a HEAD for "/../two/secret.txt"
	// resolved into a neighbouring export's subtree and this method answered
	// with its real digests.  The handler now cleans the path before calling,
	// but a checksum lookup that silently addresses another tenant's object is
	// not something to leave depending on one caller doing the right thing.
	full, err := confineToPrefix(c.storagePrefix, relativePath)
	if err != nil {
		log.Warnf("Refusing a digest lookup for %s: outside the export's storage prefix", relativePath)
		return nil, err
	}

	stored, err := c.store.Digests(full)
	if err != nil {
		// A missing object or one written before checksums were recorded is
		// not an error: the handler simply omits the Digest header.
		log.Debugf("No stored digests for %s: %v", relativePath, err)
		return nil, nil
	}

	byType := make(map[local_cache.ChecksumType]local_cache.Checksum, len(stored))
	for _, c := range stored {
		byType[c.Type] = c
	}

	var out []string
	for _, alg := range strings.Split(wantDigest, ",") {
		t, ok := local_cache.ParseChecksumAlgorithm(alg)
		if !ok {
			continue
		}
		if c, have := byType[t]; have {
			// Naming and encoding come from local_cache so the origin cannot
			// drift from the value the cache would report for the same bytes.
			if entry := local_cache.FormatDigestEntry(c); entry != "" {
				out = append(out, entry)
			}
		}
	}
	return out, nil
}

// Close releases the store this backend uses.
//
// Only safe when the backend is the sole user of that store, which is the
// case in tests; in the server the store is shared between exports and closed
// once, from the goroutine watching the server context.
func (b *pstoreBackend) Close() error { return b.store.Close() }

// HasCapacityFor implements server_utils.CapacityReporter so the origin can
// refuse an oversized PUT with 507 before the client streams its body.
func (b *pstoreBackend) HasCapacityFor(nBytes int64) error {
	return b.store.HasCapacityFor(nBytes)
}

// pstoreBackupKeys resolves the keys metadata snapshots are sealed to.
//
// The store does not read configuration itself -- pstore deliberately does not
// import config -- so the resolution happens here and the result is handed in.
//
// Every current issuer key is a recipient, which is what makes rotation free: a
// snapshot written before a rotation still opens with either the key that has
// since been retired or the one that was already present.  There is deliberately
// no way to configure a different key: the scheme derives everything an operator
// could need from the issuer keys, and the per-archive key an outside custodian
// should be given is printed per file by `pelican-server origin pstore
// metadata-backup-key <file>` rather than fixed for the whole series.
func pstoreBackupKeys() (pstore.BackupKeys, error) {
	issuerKeys := config.GetIssuerPrivateKeys()
	if len(issuerKeys) == 0 && param.Origin_PStoreMetadataBackupLocation.GetString() != "" {
		return pstore.BackupKeys{}, errors.Errorf(
			"metadata backups are enabled (%s) but the origin has no issuer keys to "+
				"derive a backup key from; a snapshot is a logical dump of the namespace "+
				"and is never written unencrypted",
			param.Origin_PStoreMetadataBackupLocation.GetName())
	}
	return pstore.BackupKeys{IssuerKeys: issuerKeys}, nil
}
