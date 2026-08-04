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

// Getting data back out.
//
// A store is not something an operator can read with ordinary tools, so the
// recovery path has to be part of the product rather than an exercise left to
// whoever is having the bad day.  Export writes objects out as plain files in
// a normal directory tree: no Pelican, no origin, no client -- just the data.
//
// # What a recovery needs
//
// Three things, and they are separate on purpose so they can be stored
// separately -- and so that losing one does not mean losing the store:
//
//   - the catalog, from a metadata snapshot or from the store itself;
//   - the block files, whatever ordinary tool backed them up; and
//   - masterkey.json, which wraps the key the block files are encrypted under.
//
// Export runs against a store opened for maintenance, so the usual route is to
// restore a snapshot into a directory holding the block files and
// masterkey.json, then export from that.
//
// # Two key hierarchies, and why that is not a contradiction
//
// It is easy to read backup.go and conclude that the backup keys are all an
// operator needs to escrow.  They are not, and the difference is worth being
// precise about because a recovery is a bad time to discover it.  There are two
// unrelated mechanisms:
//
//   - The **metadata-backup keys** (backup.go, backup_crypto.go) open a
//     *snapshot file*.  Any one of an issuer key, the escrowed backup key, or
//     that archive's own file key decrypts the container and yields the catalog:
//     paths, sizes, checksums, generations, and each object's data key.
//   - **masterkey.json** holds the store's *data* master key, which every block
//     file is encrypted under.  It lives in the store's base directory and is
//     itself sealed to the origin's issuer keys, one wrapped copy per key ID, so
//     opening it requires one of those issuer keys.  It has nothing to do with
//     the backup key hierarchy and is not derived from it.
//
// The consequence an operator has to plan around: **escrowing the backup key
// buys the catalog, not the data.**  With it and a snapshot you can read the
// namespace -- every path, size and checksum -- and nothing else.  Turning that
// back into objects also needs the block files *and* masterkey.json, and
// masterkey.json is useless without one of the issuer keys it was sealed to.
// So an issuer key has to survive, or be escrowed alongside the backup key; the
// backup key alone is not a complete recovery plan.

package pstore

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// ExportOptions controls a recovery export.
type ExportOptions struct {
	// Root is the subtree to export; empty means the whole store.
	Root string
	// Dest is the directory to write into.  It is created if missing.
	Dest string
	// Verify checks each object against its recorded checksums as it is
	// written, so a recovery does not quietly reproduce corrupt data.
	Verify bool
	// DryRun reports what would be written without writing it.
	DryRun bool
	// Resume skips objects already present in the destination instead of
	// reporting them.
	//
	// An export of a large store is interrupted sooner or later -- a full
	// disk, a lost session, an operator's Ctrl-C -- and the natural response
	// is to run it again.  Without this the second run reports every file the
	// first one wrote as a failure, which is indistinguishable from real
	// corruption at exactly the moment an operator most needs to tell the
	// difference.
	Resume bool
}

// ExportReport summarizes a recovery export.
type ExportReport struct {
	// FilesWritten is how many objects were exported.
	FilesWritten int
	// DirsCreated is how many directories were created.
	DirsCreated int
	// BytesWritten totals the object content exported.
	BytesWritten int64
	// Failed lists objects that could not be exported, with the reason.
	// A recovery continues past a bad object rather than abandoning the rest.
	Failed map[string]string
	// AlreadyPresent counts objects skipped because the destination already
	// held a file of that name.
	//
	// Kept apart from Failed on purpose.  "The previous run already wrote
	// this" and "this object cannot be read" call for opposite responses, and
	// a report that conflates them turns a resumed export into a false
	// corruption report.
	AlreadyPresent int
}

// Export writes a subtree out as ordinary files.
//
// It continues past objects it cannot read, collecting them in the report: on
// a damaged store, recovering most of the data and being told exactly what was
// lost is far more useful than stopping at the first bad block.
func (s *Store) Export(ctx context.Context, opts ExportOptions) (*ExportReport, error) {
	if opts.Dest == "" {
		return nil, errors.New("a destination directory is required")
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}
	cleanRoot, err := cleanRelative(root)
	if err != nil {
		return nil, err
	}

	report := &ExportReport{Failed: map[string]string{}}
	if !opts.DryRun {
		if err := os.MkdirAll(opts.Dest, 0750); err != nil {
			return nil, errors.Wrapf(err, "cannot create %s", opts.Dest)
		}
	}
	return report, s.exportDir(ctx, cleanRoot, cleanRoot, opts, report)
}

// exportDir walks one directory, recursing into children.
//
// It pages through the listing rather than materializing it, so exporting a
// directory with a very large number of entries does not need them all in
// memory at once.
func (s *Store) exportDir(ctx context.Context, dir, root string, opts ExportOptions, report *ExportReport) error {
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, more, err := s.List(dir, after, 512)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s", dir)
		}
		if len(entries) == 0 {
			return nil
		}

		for _, e := range entries {
			childPath := joinPath(dir, e.Name)
			localPath, lErr := destinationFor(root, childPath, opts.Dest)
			if lErr != nil {
				report.Failed[childPath] = lErr.Error()
				continue
			}

			if e.Dirent.IsDir() {
				if !opts.DryRun {
					if mErr := os.MkdirAll(localPath, 0750); mErr != nil {
						report.Failed[childPath] = mErr.Error()
						continue
					}
				}
				report.DirsCreated++
				if rErr := s.exportDir(ctx, childPath, root, opts, report); rErr != nil {
					return rErr
				}
				continue
			}

			n, fErr := s.exportFile(childPath, localPath, opts)
			if errors.Is(fErr, errAlreadyExported) {
				report.AlreadyPresent++
				continue
			}
			if fErr != nil {
				report.Failed[childPath] = fErr.Error()
				log.Warnf("Could not export %s: %v", childPath, fErr)
				continue
			}
			report.FilesWritten++
			report.BytesWritten += n
		}

		if !more {
			return nil
		}
		after = entries[len(entries)-1].Name
	}
}

// errAlreadyExported marks an object a resumed run found already in place.
var errAlreadyExported = errors.New("already exported")

// exportFile writes one object out.
func (s *Store) exportFile(objectPath, localPath string, opts ExportOptions) (int64, error) {
	if opts.Resume && !opts.DryRun {
		// Checked before the (expensive) verification so that resuming a
		// --verify export does not re-read every object it already wrote.
		if _, err := os.Stat(localPath); err == nil {
			return 0, errAlreadyExported
		}
	}
	if opts.Verify {
		ok, err := s.VerifyObject(objectPath)
		if err != nil {
			return 0, errors.Wrap(err, "could not verify")
		}
		if !ok {
			return 0, errors.New("data does not match its recorded checksums")
		}
	}
	if opts.DryRun {
		d, err := s.Stat(objectPath)
		if err != nil {
			return 0, err
		}
		return d.Size, nil
	}

	r, err := s.OpenRead(objectPath)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0750); err != nil {
		return 0, err
	}
	// Exclusive create: a recovery must never silently overwrite whatever is
	// already in the destination.  Losing the race with a concurrent writer
	// reads the same as finding the file already there, which is what --resume
	// is for.
	f, err := os.OpenFile(localPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		if opts.Resume && os.IsExist(err) {
			return 0, errAlreadyExported
		}
		return 0, err
	}
	defer f.Close()

	n, err := io.Copy(f, r)
	if err != nil {
		return n, err
	}
	return n, f.Sync()
}

// destinationFor maps an object path to its place under the destination
// directory, refusing anything that would escape it.
func destinationFor(root, objectPath, dest string) (string, error) {
	rel := strings.TrimPrefix(objectPath, root)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", errors.Errorf("%s is the export root", objectPath)
	}

	// Object paths are validated on the way in, but a recovery may be run
	// against a damaged or hand-edited catalog, so the destination is checked
	// rather than trusted.
	local := filepath.Join(dest, filepath.FromSlash(rel))
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	absLocal, err := filepath.Abs(local)
	if err != nil {
		return "", err
	}
	if absLocal != absDest && !strings.HasPrefix(absLocal, absDest+string(os.PathSeparator)) {
		return "", errors.Errorf("%s would be written outside the destination", objectPath)
	}
	return local, nil
}
