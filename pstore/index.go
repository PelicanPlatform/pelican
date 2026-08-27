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

// The pstore directory index.
//
// Entries are keyed by parent path and name:
//
//	pd:<parent path>\x00<name>
//
// so that a directory's direct children form one contiguous, name-ordered key
// range.  Listing a single directory — the dominant operation — is a
// sequential scan with no seeks and no filtering.  Both files and directories
// are entries under their parent, so a directory needs no marker record and an
// empty directory is as real as any other entry.
//
// A subtree spans two contiguous ranges: the direct children under
// pd:<path>\x00, and everything deeper under the prefix pd:<path>/, because
// every node below the direct children has a parent path beginning with
// "<path>/".  Both are sequential; see docs/pstore-design.md §4.
//
// NUL is the separator precisely because it cannot appear in a path component
// (validatePath rejects it), which is what makes the encoding unambiguous.

package pstore

import (
	"bytes"
	"path"
	"strings"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/pelicanplatform/pelican/local_cache"
)

// EntryType distinguishes files from directories in a dirent.
type EntryType uint8

const (
	// EntryFile is a regular object.
	EntryFile EntryType = 0
	// EntryDir is a directory.
	EntryDir EntryType = 1
)

// direntSeparator separates a parent path from a child name in an index key.
// It is NUL because path components may not contain it (see validatePath).
const direntSeparator = 0x00

// Dirent is one entry in a directory.
//
// Size, MTimeNanos, and Generation are denormalized from the object's
// CacheMetadata so that a listing is a single scan: without them, a PROPFIND
// over a large directory would need one additional point lookup per child.
// They are rewritten only at commit, in a transaction the write path performs
// anyway.
type Dirent struct {
	Type       EntryType `msgpack:"t"`
	Generation string    `msgpack:"g,omitempty"` // files only; also the ETag
	Size       int64     `msgpack:"s,omitempty"`
	MTimeNanos int64     `msgpack:"m"`
	Mode       uint32    `msgpack:"o"`
}

// IsDir reports whether the entry is a directory.
func (d *Dirent) IsDir() bool { return d.Type == EntryDir }

// direntKey returns the index key for the entry at the given absolute path.
//
// The path must already be validated and cleaned.  The root has no parent and
// therefore no dirent; callers must not pass it.
func direntKey(cleanPath string) []byte {
	parent, name := splitPath(cleanPath)
	return childKey(parent, name)
}

// childKey returns the index key for name within parent.
func childKey(parent, name string) []byte {
	var b bytes.Buffer
	b.Grow(len(local_cache.PrefixDirent) + len(parent) + 1 + len(name))
	b.WriteString(local_cache.PrefixDirent)
	b.WriteString(parent)
	b.WriteByte(direntSeparator)
	b.WriteString(name)
	return b.Bytes()
}

// childrenPrefix returns the key prefix covering exactly the direct children
// of the directory at parent.
func childrenPrefix(parent string) []byte {
	var b bytes.Buffer
	b.Grow(len(local_cache.PrefixDirent) + len(parent) + 1)
	b.WriteString(local_cache.PrefixDirent)
	b.WriteString(parent)
	b.WriteByte(direntSeparator)
	return b.Bytes()
}

// descendantsPrefix returns the key prefix covering every node strictly below
// the direct children of dir — that is, all entries whose parent path begins
// with "<dir>/".
//
// For the root this is the whole index, since every parent path begins with
// "/". Callers that need the root's full subtree should use the index prefix
// directly; isRootPath reports that case.
func descendantsPrefix(dir string) []byte {
	if isRootPath(dir) {
		return []byte(local_cache.PrefixDirent)
	}
	return []byte(local_cache.PrefixDirent + dir + "/")
}

// splitPath divides an absolute, cleaned path into its parent directory and
// final component.
//
// This is path.Split with the two adjustments the index needs: the trailing
// separator is dropped from the parent, since keys are built from an exact
// parent path, and a top-level entry reports "/" rather than the empty string.
func splitPath(cleanPath string) (parent, name string) {
	dir, name := path.Split(cleanPath)
	if dir == "/" || dir == "" {
		return "/", name
	}
	return strings.TrimSuffix(dir, "/"), name
}

// joinPath appends a child name to a parent directory path.
//
// path.Join would also Clean the result, which is wasted work here: both
// halves are already clean, and name is a single validated component.
func joinPath(parent, name string) string {
	if isRootPath(parent) {
		return "/" + name
	}
	return parent + "/" + name
}

// isRootPath reports whether p denotes the store root.
func isRootPath(p string) bool { return p == "/" }

// encodeDirent serializes a dirent for storage.
func encodeDirent(d *Dirent) ([]byte, error) {
	b, err := msgpack.Marshal(d)
	return b, errors.Wrap(err, "failed to encode directory entry")
}

// decodeDirent deserializes a stored dirent.
func decodeDirent(b []byte) (*Dirent, error) {
	var d Dirent
	if err := msgpack.Unmarshal(b, &d); err != nil {
		return nil, errors.Wrap(err, "failed to decode directory entry")
	}
	return &d, nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// getDirent reads the entry at cleanPath within the given transaction.
// It returns ErrNotExist when no entry is present.
func getDirent(txn *badger.Txn, cleanPath string) (*Dirent, error) {
	if isRootPath(cleanPath) {
		return rootDirent(), nil
	}
	item, err := txn.Get(direntKey(cleanPath))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, ErrNotExist
		}
		return nil, errors.Wrapf(err, "failed to look up %s", cleanPath)
	}
	var d *Dirent
	err = item.Value(func(val []byte) error {
		var dErr error
		d, dErr = decodeDirent(val)
		return dErr
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// rootDirent synthesizes the entry for the store root, which has no parent and
// therefore no stored record.
func rootDirent() *Dirent {
	return &Dirent{Type: EntryDir, Mode: uint32(defaultDirMode)}
}

// ListEntry pairs a child name with its dirent during a listing.
type ListEntry struct {
	Name   string
	Dirent *Dirent
}

// listDir returns the direct children of dir in name order.
//
// This is a single sequential scan over one contiguous key range: every key
// under the prefix is a direct child, so there is nothing to filter and no
// subtree to seek past.
//
// When limit is positive at most that many entries are returned, starting at
// the first name strictly greater than after (empty means start at the
// beginning).  The returned bool reports whether more entries remain.
func listDir(txn *badger.Txn, dir string, after string, limit int) ([]ListEntry, bool, error) {
	prefix := childrenPrefix(dir)

	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefix
	it := txn.NewIterator(opts)
	defer it.Close()

	start := prefix
	if after != "" {
		// Seek past the last name already returned.  Appending a zero byte
		// yields the smallest key strictly greater than the "after" key,
		// because no name may contain NUL.
		start = append(childKey(dir, after), 0x00)
	}

	entries := make([]ListEntry, 0, 16)
	more := false
	for it.Seek(start); it.ValidForPrefix(prefix); it.Next() {
		if limit > 0 && len(entries) == limit {
			more = true
			break
		}
		item := it.Item()
		name := string(item.Key()[len(prefix):])
		var d *Dirent
		if err := item.Value(func(val []byte) error {
			var dErr error
			d, dErr = decodeDirent(val)
			return dErr
		}); err != nil {
			return nil, false, errors.Wrapf(err, "failed to read entry %q in %s", name, dir)
		}
		entries = append(entries, ListEntry{Name: name, Dirent: d})
	}
	return entries, more, nil
}

// dirHasChildren reports whether dir contains at least one entry.
func dirHasChildren(txn *badger.Txn, dir string) (bool, error) {
	prefix := childrenPrefix(dir)

	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefix
	opts.PrefetchValues = false
	it := txn.NewIterator(opts)
	defer it.Close()

	it.Seek(prefix)
	return it.ValidForPrefix(prefix), nil
}

// walkSubtree invokes fn for every entry at or below dir, excluding dir
// itself.  It covers both of the subtree's contiguous ranges: the direct
// children, then everything deeper.
//
// Entries are not delivered in path order.  Every consumer — capacity
// accounting, recursive delete, rename, fsck — is order-independent.
func walkSubtree(txn *badger.Txn, dir string, fn func(entryPath string, d *Dirent) error) error {
	visit := func(prefix []byte) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			entryPath, ok := pathFromKey(item.Key())
			if !ok {
				// A key that does not decode is not ours to interpret; fsck
				// reports it rather than the hot path guessing.
				continue
			}
			var d *Dirent
			if err := item.Value(func(val []byte) error {
				var dErr error
				d, dErr = decodeDirent(val)
				return dErr
			}); err != nil {
				return errors.Wrapf(err, "failed to read entry %s", entryPath)
			}
			if err := fn(entryPath, d); err != nil {
				return err
			}
		}
		return nil
	}

	if isRootPath(dir) {
		// Every parent path begins with "/", so the root's subtree is the
		// whole index and the two ranges collapse into one.
		return visit([]byte(local_cache.PrefixDirent))
	}
	if err := visit(childrenPrefix(dir)); err != nil {
		return err
	}
	return visit(descendantsPrefix(dir))
}

// pathFromKey recovers the absolute path an index key refers to.
func pathFromKey(key []byte) (string, bool) {
	if !bytes.HasPrefix(key, []byte(local_cache.PrefixDirent)) {
		return "", false
	}
	rest := key[len(local_cache.PrefixDirent):]
	sep := bytes.IndexByte(rest, direntSeparator)
	if sep < 0 {
		return "", false
	}
	parent := string(rest[:sep])
	name := string(rest[sep+1:])
	if parent == "" || name == "" {
		return "", false
	}
	return joinPath(parent, name), true
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

// putDirent writes an entry within the given transaction.
func putDirent(txn *badger.Txn, cleanPath string, d *Dirent) error {
	if isRootPath(cleanPath) {
		return errors.New("the store root has no directory entry")
	}
	val, err := encodeDirent(d)
	if err != nil {
		return err
	}
	return errors.Wrapf(txn.Set(direntKey(cleanPath), val), "failed to write entry %s", cleanPath)
}

// deleteDirent removes an entry within the given transaction.
func deleteDirent(txn *badger.Txn, cleanPath string) error {
	if isRootPath(cleanPath) {
		return errors.New("the store root has no directory entry")
	}
	return errors.Wrapf(txn.Delete(direntKey(cleanPath)), "failed to delete entry %s", cleanPath)
}

// cleanRelative normalizes a caller-supplied path into the store's absolute,
// cleaned form and validates it.
func cleanRelative(p string) (string, error) {
	if p == "" {
		return "", errors.Wrap(ErrInvalidPath, "empty path")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if err := validatePath(cleaned); err != nil {
		return "", err
	}
	return cleaned, nil
}

// validatePath rejects paths the index cannot represent unambiguously.
//
// The NUL check is load-bearing rather than defensive: the index key encoding
// uses NUL to separate a parent path from a name, so a name containing NUL
// would make pd:/a\x00b ambiguous between the file /a/b and a file literally
// named "a\x00b" at the root.
func validatePath(cleanPath string) error {
	if !strings.HasPrefix(cleanPath, "/") {
		return errors.Wrapf(ErrInvalidPath, "path %q is not absolute", cleanPath)
	}
	if strings.ContainsRune(cleanPath, direntSeparator) {
		return errors.Wrap(ErrInvalidPath, "path contains a NUL byte")
	}
	if isRootPath(cleanPath) {
		return nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(cleanPath, "/"), "/") {
		switch component {
		case "":
			return errors.Wrapf(ErrInvalidPath, "path %q has an empty component", cleanPath)
		case ".", "..":
			// path.Clean resolves these, so reaching here means the path
			// tried to escape the root.
			return errors.Wrapf(ErrInvalidPath, "path %q escapes the store root", cleanPath)
		}
	}
	return nil
}
