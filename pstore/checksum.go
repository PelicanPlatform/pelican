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

// Checksums computed at ingest.
//
// A POSIX origin answers Want-Digest from checksums cached in xattrs, which
// depends on filesystem xattr support and on something having computed them
// earlier -- otherwise the whole object is re-read.
//
// pstore hashes the stream as it is written, which costs no extra I/O because
// the bytes are already in hand, and stores the result on the object version's
// metadata.  A Want-Digest HEAD is then a metadata read regardless of object
// size.  Because the digests belong to the version rather than the path, an
// overwrite cannot leave a stale checksum behind the way an mtime-validated
// xattr cache can.
//
// Algorithm naming, value encoding, and hasher construction all come from
// local_cache, which the cache's own Digest header and consistency checker
// use as well.

package pstore

import (
	"hash"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/local_cache"
)

// ingestAlgorithms are the digests recorded for every object.
//
// The set is fixed rather than configurable: hashing is cheap next to the I/O
// already happening, and computing one later would mean re-reading the object,
// which is the cost this exists to avoid.
var ingestAlgorithms = []local_cache.ChecksumType{
	local_cache.ChecksumMD5,
	local_cache.ChecksumSHA1,
	local_cache.ChecksumCRC32C,
}

// ingestDigests hashes an object as it is written.
type ingestDigests struct {
	types  []local_cache.ChecksumType
	hashes []hash.Hash
}

func newIngestDigests() (*ingestDigests, error) {
	d := &ingestDigests{
		types:  ingestAlgorithms,
		hashes: make([]hash.Hash, 0, len(ingestAlgorithms)),
	}
	for _, t := range ingestAlgorithms {
		h, err := local_cache.NewChecksumHasher(t)
		if err != nil {
			return nil, errors.Wrap(err, "failed to build an ingest hasher")
		}
		d.hashes = append(d.hashes, h)
	}
	return d, nil
}

// Write feeds bytes to every digest.  hash.Hash writes never fail.
func (d *ingestDigests) Write(p []byte) {
	if d == nil || len(p) == 0 {
		return
	}
	for _, h := range d.hashes {
		_, _ = h.Write(p)
	}
}

// checksums renders the digests in the catalog's representation.
//
// They are marked OriginVerified because this origin computed them over the
// bytes it stored, which is the strongest provenance available.
func (d *ingestDigests) checksums() []local_cache.Checksum {
	if d == nil {
		return nil
	}
	out := make([]local_cache.Checksum, 0, len(d.hashes))
	for i, h := range d.hashes {
		out = append(out, local_cache.Checksum{
			Type:           d.types[i],
			Value:          h.Sum(nil),
			OriginVerified: true,
		})
	}
	return out
}

// Digests returns the checksums recorded for an object when it was written.
//
// An object written before checksums were recorded yields an empty slice
// rather than an error, so callers can fall back rather than fail.
func (s *Store) Digests(name string) ([]local_cache.Checksum, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return nil, err
	}

	d, err := s.Stat(cleanPath)
	if err != nil {
		return nil, err
	}
	if d.IsDir() {
		return nil, ErrIsDir
	}

	meta, err := s.db.GetMetadata(instanceHashFor(s.db, d.Generation))
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, ErrNotExist
	}
	return meta.Checksums, nil
}
