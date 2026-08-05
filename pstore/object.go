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

// Object identity.
//
// Every write mints a generation: 128 random bits that serve as the version's
// identity, its HTTP ETag, and the input to its storage key.
//
//	instanceHash = HMAC(salt, "gen:" + generation)
//
// The derivation deliberately does not involve the path.  That keeps the
// object's metadata, block state, and on-disk data files path-independent, so
// renaming an entry rewrites index keys and moves no bytes.  It also means two
// paths can never collide on a storage key the way the cache's URL-derived
// hashes can (see docs/pstore-design.md §12).
//
// Data files stay hash-named on disk, so an attacker holding the disks but not
// the master key still cannot tell which objects a store contains.

package pstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/local_cache"
)

// generationBytes is the size of a generation token.  128 bits is enough that
// a collision is not worth reasoning about, and it doubles as a strong opaque
// ETag.
const generationBytes = 16

// newGeneration mints a fresh version token.
func newGeneration() (string, error) {
	buf := make([]byte, generationBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Wrap(err, "failed to generate an object version token")
	}
	return hex.EncodeToString(buf), nil
}

// instanceHashFor derives the storage key for a generation.
func instanceHashFor(db *local_cache.CacheDB, generation string) local_cache.InstanceHash {
	h := hmac.New(sha256.New, db.Salt())
	h.Write([]byte("gen:"))
	h.Write([]byte(generation))
	return local_cache.InstanceHash(hex.EncodeToString(h.Sum(nil)))
}

// etagFor renders a generation as a strong HTTP entity tag.
func etagFor(generation string) string {
	if generation == "" {
		return ""
	}
	return `"` + generation + `"`
}
