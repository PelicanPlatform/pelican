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

package origin_serve

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// localBackend — OriginBackend for local (POSIX) storage
// ---------------------------------------------------------------------------

// localBackend wraps a local webdav.FileSystem and provides an xattr-based
// checksummer.  It is always available (CheckAvailability returns nil).
type localBackend struct {
	fs            webdav.FileSystem
	storagePrefix string
}

func newLocalBackend(fs webdav.FileSystem, storagePrefix string) *localBackend {
	return &localBackend{fs: fs, storagePrefix: storagePrefix}
}

func (b *localBackend) CheckAvailability() error      { return nil }
func (b *localBackend) FileSystem() webdav.FileSystem { return b.fs }
func (b *localBackend) Checksummer() server_utils.OriginChecksummer {
	return &xattrChecksumAdapter{storagePrefix: b.storagePrefix}
}

// ---------------------------------------------------------------------------
// xattrChecksumAdapter — adapts XattrChecksummer to OriginChecksummer
// ---------------------------------------------------------------------------

// xattrChecksumAdapter implements server_utils.OriginChecksummer by
// delegating to the xattr-based checksum machinery in this package.
type xattrChecksumAdapter struct {
	storagePrefix string
}

// GetDigests parses the Want-Digest header, opens an os.Root confined to
// storagePrefix, and returns RFC 3230 formatted digest strings.
func (a *xattrChecksumAdapter) GetDigests(relativePath string, wantDigest string) ([]string, error) {
	// Parse wantDigest into ChecksumType values
	var types []ChecksumType
	for _, alg := range strings.Split(wantDigest, ",") {
		alg = strings.TrimSpace(strings.ToLower(alg))
		switch alg {
		case "md5":
			types = append(types, ChecksumTypeMD5)
		case "sha", "sha-1", "sha1":
			types = append(types, ChecksumTypeSHA1)
		case "crc32":
			types = append(types, ChecksumTypeCRC32)
		case "crc32c":
			types = append(types, ChecksumTypeCRC32C)
		default:
			continue
		}
	}

	if len(types) == 0 {
		return nil, nil
	}

	root, err := os.OpenRoot(a.storagePrefix)
	if err != nil {
		log.Debugf("Failed to open storage root for checksum: %v", err)
		return nil, nil
	}
	defer root.Close()

	// Normalize the path (remove leading slash)
	normalizedPath := relativePath
	if len(normalizedPath) > 0 && normalizedPath[0] == '/' {
		normalizedPath = normalizedPath[1:]
	}

	xc := &XattrChecksummer{}
	return xc.GetChecksumsRFC3230(root, normalizedPath, types)
}
