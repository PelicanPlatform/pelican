/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package server_structs

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type (
	OriginStorageType string
)

// OriginDataRoutePrefix is where a native origin mounts its exports when it
// shares a web server with a co-located director.  The director owns the root
// path space (clients resolve an object by GETting
// https://<director>/<ns>/<obj> and following the redirect), so the bytes have
// to live somewhere else.  An origin running without a director -- including a
// standalone one -- mounts its exports at their bare federation prefixes
// instead; see origin_serve.RegisterHandlers.
//
// Both ends of that arrangement must agree on this string: the origin mounts
// its handlers under it, and the ad it publishes has to point here.
const OriginDataRoutePrefix = "/api/v1.0/origin/data"

const (
	OriginStoragePosix    OriginStorageType = "posix"
	OriginStoragePosixv2  OriginStorageType = "posixv2"
	OriginStorageSSH      OriginStorageType = "ssh"
	OriginStorageS3       OriginStorageType = "s3"
	OriginStorageHTTPS    OriginStorageType = "https"
	OriginStorageGlobus   OriginStorageType = "globus"
	OriginStorageS3v2     OriginStorageType = "s3v2"     // Native S3 backend (no XRootD)
	OriginStorageHTTPSv2  OriginStorageType = "httpsv2"  // Native HTTPS/WebDAV backend (no XRootD)
	OriginStorageGlobusv2 OriginStorageType = "globusv2" // Native Globus backend (no XRootD)
	OriginStoragePStore   OriginStorageType = "pstore"   // Pelican store: encrypted block store on local disk (no XRootD)
	OriginStorageXRoot    OriginStorageType = "xroot"    // Not meant to be extensible, but facilitates legacy OSDF --> Pelican transition
)

var (
	ErrUnknownOriginStorageType = errors.New("unknown origin storage type")
)

// SupportsSelfTest reports whether the origin can accept the write-read probe
// that the origin self-test and the director test rely on.
//
// The probe writes a small object and reads it back, so it needs a backend the
// origin can write to directly and cheaply. That rules out the
// remote-protocol backends (S3, HTTPS, Globus, SSH, XRoot), where the probe
// would mean egress and credentials for every health check.
//
// Note that this is a different question from IsPosixLike: pstore is not a
// POSIX filesystem and its StoragePrefix is not a host path, but it is local
// and writable, so it can self-test.
func (t OriginStorageType) SupportsSelfTest() bool {
	switch t {
	case OriginStoragePosix, OriginStoragePosixv2, OriginStoragePStore:
		return true
	default:
		return false
	}
}

// IsPosixLike reports whether an export's StoragePrefix names a directory on
// this host, so it can be walked, stat'd, or opened as an os.Root.
//
// pstore is deliberately excluded. Its StoragePrefix is a path inside the
// store's own namespace, not on the filesystem -- "/" is a perfectly ordinary
// value for it -- so resolving one against the local filesystem reads
// something else entirely, or the host's root directory.
func (t OriginStorageType) IsPosixLike() bool {
	switch t {
	case OriginStoragePosix, OriginStoragePosixv2:
		return true
	default:
		return false
	}
}

// UsesXRootD reports whether an origin of this storage type is fronted by an
// XRootD process. The native "v2" backends (and SSH) are served directly by
// the pelican process and never launch XRootD. New native backends should be
// added here rather than duplicating the list of storage-type comparisons.
func (t OriginStorageType) UsesXRootD() bool {
	switch t {
	case OriginStoragePosixv2, OriginStorageSSH, OriginStorageS3v2, OriginStorageHTTPSv2, OriginStorageGlobusv2, OriginStoragePStore:
		return false
	default:
		return true
	}
}

// Convert a string to an OriginStorageType
func ParseOriginStorageType(storageType string) (ost OriginStorageType, err error) {
	switch storageType {
	case string(OriginStorageS3):
		ost = OriginStorageS3
	case string(OriginStorageHTTPS):
		ost = OriginStorageHTTPS
	case string(OriginStoragePosix):
		ost = OriginStoragePosix
	case string(OriginStoragePosixv2):
		ost = OriginStoragePosixv2
	case string(OriginStorageSSH):
		ost = OriginStorageSSH
	case string(OriginStorageXRoot):
		ost = OriginStorageXRoot
	case string(OriginStorageGlobus):
		ost = OriginStorageGlobus
	case string(OriginStorageS3v2):
		ost = OriginStorageS3v2
	case string(OriginStorageHTTPSv2):
		ost = OriginStorageHTTPSv2
	case string(OriginStorageGlobusv2):
		ost = OriginStorageGlobusv2
	case string(OriginStoragePStore):
		ost = OriginStoragePStore
	default:
		err = errors.Wrapf(ErrUnknownOriginStorageType, "storage type %s (known types are posix, posixv2, ssh, s3, s3v2, https, httpsv2, globus, globusv2, pstore, and xroot)", storageType)
	}
	return
}

// ParseExportVolume splits a docker-style export volume into the storage prefix
// it exposes and the federation prefix it is served under.  A value with no
// colon names the same path on both sides.
//
// The two sides are cleaned differently on purpose.  A storage prefix names a
// location on this host, so it takes the platform's separator; a federation
// prefix is the path half of a URL and is always slash-separated, so cleaning it
// as a filesystem path would turn "/public" into "\public" on Windows and stop
// it matching anything -- including the checks that reject a root prefix.
//
// The split is on the *first* colon, which means a storage prefix containing one
// -- a Windows drive letter, say -- cannot be expressed in this syntax.  That is
// a property of the syntax rather than a choice made here, and it is the reason
// this lives in one place: config validation and export construction disagreeing
// about where the federation prefix begins would let a prefix pass validation
// and then be served under a different name.
func ParseExportVolume(volume string) (storagePrefix, federationPrefix string) {
	storagePrefix = filepath.Clean(volume)
	federationPrefix = path.Clean(volume)
	if parts := strings.SplitN(volume, ":", 2); len(parts) == 2 {
		storagePrefix = filepath.Clean(parts[0])
		federationPrefix = path.Clean(parts[1])
	}
	return
}
