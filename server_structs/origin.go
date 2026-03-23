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

import "github.com/pkg/errors"

type (
	OriginStorageType string
)

const (
	OriginStoragePosix    OriginStorageType = "posix"
	OriginStoragePosixv2  OriginStorageType = "posixv2"
	OriginStorageSSH      OriginStorageType = "ssh"
	OriginStorageAdios    OriginStorageType = "adios"
	OriginStorageS3       OriginStorageType = "s3"
	OriginStorageHTTPS    OriginStorageType = "https"
	OriginStorageGlobus   OriginStorageType = "globus"
	OriginStorageS3v2     OriginStorageType = "s3v2"     // Native S3 backend (no XRootD)
	OriginStorageHTTPSv2  OriginStorageType = "httpsv2"  // Native HTTPS/WebDAV backend (no XRootD)
	OriginStorageGlobusv2 OriginStorageType = "globusv2" // Native Globus backend (no XRootD)
	OriginStorageXRoot    OriginStorageType = "xroot"    // Not meant to be extensible, but facilitates legacy OSDF --> Pelican transition
)

var (
	ErrUnknownOriginStorageType = errors.New("unknown origin storage type")
)

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
	case string(OriginStorageAdios):
		ost = OriginStorageAdios
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
	default:
		err = errors.Wrapf(ErrUnknownOriginStorageType, "storage type %s (known types are posix, posixv2, ssh, adios, s3, s3v2, https, httpsv2, globus, globusv2, and xroot)", storageType)
	}
	return
}
