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
	OriginStoragePosix  OriginStorageType = "posix"
	OriginStorageS3     OriginStorageType = "s3"
	OriginStorageHTTPS  OriginStorageType = "https"
	OriginStorageGlobus OriginStorageType = "globus"
	OriginStorageXRoot  OriginStorageType = "xroot" // Not meant to be extensible, but facilitates legacy OSDF --> Pelican transition
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
	case string(OriginStorageXRoot):
		ost = OriginStorageXRoot
	case string(OriginStorageGlobus):
		ost = OriginStorageGlobus
	default:
		err = errors.Wrapf(ErrUnknownOriginStorageType, "storage type %s (known types are posix, s3, https, globus, and xroot)", storageType)
	}
	return
}
