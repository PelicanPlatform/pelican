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

package server_utils

import (
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// S3v2Origin is the native (non-XRootD) S3 backend.
// It reuses the same configuration and validation as S3Origin, but
// relaxes the validation when Origin.ObjectProviderURL is set (since
// the S3-specific params like S3ServiceUrl are not needed then).
type S3v2Origin struct {
	S3Origin
}

func (o *S3v2Origin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageS3v2
}

func (o *S3v2Origin) validateExtra(e *OriginExport, numExports int) error {
	// When ObjectProviderURL is set, the S3-specific fields (S3ServiceUrl,
	// S3Bucket, etc.) are not required — the bucket is opened via the URL.
	if param.Origin_ObjectProviderURL.GetString() != "" {
		return nil
	}
	return o.S3Origin.validateExtra(e, numExports)
}
