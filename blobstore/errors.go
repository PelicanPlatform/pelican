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

package blobstore

import (
	"errors"
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"gocloud.dev/gcerrors"
)

// IsNotFound reports whether an error from a blob operation means the object
// is absent, as opposed to a failure.
//
// gocloud.dev's own classification covers the documented S3 error codes, but
// its S3 driver classifies by API error code alone.  A HeadObject against a
// missing key, and several S3-compatible services in general, answer with a
// bare 404 that the SDK surfaces as a generic HTTP response error with no
// parseable code -- and gocloud reports that as Unknown.  Treating it as a
// failure turns "absent" into a hard error: deletes stop being idempotent,
// a stat cannot answer "does not exist", and anything reconciling a bucket
// against a database can never settle the entry it is checking.
//
// gocloud's errors keep the underlying cause reachable through Unwrap, which
// is what lets the S3-specific checks below run on them.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return gcerrors.Code(err) == gcerrors.NotFound || isS3NotFound(err)
}

// isS3NotFound recognises the S3 error shapes that mean "absent", inspecting
// the HTTP status rather than matching error text so a provider that phrases
// its errors differently cannot slip through.
func isS3NotFound(err error) bool {
	var noKey *s3types.NoSuchKey
	var notFound *s3types.NotFound
	if errors.As(err, &noKey) || errors.As(err, &notFound) {
		return true
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == http.StatusNotFound
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}
