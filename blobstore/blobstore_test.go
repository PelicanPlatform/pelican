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
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactURL(t *testing.T) {
	t.Run("StripsUserinfoPassword", func(t *testing.T) {
		got := RedactURL("s3://AKIAEXAMPLE:supersecret@my-bucket?region=us-east-1")
		assert.NotContains(t, got, "supersecret")
		assert.NotContains(t, got, "AKIAEXAMPLE")
		assert.Contains(t, got, "my-bucket")
	})

	t.Run("LeavesCleanURLUntouched", func(t *testing.T) {
		in := "s3://my-bucket?region=us-east-1&use_path_style=true"
		got := RedactURL(in)
		assert.Contains(t, got, "my-bucket")
		assert.Contains(t, got, "region=us-east-1")
	})

	t.Run("UnparsableIsFullyRedacted", func(t *testing.T) {
		assert.Equal(t, "[unparsable blob URL redacted]", RedactURL("://::not-a-url::"))
	})

	// Every spelling either former copy guarded, plus the ones each copy
	// missed: before this package existed, the origin logged sas_token and
	// accountkey in clear and the cache logged token and password.
	for _, key := range []string{
		"awssecretkey", "secretkey", "secret_access_key", "access_key", "awsaccesskeyid",
		"password", "token", "sas_token", "accountkey", "awssessiontoken", "session_token",
		"AWSSecretKey", // matching is case-insensitive
	} {
		t.Run("Redacts_"+key, func(t *testing.T) {
			got := RedactURL("s3://my-bucket?" + key + "=supersecret&region=us-east-1")
			assert.NotContains(t, got, "supersecret")
			assert.Contains(t, got, "region=us-east-1")
		})
	}
}

// TestOpenURLScrubsTheURLFromErrors covers the openers that quote the URL in
// their errors -- S3 and GCS on an unknown parameter, and the scheme
// dispatcher on an unregistered scheme -- plus userinfo, which the S3 opener
// accepts silently and so only shows up if something else fails.
func TestOpenURLScrubsTheURLFromErrors(t *testing.T) {
	for _, raw := range []string{
		"s3://bucket?awssecretkey=SUPERSECRET",
		"gs://bucket?secretkey=SUPERSECRET",
		"bogus://bucket?sas_token=SUPERSECRET",
		"s3://AKIDEXAMPLE:SUPERSECRET@bucket?nosuchparam=1",
	} {
		t.Run(raw[:5], func(t *testing.T) {
			_, err := OpenURL(context.Background(), raw)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "SUPERSECRET")
			assert.NotContains(t, err.Error(), "AKIDEXAMPLE")
			// Wrapping must not reintroduce it either.
			assert.NotContains(t, fmt.Sprintf("%+v", fmt.Errorf("outer: %w", err)), "SUPERSECRET")
			// The cause is still there for errors.Is / errors.As.
			assert.NotNil(t, errors.Unwrap(err))
		})
	}
}

// TestOpenS3DoesNotMutateEnv guards the property that motivated the explicit
// client: static credentials stay local to it and are never written into the
// process environment, where they would clobber every other S3 client.
// Opening is lazy, so no server is contacted.
func TestOpenS3DoesNotMutateEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "sentinel-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sentinel-secret")

	bucket, client, err := OpenS3(context.Background(), S3Options{
		ServiceURL: "http://127.0.0.1:1", // never contacted
		Region:     "us-east-1",
		Bucket:     "my-bucket",
		AccessKey:  "AKIAEXAMPLE",
		SecretKey:  "supersecret",
		URLStyle:   "path",
	})
	require.NoError(t, err)
	require.NotNil(t, client)
	defer bucket.Close()

	assert.Equal(t, "sentinel-access", os.Getenv("AWS_ACCESS_KEY_ID"))
	assert.Equal(t, "sentinel-secret", os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

func TestOpenS3RequiresBucket(t *testing.T) {
	_, _, err := OpenS3(context.Background(), S3Options{Region: "us-east-1"})
	assert.Error(t, err)
}

func TestReadKeyfilePair(t *testing.T) {
	t.Run("EmptyPathsMeanNoStaticCredentials", func(t *testing.T) {
		ak, sk, err := ReadKeyfilePair("", "")
		require.NoError(t, err)
		assert.Empty(t, ak)
		assert.Empty(t, sk)
	})

	t.Run("ValidFilesAreTrimmed", func(t *testing.T) {
		dir := t.TempDir()
		akFile := filepath.Join(dir, "access_key")
		skFile := filepath.Join(dir, "secret_key")
		require.NoError(t, os.WriteFile(akFile, []byte("  AKID123  \n"), 0600))
		require.NoError(t, os.WriteFile(skFile, []byte("  SECRET456  \n"), 0600))

		ak, sk, err := ReadKeyfilePair(akFile, skFile)
		require.NoError(t, err)
		assert.Equal(t, "AKID123", ak)
		assert.Equal(t, "SECRET456", sk)
	})

	t.Run("MissingAccessKeyFile", func(t *testing.T) {
		dir := t.TempDir()
		skFile := filepath.Join(dir, "secret_key")
		require.NoError(t, os.WriteFile(skFile, []byte("SECRET"), 0600))

		_, _, err := ReadKeyfilePair(filepath.Join(dir, "nonexistent"), skFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access key file")
	})

	t.Run("MissingSecretKeyFile", func(t *testing.T) {
		dir := t.TempDir()
		akFile := filepath.Join(dir, "access_key")
		require.NoError(t, os.WriteFile(akFile, []byte("AKID"), 0600))

		_, _, err := ReadKeyfilePair(akFile, filepath.Join(dir, "nonexistent"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret key file")
	})
}

// TestIsNotFound pins the error shapes that must read as "the object is
// absent".  gocloud classifies S3 errors by API error code alone, so the
// bare 404 that several S3-compatible services return comes back from it as
// Unknown; before this package, the origin's blob backend treated that as a
// hard failure.
func TestIsNotFound(t *testing.T) {
	bare404 := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
		Err:      errors.New("unparsable error body"),
	}}
	bare500 := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}},
		Err:      errors.New("server error"),
	}}
	// gocloud wraps driver errors in its own type, which unwraps; %w stands
	// in for that wrapping.
	wrap := func(err error) error { return fmt.Errorf("blob (key %q): %w", "42/56/x", err) }

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"typed NoSuchKey", wrap(&s3types.NoSuchKey{}), true},
		{"typed NotFound", wrap(&s3types.NotFound{}), true},
		{"bare 404 response", wrap(bare404), true},
		{"generic API error coded 404", wrap(&smithy.GenericAPIError{Code: "404"}), true},
		{"generic API error coded NotFound", wrap(&smithy.GenericAPIError{Code: "NotFound"}), true},
		{"server error is not absence", wrap(bare500), false},
		{"access denied is not absence", wrap(&smithy.GenericAPIError{Code: "AccessDenied"}), false},
		{"unrelated error", errors.New("connection reset"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsNotFound(tt.err))
		})
	}
}
