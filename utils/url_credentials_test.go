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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactURLCredentials(t *testing.T) {
	t.Run("StripsUserinfo", func(t *testing.T) {
		got := RedactURLCredentials("s3://AKIAEXAMPLE:supersecret@my-bucket?region=us-east-1")
		assert.NotContains(t, got, "supersecret")
		assert.NotContains(t, got, "AKIAEXAMPLE")
		assert.Contains(t, got, "my-bucket")
	})

	t.Run("LeavesCleanURLUntouched", func(t *testing.T) {
		got := RedactURLCredentials("s3://my-bucket?region=us-east-1&use_path_style=true")
		assert.Contains(t, got, "my-bucket")
		assert.Contains(t, got, "region=us-east-1")
	})

	// A redirect URL a cache mints for a dCache target carries a macaroon as
	// ?authz=; Pelican's own director-issued URLs carry a token the same way.
	t.Run("RedactsAuthzKeepsRest", func(t *testing.T) {
		got := RedactURLCredentials("https://dcache.example.org:2880/data/aa/bb/obj?authz=MDAxY2xvY2F0aW9uSECRET")
		assert.NotContains(t, got, "SECRET")
		assert.Equal(t, "https://dcache.example.org:2880/data/aa/bb/obj?authz=redacted", got)
	})

	t.Run("UnparsableIsFullyRedacted", func(t *testing.T) {
		assert.Equal(t, "[unparsable blob URL redacted]", RedactURLCredentials("://::not-a-url::"))
	})

	// Every spelling the origin and the cache each guarded, plus the ones
	// each missed before they shared one list: the origin logged sas_token
	// and accountkey in clear, the cache logged token and password.
	for _, key := range []string{
		"awssecretkey", "secretkey", "secret_access_key", "access_key", "awsaccesskeyid",
		"password", "token", "sas_token", "accountkey", "awssessiontoken", "session_token",
		"authz",        // Pelican's and dCache's bearer-token parameter
		"AWSSecretKey", // matching is case-insensitive
	} {
		t.Run("Redacts_"+key, func(t *testing.T) {
			got := RedactURLCredentials("s3://my-bucket?" + key + "=supersecret&region=us-east-1")
			assert.NotContains(t, got, "supersecret")
			assert.Contains(t, got, "region=us-east-1")
		})
	}
}

// TestURLHasCredentials matters because it is applied to *every* string in
// the configuration dump: anything that is not a credential-bearing URL must
// report false, or ordinary values would be rewritten.
func TestURLHasCredentials(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"s3://AKID:SECRET@bucket", true},
		{"s3://AKID@bucket", true},
		{"postgres://user:pw@db.example.org/pelican", true},
		{"s3://bucket?awssecretkey=x", true},
		{"azblob://container?sas_token=x", true},
		{"https://dcache.example.org:2880/data/obj?authz=MDAxY2xvY2F0aW9u", true},
		{"https://cache.example.org:8443/ns/obj?authz=Bearer%20eyJhbGciOi", true},
		{"s3://bucket?region=us-east-1", false},
		{"https://cache.example.org:8443", false},
		{"/var/lib/pelican/keys/secret", false},
		{"user@example.org", false}, // no scheme: not a URL
		{"just some text with token=abc", false},
		{"", false},
		{"://::not-a-url::", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, URLHasCredentials(tt.in))
		})
	}
}

func TestCheckNoURLCredentials(t *testing.T) {
	for _, ok := range []string{
		"s3://bucket",
		"s3://bucket?region=us-east-1&endpoint=https://minio.example.org",
		"gs://bucket",
		"azblob://container?domain=blob.core.windows.net",
	} {
		assert.NoError(t, CheckNoURLCredentials(ok), ok)
	}

	for _, bad := range []string{
		"s3://AKID:SUPERSECRET@bucket",
		"s3://AKIDONLY@bucket",
		"s3://bucket?awssecretkey=SUPERSECRET",
		"azblob://container?sas_token=SUPERSECRET",
		"s3://bucket?region=us-east-1&Token=SUPERSECRET",
		"https://dcache.example.org/data?authz=SUPERSECRET",
	} {
		err := CheckNoURLCredentials(bad)
		if assert.Error(t, err, bad) {
			// The refusal must not itself leak what it refused.
			assert.NotContains(t, err.Error(), "SUPERSECRET")
			assert.NotContains(t, err.Error(), "AKIDONLY")
			assert.Contains(t, err.Error(), "outside the URL")
		}
	}

	// An unparsable value is refused without being quoted.
	err := CheckNoURLCredentials("://SUPERSECRET::")
	if assert.Error(t, err) {
		assert.NotContains(t, err.Error(), "SUPERSECRET")
	}
}
