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
	"fmt"
	"net/url"
	"os"
	"strings"
)

// secretParams are the URL query parameters that carry a secret in some
// tool's or driver's spelling.  The list is the union of what the origin and
// the cache each guarded separately -- each of their copies leaked a few the
// other caught.  Matching is case-insensitive.
var secretParams = map[string]bool{
	"accesskey":         true,
	"access_key":        true,
	"accountkey":        true,
	"awsaccesskeyid":    true,
	"awssecretkey":      true,
	"awssessiontoken":   true,
	"password":          true,
	"sas_token":         true,
	"secret_access_key": true,
	"secretkey":         true,
	"session_token":     true,
	"token":             true,
}

func isSecretParam(key string) bool { return secretParams[strings.ToLower(key)] }

// RedactURL returns rawURL with its credentials replaced, for logging and for
// anything persisted as a human-readable identity: the userinfo component
// and the value of every secret-bearing query parameter.  An unparsable URL
// is replaced outright rather than risk echoing part of a secret.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[unparsable blob URL redacted]"
	}
	if u.User != nil {
		u.User = url.UserPassword("redacted", "redacted")
	}
	q := u.Query()
	changed := false
	for key := range q {
		if isSecretParam(key) {
			q.Set(key, "redacted")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// ReadKeyfilePair loads static credentials from an access-key file and a
// secret-key file, each read whole and trimmed.  When either path is empty
// it returns two empty strings and no error, meaning "no static
// credentials"; callers validate that the two are configured together.
func ReadKeyfilePair(accessKeyFile, secretKeyFile string) (accessKey, secretKey string, err error) {
	if accessKeyFile == "" || secretKeyFile == "" {
		return "", "", nil
	}
	akBytes, err := os.ReadFile(accessKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to read access key file %s: %w", accessKeyFile, err)
	}
	skBytes, err := os.ReadFile(secretKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to read secret key file %s: %w", secretKeyFile, err)
	}
	return strings.TrimSpace(string(akBytes)), strings.TrimSpace(string(skBytes)), nil
}
