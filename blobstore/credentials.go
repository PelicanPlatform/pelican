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
	"os"
	"strings"
)

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
