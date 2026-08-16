//go:build !windows

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

// The same client operations, swept across every origin backend.
//
// The per-backend test files each cover whatever operations their author
// needed, which leaves holes that are invisible until someone trips over one
// in production: listing a plain object was untested on every backend, so
// `pelican object ls <object>` could return nothing against a POSIX v2 origin
// without a single test noticing. Sweeping one matrix across backends means a
// new backend inherits the whole matrix instead of starting from zero.
//
// Operations exercised per backend: put (also the seed), stat, list a
// collection, list a plain object, get.

package fed_tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// conformanceBackend names an origin backend and how to stand one up. Adding a
// backend here gives it the whole operation matrix below.
type conformanceBackend struct {
	name string
	// originConfig returns the origin YAML, standing up whatever external
	// service the backend fronts (all of which are local: a WebDAV server on
	// httptest, minio, mock Globus APIs). May call t.Skip when a backend's
	// dependency is unavailable.
	originConfig func(t *testing.T) string
	// afterFed runs once the federation is up. NewFedTest rewrites
	// StoragePrefix to a temp path, so backends that front a separate service
	// can only mirror the directory layout here, not in originConfig.
	afterFed func(t *testing.T, ft *fed_test_utils.FedTest)
	// token returns the credential for this backend, when it is not the
	// standard one.
	token func(t *testing.T) string
}

func conformanceBackends() []conformanceBackend {
	return []conformanceBackend{
		{
			name: "posixv2",
			originConfig: func(t *testing.T) string {
				return `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`
			},
		},
		{
			name: "pstore",
			originConfig: func(t *testing.T) string {
				return pstoreOriginConfig(t.TempDir())
			},
			token: getPStoreToken,
		},
		{
			name: "s3v2",
			originConfig: func(t *testing.T) string {
				// Skips the subtest when minio is unavailable, leaving the
				// rest of the matrix to run.
				test_utils.SkipIfNoMinio(t)
				endpoint, accessKey, secretKey := test_utils.StartMinio(t, "test-bucket")
				credDir := t.TempDir()
				akFile := filepath.Join(credDir, "access-key")
				skFile := filepath.Join(credDir, "secret-key")
				require.NoError(t, os.WriteFile(akFile, []byte(accessKey), 0600))
				require.NoError(t, os.WriteFile(skFile, []byte(secretKey), 0600))
				return fmt.Sprintf(`
Origin:
  StorageType: s3v2
  S3ServiceUrl: %s
  S3Region: us-east-1
  S3Bucket: test-bucket
  S3AccessKeyfile: %s
  S3SecretKeyfile: %s
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, endpoint, akFile, skFile)
			},
			token: getS3v2Token,
		},
		func() conformanceBackend {
			// Captured so afterFed can mirror the rewritten StoragePrefix
			// into the WebDAV server's root.
			var webdavRoot string
			return conformanceBackend{
				name: "httpsv2",
				originConfig: func(t *testing.T) string {
					webdavRoot = t.TempDir()
					return httpsv2OriginConfig(startWebDAVServer(t, webdavRoot), "/data")
				},
				afterFed: func(t *testing.T, ft *fed_test_utils.FedTest) {
					require.Greater(t, len(ft.Exports), 0)
					require.NoError(t, os.MkdirAll(
						filepath.Join(webdavRoot, ft.Exports[0].StoragePrefix), 0755))
				},
				token: getHTTPSv2Token,
			}
		}(),
	}
}

// TestBackendConformance runs one operation matrix against each backend.
func TestBackendConformance(t *testing.T) {
	for _, backend := range conformanceBackends() {
		t.Run(backend.name, func(t *testing.T) {
			t.Cleanup(test_utils.SetupTestLogging(t))
			server_utils.ResetTestState()
			t.Cleanup(server_utils.ResetTestState)

			ft := fed_test_utils.NewFedTest(t, backend.originConfig(t))
			require.NotNil(t, ft)
			if backend.afterFed != nil {
				backend.afterFed(t, ft)
			}
			token := getTempTokenForTest(t)
			if backend.token != nil {
				token = backend.token(t)
			}

			base := fmt.Sprintf("pelican://%s:%d/test",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
			const contents = "conformance object contents"
			objectURL := base + "/conformance.txt"

			// put -- also seeds every operation that follows, so a backend
			// that cannot write is out of scope for this matrix.
			local := filepath.Join(t.TempDir(), "conformance.txt")
			require.NoError(t, os.WriteFile(local, []byte(contents), 0644))
			_, err := client.DoPut(ft.Ctx, local, objectURL, false, client.WithToken(token))
			require.NoError(t, err, "put")

			t.Run("stat", func(t *testing.T) {
				info, err := client.DoStat(ft.Ctx, objectURL, client.WithToken(token))
				require.NoError(t, err)
				assert.EqualValues(t, len(contents), info.Size,
					"stat must report the object's size, not the size of whatever document described it")
			})

			t.Run("list-collection", func(t *testing.T) {
				entries, err := client.DoList(ft.Ctx, base+"/", client.WithToken(token))
				require.NoError(t, err)
				var found bool
				for _, e := range entries {
					if filepath.Base(e.Name) == "conformance.txt" {
						found = true
					}
				}
				assert.True(t, found, "the collection listing should contain the object")
			})

			// The gap this suite exists for: every backend's own tests listed
			// collections only.
			t.Run("list-object", func(t *testing.T) {
				entries, err := client.DoList(ft.Ctx, objectURL, client.WithToken(token))
				require.NoError(t, err, "listing a plain object must not fail")
				require.Len(t, entries, 1, "listing a plain object should yield exactly that object")
				assert.False(t, entries[0].IsCollection)
				assert.EqualValues(t, len(contents), entries[0].Size)
			})

			t.Run("get", func(t *testing.T) {
				dest := filepath.Join(t.TempDir(), "fetched.txt")
				_, err := client.DoGet(ft.Ctx, objectURL, dest, false, client.WithToken(token))
				require.NoError(t, err)
				got, err := os.ReadFile(dest)
				require.NoError(t, err)
				assert.Equal(t, contents, string(got))
			})
		})
	}
}
