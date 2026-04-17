//go:build linux

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

package origin_serve_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	pconfig "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// createTokenForUser creates a WLCG token with the given subject (mapped to a
// local user when ScitokensMapSubject is enabled) and full read/write/create scopes.
func createTokenForUser(t *testing.T, subject string) string {
	t.Helper()

	issuer, err := pconfig.GetServerIssuerURL()
	require.NoError(t, err)

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modifyScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)

	tc := token.NewWLCGToken()
	tc.Lifetime = 5 * time.Minute
	tc.Issuer = issuer
	tc.Subject = subject
	tc.AddAudienceAny()
	tc.AddScopes(readScope, createScope, modifyScope)

	tkn, err := tc.CreateToken()
	require.NoError(t, err)
	return tkn
}

// lookupUIDGID returns the numeric UID and primary GID for the given username.
func lookupUIDGID(t *testing.T, username string) (uint32, uint32) {
	t.Helper()
	u, err := user.Lookup(username)
	require.NoError(t, err)
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	require.NoError(t, err)
	return uint32(uid), uint32(gid)
}

// pelURL constructs a pelican:// URL for the test federation.
func pelURL(path string) string {
	return fmt.Sprintf("pelican://%s:%d%s",
		param.Server_Hostname.GetString(),
		param.Server_WebPort.GetInt(),
		path)
}

// TestMultiuserIntegration exercises the full multiuser origin stack: HTTP
// upload/download through the auth middleware, user-mapping, and multiuser
// filesystem layer.  It verifies that files land on disk with the correct
// ownership and that cross-user permission isolation is enforced.
//
// Requirements (skipped otherwise):
//   - Running as root (euid == 0)
//   - CAP_SETUID + CAP_SETGID
//   - Test users "alice" and "bob" present in the system
func TestMultiuserIntegration(t *testing.T) {
	test_utils.SkipUnlessPrivileged(t)
	test_utils.SkipUnlessTestUsers(t, "alice", "bob")

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Stand up a full federation with multiuser POSIXv2 origin.
	// ScitokensMapSubject maps the token "sub" claim to a local user.
	const originCfg = `
Origin:
  StorageType: posixv2
  Multiuser: true
  ScitokensMapSubject: true
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`
	ft := fed_test_utils.NewFedTest(t, originCfg)
	require.NotNil(t, ft)

	storagePrefix := ft.Exports[0].StoragePrefix
	require.NotEmpty(t, storagePrefix)

	// The storage directory was created by NewFedTest and is owned by root.
	// Make it world-writable so switched UIDs can create entries.
	require.NoError(t, os.Chmod(storagePrefix, 0777))

	aliceUID, aliceGID := lookupUIDGID(t, "alice")
	bobUID, _ := lookupUIDGID(t, "bob")

	aliceToken := createTokenForUser(t, "alice")
	bobToken := createTokenForUser(t, "bob")

	t.Run("UploadOwnership", func(t *testing.T) {
		// Upload as alice
		localDir := t.TempDir()
		localFile := filepath.Join(localDir, "alice.txt")
		require.NoError(t, os.WriteFile(localFile, []byte("alice data"), 0644))

		_, err := client.DoPut(ft.Ctx, localFile, pelURL("/test/alice.txt"), false,
			client.WithToken(aliceToken))
		require.NoError(t, err)

		uid, _ := test_utils.FileOwner(t, filepath.Join(storagePrefix, "alice.txt"))
		assert.Equal(t, aliceUID, uid, "file should be owned by alice")

		// Upload as bob
		localFile2 := filepath.Join(localDir, "bob.txt")
		require.NoError(t, os.WriteFile(localFile2, []byte("bob data"), 0644))

		_, err = client.DoPut(ft.Ctx, localFile2, pelURL("/test/bob.txt"), false,
			client.WithToken(bobToken))
		require.NoError(t, err)

		uid, _ = test_utils.FileOwner(t, filepath.Join(storagePrefix, "bob.txt"))
		assert.Equal(t, bobUID, uid, "file should be owned by bob")
	})

	t.Run("DownloadRoundTrip", func(t *testing.T) {
		// Upload as alice, then download the same file
		localDir := t.TempDir()
		srcFile := filepath.Join(localDir, "roundtrip.txt")
		content := []byte("round-trip content from alice")
		require.NoError(t, os.WriteFile(srcFile, content, 0644))

		_, err := client.DoPut(ft.Ctx, srcFile, pelURL("/test/roundtrip.txt"), false,
			client.WithToken(aliceToken))
		require.NoError(t, err)

		// Verify ownership
		uid, _ := test_utils.FileOwner(t, filepath.Join(storagePrefix, "roundtrip.txt"))
		assert.Equal(t, aliceUID, uid)

		// Download
		dstFile := filepath.Join(t.TempDir(), "roundtrip.txt")
		_, err = client.DoGet(ft.Ctx, pelURL("/test/roundtrip.txt"), dstFile, false,
			client.WithToken(aliceToken))
		require.NoError(t, err)

		got, err := os.ReadFile(dstFile)
		require.NoError(t, err)
		assert.Equal(t, content, got, "downloaded content should match uploaded content")
	})

	t.Run("PermissionDenied", func(t *testing.T) {
		// Create a directory owned by alice with restrictive permissions (0700).
		// Bob should get a permission error trying to write into it.
		aliceDir := filepath.Join(storagePrefix, "alice-private")
		require.NoError(t, os.Mkdir(aliceDir, 0700))
		require.NoError(t, os.Chown(aliceDir, int(aliceUID), int(aliceGID)))

		localDir := t.TempDir()
		localFile := filepath.Join(localDir, "denied.txt")
		require.NoError(t, os.WriteFile(localFile, []byte("should fail"), 0644))

		// Bob tries to upload into alice's private directory
		_, err := client.DoPut(ft.Ctx, localFile, pelURL("/test/alice-private/denied.txt"), false,
			client.WithToken(bobToken))
		require.Error(t, err, "bob should not be able to write into alice's private directory")

		// Verify the file was NOT created
		_, statErr := os.Stat(filepath.Join(aliceDir, "denied.txt"))
		assert.True(t, os.IsNotExist(statErr), "file should not have been created")
	})

	t.Run("PermissionDeniedRead", func(t *testing.T) {
		// Alice creates a file that only she can read
		privateDir := filepath.Join(storagePrefix, "alice-readonly")
		require.NoError(t, os.Mkdir(privateDir, 0700))
		require.NoError(t, os.Chown(privateDir, int(aliceUID), int(aliceGID)))

		secretFile := filepath.Join(privateDir, "secret.txt")
		require.NoError(t, os.WriteFile(secretFile, []byte("alice secret"), 0600))
		require.NoError(t, os.Chown(secretFile, int(aliceUID), int(aliceGID)))

		// Bob tries to download alice's secret file — should get an HTTP error
		dstFile := filepath.Join(t.TempDir(), "stolen.txt")
		_, err := client.DoGet(ft.Ctx, pelURL("/test/alice-readonly/secret.txt"), dstFile, false,
			client.WithToken(bobToken))
		require.Error(t, err, "bob should not be able to read alice's private file")
	})

	t.Run("DirectWebDAVOwnership", func(t *testing.T) {
		// Verify ownership via a direct HTTP PUT to the origin (bypassing cache).
		// This exercises the full Gin → authMiddleware → multiuserFS → OS path.
		// The origin's WebDAV endpoint is at /api/v1.0/origin/data/<prefix>/...
		originURL := fmt.Sprintf("%s/api/v1.0/origin/data/test/direct-alice.txt",
			param.Server_ExternalWebUrl.GetString())

		content := []byte("direct upload by alice")
		req, err := http.NewRequestWithContext(ft.Ctx, http.MethodPut, originURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+aliceToken)
		req.Body = io.NopCloser(bytes.NewReader(content))
		req.ContentLength = int64(len(content))

		resp, err := pconfig.GetTransport().RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 201 Created or 204 No Content are both acceptable
		require.True(t, resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent,
			"expected 201 or 204, got %d", resp.StatusCode)

		uid, _ := test_utils.FileOwner(t, filepath.Join(storagePrefix, "direct-alice.txt"))
		assert.Equal(t, aliceUID, uid, "directly uploaded file should be owned by alice")
	})
}

// TestMultiuserMapfileIntegration exercises the mapfile-based user mapping in
// a full federation.  A mapfile rule maps the token subject "testsubject" to
// the local user "alice".  We then upload a file using that token and verify
// the on-disk file is owned by alice, proving the mapfile mapping was applied
// end-to-end through the auth middleware, user mapper, and multiuser filesystem.
//
// Requirements (skipped otherwise):
//   - Running as root (euid == 0)
//   - CAP_SETUID + CAP_SETGID
//   - Test user "alice" present in the system
func TestMultiuserMapfileIntegration(t *testing.T) {
	test_utils.SkipUnlessPrivileged(t)
	test_utils.SkipUnlessTestUsers(t, "alice")

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create the mapfile before starting the federation, because the config
	// must reference its path.
	mapfileDir := t.TempDir()
	mapfilePath := filepath.Join(mapfileDir, "scitokens-mapfile.json")

	type mapfileRule struct {
		Sub    *string `json:"sub,omitempty"`
		Result string  `json:"result"`
	}
	sub := "testsubject"
	rules := []mapfileRule{
		{Sub: &sub, Result: "alice"},
	}
	data, err := json.Marshal(rules)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mapfilePath, data, 0644))

	originCfg := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Multiuser: true
  ScitokensNameMapFile: %s
  ScitokensDefaultUser: nobody
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, mapfilePath)

	ft := fed_test_utils.NewFedTest(t, originCfg)
	require.NotNil(t, ft)

	storagePrefix := ft.Exports[0].StoragePrefix
	require.NotEmpty(t, storagePrefix)
	require.NoError(t, os.Chmod(storagePrefix, 0777))

	aliceUID, _ := lookupUIDGID(t, "alice")

	// Create a token with subject "testsubject" — not a real local user, but
	// the mapfile maps it to "alice".
	testToken := createTokenForUser(t, "testsubject")

	t.Run("MapfileRemapsToAlice", func(t *testing.T) {
		localDir := t.TempDir()
		localFile := filepath.Join(localDir, "mapped.txt")
		require.NoError(t, os.WriteFile(localFile, []byte("mapped via mapfile"), 0644))

		_, err := client.DoPut(ft.Ctx, localFile, pelURL("/test/mapped.txt"), false,
			client.WithToken(testToken))
		require.NoError(t, err)

		uid, _ := test_utils.FileOwner(t, filepath.Join(storagePrefix, "mapped.txt"))
		assert.Equal(t, aliceUID, uid,
			"file uploaded with subject 'testsubject' should be owned by alice per mapfile")
	})

	t.Run("MapfileNoMatchFallsBack", func(t *testing.T) {
		// "unknownsub" is not in the mapfile; ScitokensDefaultUser is "nobody",
		// so the file should be owned by nobody.
		nobodyUID, _ := lookupUIDGID(t, "nobody")

		unmatchedToken := createTokenForUser(t, "unknownsub")

		localDir := t.TempDir()
		localFile := filepath.Join(localDir, "fallback.txt")
		require.NoError(t, os.WriteFile(localFile, []byte("no mapfile match"), 0644))

		_, err := client.DoPut(ft.Ctx, localFile, pelURL("/test/fallback.txt"), false,
			client.WithToken(unmatchedToken))
		require.NoError(t, err)

		uid, _ := test_utils.FileOwner(t, filepath.Join(storagePrefix, "fallback.txt"))
		assert.Equal(t, nobodyUID, uid,
			"file uploaded with unmatched subject should be owned by nobody (default user)")
	})
}
