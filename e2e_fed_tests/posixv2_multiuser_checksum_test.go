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

// Linux-only: the POSIXv2 multiuser variant relies on setfsuid/setfsgid which
// only exist on Linux, and the test-utility helpers SkipUnlessPrivileged /
// SkipUnlessTestUsers are themselves Linux-only.

package fed_tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestPosixv2_MultiuserPreservesChecksums covers the POSIXv2 multiuser variant
// (Origin.Multiuser = true with StorageType posixv2). The multiuser filesystem
// wraps the base osRoot filesystem and switches identities via setfsuid/
// setfsgid before each operation; this test pins down that, after a PUT under
// multiuser mode, the CRC32C xattr still lands on disk and a subsequent Stat
// returns the matching value -- the same contract that non-multiuser POSIXv2
// already provides.
//
// Requires Linux + CAP_SETUID/CAP_SETGID and the test user "alice"; skips
// automatically when those aren't available.
func TestPosixv2_MultiuserPreservesChecksums(t *testing.T) {
	test_utils.SkipUnlessPrivileged(t)
	test_utils.SkipUnlessTestUsers(t, "alice")

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	storage := t.TempDir()
	skipUnlessXattrs(t, storage)
	// Multiuser switches to the request's UID for I/O, so the storage dir must
	// be writable by that user.
	require.NoError(t, os.Chmod(storage, 0o777))

	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Multiuser: true
  ScitokensMapSubject: true
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	content := []byte("multiuser POSIXv2 should still cache checksums")

	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modifyScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	tok := createTokenWithSubject(t, "alice",
		[]token_scopes.TokenScope{createScope, modifyScope, readScope})

	localDir := t.TempDir()
	local := filepath.Join(localDir, "alice.bin")
	require.NoError(t, os.WriteFile(local, content, 0o644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/alice.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	_, err = client.DoPut(ft.Ctx, local, uploadURL, false, client.WithToken(tok))
	require.NoError(t, err)

	statInfo, err := client.DoStat(ft.Ctx, uploadURL, client.WithToken(tok),
		client.WithRequestChecksums([]client.ChecksumType{client.AlgCRC32C}))
	require.NoError(t, err)
	require.NotNil(t, statInfo.Checksums)
	got, ok := statInfo.Checksums["crc32c"]
	require.True(t, ok, "CRC32C should be returned for multiuser POSIXv2 stat")
	assert.Equal(t, expectedCRC32CHex(content), got)

	// The xattr lands on the underlying file regardless of which UID owns it.
	backendFile := filepath.Join(storage, "alice.bin")
	xattrData, err := xattr.Get(backendFile, "user.XrdCks.crc32c")
	require.NoError(t, err, "CRC32C xattr should be present under multiuser POSIXv2")
	assert.NotEmpty(t, xattrData)
}
