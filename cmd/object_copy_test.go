//go:build client && !windows

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

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// copyTPCOriginCfg is an authenticated POSIXv2 origin that advertises Copies,
// so `object copy` between two URLs in it takes the third-party-copy path.
const copyTPCOriginCfg = `
Origin:
  StorageType: "posixv2"
  EnableDirectReads: true
  Exports:
    - FederationPrefix: /test/tpc
      Capabilities: ["Reads", "Writes", "DirectReads", "Listings", "Copies"]
`

// TestInferCopyObjectName covers the destination rewrite `object copy` applies
// when the destination names an existing collection (row C3 of
// docs/object-transfer-semantics.md).  A copy source may be either a local path
// or a remote URL, and the object name has to be read off whichever it is.
func TestInferCopyObjectName(t *testing.T) {
	destURL, err := url.Parse("osdf:///ospool/ap40/data/user/tpc2/?directread")
	require.NoError(t, err)

	t.Run("appends the basename of a remote source", func(t *testing.T) {
		got, err := inferCopyObjectName(destURL, "osdf:///ospool/ap40/data/user/tpc1/testfile640MB")
		require.NoError(t, err)
		assert.Equal(t, "osdf:///ospool/ap40/data/user/tpc2/testfile640MB?directread", got)
	})

	t.Run("ignores a query string on the remote source", func(t *testing.T) {
		// A '?directread' on the source is a transfer instruction, not part
		// of the object's name.
		got, err := inferCopyObjectName(destURL, "pelican://example.org/ns/file.txt?directread")
		require.NoError(t, err)
		assert.Equal(t, "osdf:///ospool/ap40/data/user/tpc2/file.txt?directread", got)
	})

	t.Run("appends the basename of a local source", func(t *testing.T) {
		got, err := inferCopyObjectName(destURL, "/data/local/upload.txt")
		require.NoError(t, err)
		assert.Equal(t, "osdf:///ospool/ap40/data/user/tpc2/upload.txt?directread", got)
	})

	for _, source := range []string{"osdf:///ospool/data/..", "..", ".", "/", ""} {
		t.Run(fmt.Sprintf("refuses %q", source), func(t *testing.T) {
			// path.Join cleans its result, so a ".." here would resolve to
			// the parent of the collection the caller named.
			_, err := inferCopyObjectName(destURL, source)
			require.Error(t, err, "a source with no object name to infer must be refused")
			assert.Contains(t, err.Error(), "cannot infer a remote object name")
		})
	}
}

// TestObjectCopyToCollectionInfersObjectName drives the CLI end to end for the
// case reported in issue #3663: a third-party copy whose destination names an
// existing collection.  Before the fix the copy reached the destination origin
// as a write to the collection itself and came back as a bare HTTP 409.
//
// copyMain reports failure with os.Exit, so only the success path can be
// asserted through rootCmd; the refusals live in TestInferCopyObjectName.
func TestObjectCopyToCollectionInfersObjectName(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	fed := fed_test_utils.NewFedTest(t, copyTPCOriginCfg)
	require.NotNil(t, fed)
	require.Len(t, fed.Exports, 1)

	// The origin contacts itself over a local hostname that resolves to a
	// private address; the SSRF dialer is exercised on its own in
	// config/ssrf_transport_test.go.
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()
	require.NoError(t, param.Logging_Client_DisableProgressBars.Set(true))

	tokenFile, _ := getTempTokenForTest(t)
	t.Cleanup(func() {
		tokenFile.Close()
		os.Remove(tokenFile.Name())
	})

	prefix := fed.Exports[0].FederationPrefix
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	host := discoveryUrl.Host

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
		// Cobra copies the root's context onto a subcommand only while the
		// subcommand's own is nil, so copyCmd would otherwise pin this
		// test's cancelled context for every later test in the package.
		copyCmd.SetContext(nil)
	})

	const content = "third-party copy into a collection"
	localFile := filepath.Join(t.TempDir(), "testfile.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

	// Seed a source object, and an unrelated object under the destination
	// prefix so that the destination exists as a collection.  The seeding goes
	// through the library rather than `object put`, so this test does not leave
	// its (soon cancelled) context pinned on putCmd for the rest of the
	// package -- cobra copies the root's context onto a subcommand only while
	// the subcommand's own is nil.
	sourceURL := fmt.Sprintf("pelican://%s%s/src/testfile.txt", host, prefix)
	_, err = client.DoPut(fed.Ctx, localFile, sourceURL, false, client.WithTokenLocation(tokenFile.Name()))
	require.NoError(t, err)
	_, err = client.DoPut(fed.Ctx, localFile, fmt.Sprintf("pelican://%s%s/dst/seed.txt", host, prefix), false,
		client.WithTokenLocation(tokenFile.Name()))
	require.NoError(t, err)

	// The reported command line: a copy whose destination is the collection.
	destCollection := fmt.Sprintf("pelican://%s%s/dst/", host, prefix)
	rootCmd.SetContext(fed.Ctx)
	copyCmd.SetContext(fed.Ctx)
	rootCmd.SetArgs([]string{"object", "copy", "-t", tokenFile.Name(), sourceURL, destCollection})
	require.NoError(t, rootCmd.Execute())
	rootCmd.SetArgs(nil)

	// The object must land under the collection, named after the source.
	inferred := fmt.Sprintf("pelican://%s%s/dst/testfile.txt", host, prefix)
	downloadPath := filepath.Join(t.TempDir(), "downloaded.txt")
	_, err = client.DoGet(fed.Ctx, inferred, downloadPath, false, client.WithTokenLocation(tokenFile.Name()))
	require.NoError(t, err, "the copy must land at dst/basename(source), not on the collection itself")

	downloaded, err := os.ReadFile(downloadPath)
	require.NoError(t, err)
	assert.Equal(t, content, string(downloaded))
}
