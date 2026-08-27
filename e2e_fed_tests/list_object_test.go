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

// Listing a plain object -- `pelican object ls <object>` -- rather than a
// collection.
//
// A PROPFIND against an object answers 207 with a single, non-collection
// response for the object itself. gowebdav's ReadDir treats the first
// response as "self" and, when self is not a collection, returns a synthetic
// PathError carrying 405. The client has to tell that apart from a server
// that genuinely refuses listings.

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

func TestListPlainObjectPosixV2(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	storageDir := ft.Exports[0].StoragePrefix
	const contents = "the object's contents"
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "solo.txt"), []byte(contents), 0644))

	token := getTempTokenForTest(t)
	objectURL := fmt.Sprintf("pelican://%s:%d/test/solo.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	entries, err := client.DoList(ft.Ctx, objectURL, client.WithToken(token))
	require.NoError(t, err, "listing a plain object must not report that the origin refuses listings")
	require.Len(t, entries, 1, "listing a plain object should yield exactly that object")
	assert.False(t, entries[0].IsCollection)
	assert.EqualValues(t, len(contents), entries[0].Size)
}
