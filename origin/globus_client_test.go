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

package origin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestPersistTokenConfinesFileToTokenDir(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	globusDir := t.TempDir()
	tokDir := filepath.Join(globusDir, "tokens")
	require.NoError(t, os.MkdirAll(tokDir, 0700))
	require.NoError(t, param.Origin_GlobusConfigLocation.Set(globusDir))
	tok := &oauth2.Token{AccessToken: "secret"}

	path, err := persistToken("3b7e8f2a-collection", tok, TokenTypeCollection)
	require.NoError(t, err)
	assert.Equal(t, tokDir, filepath.Dir(path))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "secret\n", string(contents))

	// The collection ID comes from the OAuth callback's state parameter, so a
	// path-like ID must never place a token file outside the token directory.
	for _, id := range []string{"../escape", "/etc/escape", "nested/id"} {
		_, err := persistToken(id, tok, TokenTypeTransfer)
		assert.Error(t, err, "collection ID %q must be rejected", id)
	}
	_, err = os.Stat(filepath.Join(globusDir, "escape"+globusTransferTokenFileExt))
	assert.True(t, os.IsNotExist(err), "no token may be written outside the token directory")
}
