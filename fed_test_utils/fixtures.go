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

// Fixtures shared by the end-to-end federation test packages.  These live here rather than
// in any one of them because e2e_fed_tests and e2e_cache_tests both need them.

package fed_test_utils

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// BothPublicNamespaces is a two-export origin config with both namespaces public.
//
//go:embed resources/both-public.yml
var BothPublicNamespaces string

// Helper function to get a token with write permissions for testing
func TempWriteToken(t testing.TB) string {
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

	// Get the server issuer URL (same as FedTest uses)
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, readScope)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, createScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	return tkn
}

// OriginServerURL returns the https://host:port string for the running origin.
func OriginServerURL() string {
	return fmt.Sprintf("https://%s:%d",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
}

// SkipUnlessXattrs ensures the filesystem under tmpPath supports user xattrs,
// which the checksum-cache layer requires. macOS tmpfs / some Linux mounts
// silently reject these.
func SkipUnlessXattrs(t *testing.T, tmpPath string) {
	t.Helper()
	probe := filepath.Join(tmpPath, ".xattr-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Skipf("could not write probe file: %v", err)
	}
	defer os.Remove(probe)
	if err := xattr.Set(probe, "user.test.pelican", []byte("y")); err != nil {
		t.Skipf("xattrs not supported on this filesystem: %v", err)
	}
}

// LockedWriter serialises writes to an internal buffer so a child process's stdout and
// stderr can safely share one destination.  Its zero value is ready to use.
type LockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (lw *LockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.buf.Write(p)
}

// String returns everything written so far.  It is safe to call while the child process is
// still running.
func (lw *LockedWriter) String() string {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.buf.String()
}
