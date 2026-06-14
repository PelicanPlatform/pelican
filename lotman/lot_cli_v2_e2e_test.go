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

package lotman_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// ---- one-time pelican binary build for this test package ----
//
// The binary is built lazily (only when a test actually needs it) and exactly
// once for the whole package, into a temp dir cleaned up by TestMain.

var (
	pelicanBinaryPath string
	pelicanBuildDir   string
	pelicanBuildOnce  sync.Once
	pelicanBuildErr   error
)

func getPelicanBinary(t *testing.T) string {
	t.Helper()
	pelicanBuildOnce.Do(func() {
		pelicanBinaryPath = filepath.Join(pelicanBuildDir, "pelican")
		// Build the CLI (which lives in ../cmd) with both client and server
		// commands so the `lot` subcommands are present.
		build := exec.Command("go", "build", "-tags", "client,server", "-buildvcs=false", "-o", pelicanBinaryPath, "../cmd")
		if out, err := build.CombinedOutput(); err != nil {
			pelicanBuildErr = fmt.Errorf("failed to build pelican binary: %w\n%s", err, string(out))
		}
	})
	if pelicanBuildErr != nil {
		t.Fatalf("%v", pelicanBuildErr)
	}
	return pelicanBinaryPath
}

func TestMain(m *testing.M) {
	var err error
	pelicanBuildDir, err = os.MkdirTemp("", "pelican-lotman-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp build dir: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(pelicanBuildDir)
	os.Exit(code)
}

// lotCLIOriginConfig exports a single /test namespace from the in-process origin.
const lotCLIOriginConfig = `
Origin:
  StorageType: "posixv2"
  EnableDirectReads: true
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "DirectReads", "Listings"]
`

// mintLotAdminToken mints a token the cache accepts as an administrator for the
// lot API: it is issued by the server's local issuer with subject "admin", so
// the API's admin path authorizes every lot operation, overriding lot ownership.
// This is how the `pelican lot` CLI is intended to be driven. Mint it before any
// helper that re-points IssuerKeysDirectory (mintStorageToken below does).
func mintLotAdminToken(t *testing.T) string {
	t.Helper()
	cfg := token.NewWLCGToken()
	cfg.Lifetime = 30 * time.Minute
	cfg.Issuer = config.GetLocalIssuerUrl()
	cfg.Subject = "admin"
	cfg.AddAudienceAny()
	cfg.AddScopes(token_scopes.WebUi_Access)
	tok, err := cfg.CreateToken()
	require.NoError(t, err)
	return tok
}

// mintStorageToken mints a storage read/create/modify token used to push an
// object into the cache. It re-points IssuerKeysDirectory, so it must run after
// mintLotCRUDToken.
func mintStorageToken(t *testing.T) string {
	t.Helper()
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	cfg := token.NewWLCGToken()
	cfg.Lifetime = 10 * time.Minute
	cfg.Issuer = issuer
	cfg.Subject = "storage"
	cfg.AddAudienceAny()
	var scopes []token_scopes.TokenScope
	for _, base := range []token_scopes.TokenScope{
		token_scopes.Wlcg_Storage_Read,
		token_scopes.Wlcg_Storage_Create,
		token_scopes.Wlcg_Storage_Modify,
	} {
		s, err := base.Path("/")
		require.NoError(t, err)
		scopes = append(scopes, s)
	}
	cfg.AddScopes(scopes...)
	tok, err := cfg.CreateToken()
	require.NoError(t, err)
	return tok
}

// sentinelLot reports whether a lot name is one of the auto-created container
// lots rather than a namespace/reservation lot.
func sentinelLot(name string) bool {
	switch name {
	case "root", "default", "monitoring":
		return true
	}
	return false
}

// TestLotCLI_V2_CRUDAndAccounting brings up a federation with a V2 (persistent)
// cache that has LotMan enabled, then drives the `pelican lot` CLI against the
// cache's lot API: it exercises the full CRUD cycle on a caller-created lot and
// proves that bytes cached through the federation are accounted to a lot and
// reported back through the CLI.
func TestLotCLI_V2_CRUDAndAccounting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping federation+binary e2e in -short mode")
	}
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable the V2 persistent cache with LotMan + its REST API, and the cache
	// sizing/watermark parameters LotMan requires. Reconcile usage every second
	// so accounting shows up promptly.
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_EnableLotman.Set(true))
	require.NoError(t, param.Lotman_EnableAPI.Set(true))
	require.NoError(t, param.Cache_HighWaterMark.Set("100g"))
	require.NoError(t, param.Cache_LowWatermark.Set("50g"))
	require.NoError(t, param.Cache_FilesBaseSize.Set("1g"))
	require.NoError(t, param.Cache_FilesNominalSize.Set("2g"))
	require.NoError(t, param.Cache_FilesMaxSize.Set("100g"))
	require.NoError(t, param.Cache_LotUsageReconcileInterval.Set(time.Second))

	// Build the CLI binary (lazily, once) before standing up the federation.
	bin := getPelicanBinary(t)

	ft := fed_test_utils.NewFedTest(t, lotCLIOriginConfig)
	require.NotNil(t, ft)

	// Mint the lot-API admin token while the federation issuer key is still
	// active (mintStorageToken below re-points IssuerKeysDirectory). The admin
	// path overrides lot ownership, which is how operators drive the CLI.
	lotToken := mintLotAdminToken(t)
	tokenFile := filepath.Join(t.TempDir(), "lot.tok")
	require.NoError(t, os.WriteFile(tokenFile, []byte(lotToken), 0o600))

	fedInfo, err := config.GetFederation(ft.Ctx)
	require.NoError(t, err)
	caFile := param.Server_TLSCACertificateFile.GetString()
	cacheURL := fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	clientConfigDir := t.TempDir()

	// runLot invokes `pelican lot <args> --server <cache> --token <file> --json`.
	// The subprocess trusts the federation's generated CA (no skip-verify).
	runLot := func(args ...string) (stdout, stderr string, err error) {
		full := append([]string{"lot"}, args...)
		full = append(full, "--server", cacheURL, "--token", tokenFile, "--json")
		cmd := exec.CommandContext(ft.Ctx, bin, full...)
		cmd.Env = append(os.Environ(),
			"PELICAN_CONFIGDIR="+clientConfigDir,
			"PELICAN_SERVER_TLSCACERTIFICATEFILE="+caFile,
			"PELICAN_FEDERATION_DISCOVERYURL="+fedInfo.DiscoveryEndpoint,
		)
		var so, se bytes.Buffer
		cmd.Stdout = &so
		cmd.Stderr = &se
		err = cmd.Run()
		return so.String(), se.String(), err
	}

	// --- The CLI can reach the lot API and list lots. ---
	var listResp struct {
		Lots []string `json:"lots"`
	}
	require.Eventually(t, func() bool {
		so, se, err := runLot("list")
		if err != nil {
			t.Logf("lot list not ready yet: %v\nstderr: %s", err, se)
			return false
		}
		if jerr := json.Unmarshal([]byte(so), &listResp); jerr != nil {
			t.Logf("lot list output not JSON yet: %v (%s)", jerr, so)
			return false
		}
		return true
	}, 30*time.Second, time.Second, "`pelican lot list` should succeed against the cache")
	require.NotEmpty(t, listResp.Lots, "lot list should be non-empty")
	require.Contains(t, listResp.Lots, "root", "expected the root container lot to be present")

	// runLotOK runs a lot command and requires it to succeed, returning stdout.
	// (The API's readiness is handled by the require.Eventually around the first
	// list above; once it responds, mutating calls succeed on the first try.)
	runLotOK := func(desc string, args ...string) string {
		so, se, err := runLot(args...)
		require.NoError(t, err, "%s failed\nstdout: %s\nstderr: %s", desc, so, se)
		return so
	}

	// --- CRUD on a caller-created lot. Use an opportunistic-only quota: the
	// root lot's opportunistic axis is unbounded, so creating/updating an
	// opportunistic child is always within the hierarchy (the dedicated axis can
	// already be fully subscribed by the namespace lot). ---
	const crudLot = "cli-crud-lot"
	runLotOK("lot create", "create", "--name", crudLot, "--path", "/test/cli-crud", "--recursive",
		"--dedicated-gb", "0", "--opportunistic-gb", "1", "--max-objects", "-1")

	// get reflects the created lot's opportunistic quota (GB on the wire).
	var res struct {
		ReservationID   string   `json:"reservationId"`
		OpportunisticGB *float64 `json:"opportunisticGB"`
	}
	require.NoError(t, json.Unmarshal([]byte(runLotOK("lot get", "get", crudLot)), &res))
	require.Equal(t, crudLot, res.ReservationID)
	require.NotNil(t, res.OpportunisticGB)
	require.InDelta(t, 1.0, *res.OpportunisticGB, 1e-6)

	// update changes the opportunistic quota; get reflects it.
	runLotOK("lot update", "update", crudLot, "--opportunistic-gb", "2")
	require.NoError(t, json.Unmarshal([]byte(runLotOK("lot get after update", "get", crudLot)), &res))
	require.NotNil(t, res.OpportunisticGB)
	require.InDelta(t, 2.0, *res.OpportunisticGB, 1e-6, "update should have changed the opportunistic quota")

	// --- Accounting: cache an object under /test and confirm usage is reported
	// through the CLI. ---
	storageToken := mintStorageToken(t)
	localDir := t.TempDir()
	srcFile := filepath.Join(localDir, "obj.txt")
	content := strings.Repeat("lot-cli-accounting-payload-", 2048) // ~50 KB
	require.NoError(t, os.WriteFile(srcFile, []byte(content), 0o644))

	objURL := fmt.Sprintf("pelican://%s:%d/test/data/obj.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err = client.DoPut(ft.Ctx, srcFile, objURL, false, client.WithToken(storageToken))
	require.NoError(t, err, "uploading the object to the origin should succeed")
	dlFile := filepath.Join(localDir, "dl.txt")
	_, err = client.DoGet(ft.Ctx, objURL, dlFile, false, client.WithToken(ft.Token))
	require.NoError(t, err, "downloading through the cache should succeed")

	// Poll the CLI until some namespace lot reports non-zero cached usage. The
	// object lives under /test, so its bytes are attributed to the namespace lot
	// (not the cli-crud lot, whose path is /test/cli-crud).
	require.Eventually(t, func() bool {
		listOut, _, lerr := runLot("list")
		if lerr != nil {
			return false
		}
		var lr struct {
			Lots []string `json:"lots"`
		}
		if json.Unmarshal([]byte(listOut), &lr) != nil {
			return false
		}
		for _, name := range lr.Lots {
			if sentinelLot(name) || name == crudLot {
				continue
			}
			usageOut, _, uerr := runLot("usage", name)
			if uerr != nil {
				continue
			}
			var usage struct {
				TotalGB *struct {
					Total float64 `json:"total"`
				} `json:"totalGB"`
				NumObjects *struct {
					Total int64 `json:"total"`
				} `json:"numObjects"`
			}
			if json.Unmarshal([]byte(usageOut), &usage) != nil {
				continue
			}
			if usage.NumObjects != nil && usage.NumObjects.Total > 0 {
				return true
			}
			if usage.TotalGB != nil && usage.TotalGB.Total > 0 {
				return true
			}
		}
		return false
	}, 90*time.Second, 2*time.Second, "`pelican lot usage` should report non-zero cached usage for the /test namespace lot")

	// --- Delete the caller-created lot; it is then gone. ---
	runLotOK("lot delete", "delete", crudLot)
	_, _, getErr := runLot("get", crudLot)
	require.Error(t, getErr, "getting a deleted lot should fail")
}
