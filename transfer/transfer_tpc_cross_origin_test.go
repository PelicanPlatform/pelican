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

package transfer_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// secondOrigin describes a real, independent Pelican origin launched as a
// subprocess and joined to the running test federation.
type secondOrigin struct {
	fedPrefix  string // federation prefix it exports, e.g. "/origin2"
	storageDir string // on-disk storage root for that prefix
	issuer     string // the origin's issuer URL (tokens for it must carry this)
	port       int    // its HTTPS web port
	password   string // htpasswd password of the origin's user
}

// launchSecondOrigin starts a second, independent origin as a subprocess that
// joins the federation the current process is running. It mirrors the origin
// launched in origin_serve's TestTPCCrossOrigin: it shares the federation's TLS
// material and issuer keys (so both present the same JWKS) and registers via the
// federation discovery URL. Unlike that test's origin, this one enables the
// embedded issuer and requires a token to read (no PublicReads), so a storage
// token is genuinely needed on the source side.
func launchSecondOrigin(t *testing.T, ctx context.Context, host, user, password string) secondOrigin {
	t.Helper()

	pelicanBinary := getPelicanBinary(t)

	origin2Dir := t.TempDir()
	storageDir := filepath.Join(origin2Dir, "storage")
	require.NoError(t, os.MkdirAll(storageDir, 0755))
	configDir := filepath.Join(origin2Dir, "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))
	runtimeDir := filepath.Join(origin2Dir, "runtime")
	require.NoError(t, os.MkdirAll(runtimeDir, 0755))

	// Find a free port for the second origin.
	ln, err := net.Listen("tcp", host+":0")
	require.NoError(t, err)
	origin2Port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Grab federation values from the running federation.
	discoveryURL := param.Federation_DiscoveryUrl.GetString()
	require.NotEmpty(t, discoveryURL, "Federation discovery URL should be set")
	caCertFile := param.Server_TLSCACertificateFile.GetString()
	caKeyFile := param.Server_TLSCAKey.GetString()
	tlsCertFile := param.Server_TLSCertificateChain.GetString()
	tlsKeyFile := param.Server_TLSKey.GetString()

	// Share the federation's issuer keys so the second origin signs with the
	// same key set the registry already knows (avoids "unable to verify you own
	// the registered server" when the hostname is shared).
	fedIssuerKeysDir := param.IssuerKeysDirectory.GetString()
	origin2KeysDir := filepath.Join(configDir, "issuer-keys")
	require.NoError(t, os.MkdirAll(origin2KeysDir, 0700))
	entries, err := os.ReadDir(fedIssuerKeysDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(fedIssuerKeysDir, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(origin2KeysDir, e.Name()), data, 0600))
	}

	// A distinct user with a distinct password lives on the second origin.
	htpasswdFile := filepath.Join(configDir, "htpasswd")
	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(fmt.Sprintf("%s:%s\n", user, string(pwHash))), 0600))

	fedPrefix := "/origin2"
	logPath := filepath.Join(origin2Dir, "origin2.log")

	configFile := filepath.Join(configDir, "pelican.yaml")
	configContent := fmt.Sprintf(`
Federation:
  DiscoveryUrl: %s
IssuerKeysDirectory: %s
Server:
  WebPort: %d
  TLSCACertificateFile: %s
  TLSCAKey: %s
  TLSCertificateChain: %s
  TLSKey: %s
  Hostname: %s
  UIPasswordFile: %s
  UILoginRateLimit: 100
  # Isolate the server database + its backups to this origin's temp dir.
  # Otherwise InitServerDatabase falls back to the shared default
  # (~/.config/pelican/pelican.sqlite and .../backups), which on a developer
  # machine may hold a stale schema and break migrations.
  DbLocation: %s
  DatabaseBackup:
    Location: %s
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  EnableDirectReads: true
  EnableCmsd: false
  EnableVoms: false
  Port: 0
  DbLocation: %s
  Exports:
    - StoragePrefix: %s
      FederationPrefix: %s
      Capabilities: ["Reads", "Writes", "DirectReads", "Listings", "Copies"]
Issuer:
  AuthorizationTemplates:
    - prefix: /$USER
      actions: ["read", "write", "create"]
Logging:
  Level: debug
  DisableProgressBars: true
  LogLocation: %s
Xrootd:
  RunLocation: %s
`, discoveryURL, origin2KeysDir, origin2Port, caCertFile, caKeyFile, tlsCertFile, tlsKeyFile, host,
		htpasswdFile,
		filepath.Join(origin2Dir, "server.sqlite"),
		filepath.Join(origin2Dir, "backups"),
		filepath.Join(origin2Dir, "origin.sqlite"),
		storageDir, fedPrefix,
		logPath, runtimeDir,
	)
	require.NoError(t, os.WriteFile(configFile, []byte(configContent), 0644))

	cmd := exec.CommandContext(ctx, pelicanBinary, "origin", "serve", "--config", configFile)
	cmd.Env = append(os.Environ(), "PELICAN_CONFIGDIR="+configDir)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-exitCh:
		case <-time.After(5 * time.Second):
			t.Log("Timed out waiting for origin2 process to exit during cleanup")
		}
	})
	for _, pipe := range []struct {
		r    *bufio.Scanner
		name string
	}{{bufio.NewScanner(stdoutPipe), "stdout"}, {bufio.NewScanner(stderrPipe), "stderr"}} {
		p := pipe
		go func() {
			for p.r.Scan() {
				t.Logf("[origin2-%s] %s", p.name, p.r.Text())
			}
		}()
	}

	// Wait for origin #2 to become healthy, then to be resolvable in the director.
	origin2URL := fmt.Sprintf("https://%s:%d", host, origin2Port)
	waitForStatus(t, ctx, origin2URL+"/api/v1.0/health", http.StatusOK, exitCh, logPath, "origin2 health")

	directorURL := param.Server_ExternalWebUrl.GetString()
	statURL := directorURL + "/api/v1.0/director/origin" + fedPrefix + "/" + user
	// The area may not exist yet; a 307 (redirect to the origin) or 404 both mean
	// the origin registered. Wait for the namespace to be routable.
	waitForRegistration(t, ctx, statURL, exitCh, logPath)

	return secondOrigin{
		fedPrefix:  fedPrefix,
		storageDir: storageDir,
		// Tokens for this origin's namespace must carry the embedded issuer's
		// per-namespace URL — the issuer the director advertises in its
		// token-generation hint and the only one the origin trusts for
		// /origin2.  (A standalone origin serves its JWKS at the root
		// /.well-known/issuer.jwks, which this issuer's discovery document
		// advertises; see the RegisterOIDCAPI standalone branch in
		// launchers/origin_serve.go.)  Its base-path is the namespace, so
		// storage scopes are relative to it.
		issuer:   origin2URL + "/api/v1.0/issuer/ns" + fedPrefix,
		port:     origin2Port,
		password: password,
	}
}

// waitForStatus polls url until it returns wantStatus, the subprocess exits, or
// the context is done.
func waitForStatus(t *testing.T, ctx context.Context, url string, wantStatus int, exitCh <-chan error, logPath, name string) {
	t.Helper()
	hc := &http.Client{Transport: config.GetTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(45 * time.Second)
	for {
		select {
		case err := <-exitCh:
			dumpFileToLog(t, logPath)
			t.Fatalf("origin2 exited while waiting for %s: %v", name, err)
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for %s: %v", name, ctx.Err())
		default:
		}
		if time.Now().After(deadline) {
			dumpFileToLog(t, logPath)
			t.Fatalf("timed out waiting for %s at %s", name, url)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if resp, err := hc.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == wantStatus {
				return
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// waitForRegistration polls the director stat endpoint until it responds with a
// redirect (namespace routable) rather than a 5xx/connection error.
func waitForRegistration(t *testing.T, ctx context.Context, url string, exitCh <-chan error, logPath string) {
	t.Helper()
	hc := &http.Client{Transport: config.GetTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(45 * time.Second)
	for {
		select {
		case err := <-exitCh:
			dumpFileToLog(t, logPath)
			t.Fatalf("origin2 exited while waiting for director registration: %v", err)
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for director registration: %v", ctx.Err())
		default:
		}
		if time.Now().After(deadline) {
			dumpFileToLog(t, logPath)
			t.Fatalf("timed out waiting for director registration at %s", url)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if resp, err := hc.Do(req); err == nil {
			code := resp.StatusCode
			resp.Body.Close()
			if code == http.StatusTemporaryRedirect || code == http.StatusOK || code == http.StatusNotFound {
				return
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
}

func dumpFileToLog(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err == nil {
		t.Logf("===== %s =====\n%s\n=====", path, string(data))
	}
}

// storageTokenForIssuer mints a WLCG storage token with the given issuer,
// subject, and resource scopes, signed by the server's (shared) issuer key.
func storageTokenForIssuer(t *testing.T, issuer, subject string, scopes ...token_scopes.ResourceScope) string {
	t.Helper()
	tc := token.NewWLCGToken()
	tc.Lifetime = 10 * time.Minute
	tc.Issuer = issuer
	tc.Subject = subject
	tc.AddAudienceAny()
	tc.AddResourceScopes(scopes...)
	tok, err := tc.CreateToken()
	require.NoError(t, err)
	return tok
}

// writeTokenFile writes a token to a temp file and returns its path.
func writeTokenFile(t *testing.T, name, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(tok), 0600))
	return p
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

// pollTransferJob polls the transfer server for a job's status until it reaches
// a terminal state or the timeout elapses, returning the last observed status.
// It logs the full job record when the job ends in a non-completed state.
func pollTransferJob(t *testing.T, ctx context.Context, serverURL, token, jobID string, timeout time.Duration) string {
	t.Helper()
	hc := &http.Client{Transport: config.GetTransport()}
	url := serverURL + "/api/v1.0/transfer/jobs/" + jobID
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			last = nil
			_ = json.Unmarshal(body, &last)
			if st, _ := last["status"].(string); st != "" {
				switch st {
				case "completed":
					return st
				case "error", "failed", "cancelled":
					t.Logf("job %s reached terminal status %q: %s", jobID, st, string(body))
					return st
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Logf("job %s did not reach a terminal state within %s; last record: %v", jobID, timeout, last)
	return "timeout"
}

var credIDRe = regexp.MustCompile(`id:\s*([0-9a-fA-F-]+)`)

// cliCredentialAdd stores a storage token as a credential on the transfer
// server via the CLI and returns the new credential's ID.
func cliCredentialAdd(t *testing.T, cliPath, serverURL, transferTokenFile, name, tokenFile, issuer string, env []string) string {
	t.Helper()
	cmd := exec.Command(cliPath, "transfer", "credential", "add",
		"--server", serverURL,
		"--token", transferTokenFile,
		"--name", name,
		"--access-token-file", tokenFile,
		"--issuer", issuer,
	)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "credential add (%s) failed: %s", name, string(out))
	t.Logf("credential add %s: %s", name, strings.TrimSpace(string(out)))
	m := credIDRe.FindStringSubmatch(string(out))
	require.Len(t, m, 2, "could not parse credential id from: %s", string(out))
	return m[1]
}

// TestTransferTPCCrossOriginE2E drives a third-party copy BETWEEN TWO DISTINCT
// origins through the transfer server, entirely from the CLI:
//
//   - Origin #1 (the running federation) hosts the transfer API and user1's
//     read/write area under /data/user1.
//   - Origin #2 is an independent Pelican origin launched as a subprocess and
//     joined to the federation; it hosts user2's area under /origin2/user2.
//   - The embedded issuer mints a storage token for each side (user2 reads
//     /origin2/user2, user1 writes /data/user1) plus a distinct pelican.transfer
//     token for authenticating to the transfer server.
//   - The CLI stores both storage tokens as transfer-server credentials and then
//     runs `object copy --transfer-server ...` referencing them, moving the file
//     from origin #2 to origin #1.
func TestTransferTPCCrossOriginE2E(t *testing.T) {
	ft, _, testUserPassword, dataDir := setupFedForTransferTPC(t)
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	serverURL := param.Server_ExternalWebUrl.GetString()
	host := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()

	// user1 lives on origin #1 (the federation origin); user2 on origin #2.
	const user1, user2 = "testuser", "user2"
	user2Password := randomString(16)

	// Launch the independent second origin and wait for it to join the fed.
	ctx, cancel := context.WithCancel(ft.Ctx)
	defer cancel()
	o2 := launchSecondOrigin(t, ctx, host, user2, user2Password)
	_ = testUserPassword

	// Seed user2's source file on origin #2's storage (owned by the xrootd daemon).
	srcDir := filepath.Join(o2.storageDir, user2)
	require.NoError(t, os.MkdirAll(srcDir, 0755))
	srcFile := filepath.Join(srcDir, "source.txt")
	srcContent := "cross-origin transfer-server payload"
	require.NoError(t, os.WriteFile(srcFile, []byte(srcContent), 0644))
	test_utils.ChownToDaemon(t, srcDir, srcFile)

	// Ensure user1's destination area exists on origin #1.
	destDir := filepath.Join(dataDir, user1)
	require.NoError(t, os.MkdirAll(destDir, 0755))
	test_utils.ChownToDaemon(t, destDir)

	// Storage tokens from each origin's per-namespace embedded issuer — the
	// only issuer each origin trusts for its own namespace.  Both issuers have
	// a base-path equal to their namespace, so storage scopes are relative to
	// it (e.g. "/user2" → /origin2/user2, "/testuser" → /data/testuser).
	const destNS = "/data"
	origin1Issuer := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/issuer/ns" + destNS
	srcTokenFile := writeTokenFile(t, "src-token", storageTokenForIssuer(t, o2.issuer, user2,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"+user2)))
	dstTokenFile := writeTokenFile(t, "dst-token", storageTokenForIssuer(t, origin1Issuer, user1,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"+user1),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"+user1),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"+user1)))

	// A distinct pelican.transfer token authenticates the CLI to the transfer server.
	transferTokenFile := writeTokenFile(t, "transfer-token", generateTransferScopeToken(t))

	cliPath := getPelicanBinary(t)
	cliEnv := append(os.Environ(),
		"PELICAN_FEDERATION_DISCOVERYURL="+param.Federation_DiscoveryUrl.GetString(),
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_SKIP_TERMINAL_CHECK=1",
		"PELICAN_LOGGING_DISABLEPROGRESSBARS=true",
	)

	// Store both storage tokens as transfer-server credentials (CLI-driven).
	srcCredID := cliCredentialAdd(t, cliPath, serverURL, transferTokenFile, "src-user2", srcTokenFile, o2.issuer, cliEnv)
	dstCredID := cliCredentialAdd(t, cliPath, serverURL, transferTokenFile, "dst-user1", dstTokenFile, origin1Issuer, cliEnv)

	// Run the third-party copy across the two origins via the transfer server.
	sourceURL := fmt.Sprintf("pelican://%s:%d%s/%s/source.txt", host, port, o2.fedPrefix, user2)
	destURL := fmt.Sprintf("pelican://%s:%d/data/%s/dest.txt", host, port, user1)

	copyCmd := exec.Command(cliPath, "object", "copy",
		"--transfer-server", serverURL,
		"--transfer-server-token", transferTokenFile,
		"--source-credential-id", srcCredID,
		"--dest-credential-id", dstCredID,
		sourceURL, destURL,
	)
	copyCmd.Env = cliEnv
	copyOut, copyErr := copyCmd.CombinedOutput()
	t.Logf("object copy output:\n%s", string(copyOut))
	require.NoError(t, copyErr, "submitting the cross-origin copy should succeed")

	jm := regexp.MustCompile(`job submitted:\s*([0-9a-fA-F-]+)`).FindStringSubmatch(string(copyOut))
	require.Len(t, jm, 2, "could not parse job id from: %s", string(copyOut))
	transferTok := strings.TrimSpace(readFileString(t, transferTokenFile))
	status := pollTransferJob(t, ft.Ctx, serverURL, transferTok, jm[1], 120*time.Second)
	require.Equal(t, "completed", status, "cross-origin transfer job should reach completed")

	// Verify the destination file on origin #1 by downloading it with a read token.
	dlDir := t.TempDir()
	readTok := storageTokenForIssuer(t, origin1Issuer, user1,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"+user1))
	_, err := client.DoGet(ft.Ctx, destURL+"?directread", filepath.Join(dlDir, "dest.txt"), false,
		client.WithToken(readTok))
	require.NoError(t, err, "downloading the copied file from origin #1 should succeed")
	got, err := os.ReadFile(filepath.Join(dlDir, "dest.txt"))
	require.NoError(t, err)
	assert.Equal(t, srcContent, string(got), "destination content should match the source")
}
