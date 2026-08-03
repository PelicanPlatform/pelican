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

package fed_tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/param"
)

// This file is the binary-vs-binary counterpart to cmd/origin_standalone_test.go.
//
// The in-process test proves the standalone origin's *handlers* behave; it does
// so with the origin's own config, key material, and client library loaded into
// the test process.  That arrangement cannot detect the failures that matter
// most to an operator who types `pelican origin serve`: config that is only
// reachable through the parameter API, key material the client can only get at
// through a file, and federation discovery that would silently work because the
// test process already knew the answer.
//
// So everything here crosses a process boundary.  The origin is a child process
// started from the built binary via its CLI; every client action is another
// child process invoking the `pelican` CLI; and the only things they share are
// a TCP port, a filesystem path to one PEM file, and the bytes being
// transferred.  The parent test process holds no Pelican global state at all --
// note the absence of ResetTestState and of fed_test_utils.NewFedTest, which
// would contradict the entire premise by standing up a federation.

const standaloneCliPrefix = "/standalone-cli"

// pelicanEnv returns an environment for a child pelican process with every
// PELICAN_* variable stripped.  Configuration must arrive only through the
// config file (for the origin) or the explicit variables we add back (for the
// client); inheriting the developer's or CI job's Pelican environment would let
// a federation setting leak in and quietly invalidate the test.
func pelicanEnv(extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PELICAN_") || strings.HasPrefix(kv, "OSDF_") || strings.HasPrefix(kv, "STASH_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// standaloneOriginProcess is a running `pelican origin serve` child.
type standaloneOriginProcess struct {
	webUrl        string
	storageDir    string
	issuerKeyPath string
	// caPath is the CA the origin generated for itself at startup.  Both the
	// test's own HTTP client and every child pelican process verify the
	// origin's certificate against it: a certificate that does not cover the
	// host the discovery document advertises is a real failure, and skipping
	// verification would hide it.
	caPath string
	client *http.Client
}

// startStandaloneOrigin writes a config file that describes a standalone origin
// -- and nothing else -- then launches the pelican binary against it and waits
// for it to serve.
//
// The config deliberately omits Federation.DiscoveryUrl.  A federated origin
// cannot start without one (the negative control at the bottom of this file
// demonstrates that with the very same config file), so the origin reaching a
// healthy state is itself the assertion that no federation touchpoint ran.
func startStandaloneOrigin(t *testing.T, ctx context.Context, cliPath string) *standaloneOriginProcess {
	t.Helper()

	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	runtimeDir := filepath.Join(root, "runtime")
	storageDir := filepath.Join(root, "storage")
	issuerKeysDir := filepath.Join(configDir, "issuer-keys")
	for _, dir := range []string{configDir, runtimeDir, storageDir, issuerKeysDir} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	configPath := writeStandaloneConfig(t, configDir, runtimeDir, storageDir, issuerKeysDir, true)

	var output bytes.Buffer
	var outputMu sync.Mutex
	cmd := exec.CommandContext(ctx, cliPath, "origin", "serve", "--config", configPath)
	cmd.Env = pelicanEnv()
	cmd.Stdout = &lockedWriter{w: &output, mu: &outputMu}
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start(), "failed to start the standalone origin")

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	snapshot := func() string {
		outputMu.Lock()
		defer outputMu.Unlock()
		return output.String()
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Log("timed out waiting for the standalone origin to exit")
		}
		if t.Failed() {
			t.Logf("standalone origin output:\n%s", snapshot())
		}
	})

	// Server.WebPort is 0, so the port is not known until the child has bound
	// it.  Pelican records the result in the runtime directory's address file
	// precisely so that external tooling does not have to scrape logs or
	// pre-select a port (which would race with the child's bind).
	addressFile := filepath.Join(runtimeDir, "pelican.addresses")
	var webUrl string
	require.Eventually(t, func() bool {
		select {
		case err := <-exited:
			t.Fatalf("standalone origin exited before writing its address file: %v\n%s", err, snapshot())
		default:
		}
		contents, err := os.ReadFile(addressFile)
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(contents), "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "SERVER_EXTERNAL_WEB_URL="); ok {
				webUrl = after
				return webUrl != ""
			}
		}
		return false
	}, 90*time.Second, 250*time.Millisecond, "standalone origin never published its address file")

	// The origin generates its CA during startup; the client cannot verify
	// anything until it is on disk.
	caPath := filepath.Join(configDir, "certificates", "tlsca.pem")
	require.Eventually(t, func() bool {
		select {
		case err := <-exited:
			t.Fatalf("standalone origin exited before writing its CA certificate: %v\n%s", err, snapshot())
		default:
		}
		info, err := os.Stat(caPath)
		return err == nil && info.Size() > 0
	}, 90*time.Second, 250*time.Millisecond, "standalone origin never wrote %s", caPath)
	httpc := clientTrusting(t, caPath)

	require.Eventually(t, func() bool {
		select {
		case err := <-exited:
			t.Fatalf("standalone origin exited before becoming healthy: %v\n%s", err, snapshot())
		default:
		}
		resp, err := httpc.Get(webUrl + "/api/v1.0/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 90*time.Second, 250*time.Millisecond, "standalone origin never became healthy")

	// The client signs tokens with the origin's issuer key.  Locating the PEM
	// on disk is how an administrator of the host would do it, and it keeps the
	// two processes sharing a file rather than a process-global key cache.
	pems, err := filepath.Glob(filepath.Join(issuerKeysDir, "*.pem"))
	require.NoError(t, err)
	require.Len(t, pems, 1, "expected the origin to have generated exactly one issuer key in %s", issuerKeysDir)

	return &standaloneOriginProcess{
		webUrl:        webUrl,
		storageDir:    storageDir,
		issuerKeyPath: pems[0],
		caPath:        caPath,
		client:        httpc,
	}
}

// writeStandaloneConfig emits the origin's config file.  It is shared with the
// negative control, which flips `standalone` to false and expects startup to
// fail; keeping one writer guarantees the control differs in exactly that knob.
func writeStandaloneConfig(t *testing.T, configDir, runtimeDir, storageDir, issuerKeysDir string, standalone bool) string {
	t.Helper()

	cfg := map[string]any{
		"ConfigBase":          configDir,
		"RuntimeDir":          runtimeDir,
		"IssuerKeysDirectory": issuerKeysDir,
		"Logging": map[string]any{
			// No LogLocation: the child's log has to come back on stdout so a
			// CI failure is diagnosable from the test output alone.
			"Level":               "debug",
			"DisableProgressBars": true,
		},
		"Server": map[string]any{
			// Hostname is fixed to localhost so the self-signed certificate
			// Pelican generates matches the name the client dials.
			"Hostname": "localhost",
			"WebPort":  0,
			"EnableUI": false,
			// Lets the test read the child's component health over the wire;
			// see the no-federation-components assertion.
			"HealthMonitoringPublic": true,
		},
		"Origin": map[string]any{
			"EnableStandaloneMode": standalone,
			// posixv2 is a native backend served in-process: no XRootD, no
			// libXrdClPelican, and the only storage type family standalone
			// mode permits.
			"StorageType": "posixv2",
			// The embedded issuer is the only issuer a standalone origin can
			// have; the default (oa4mp) is a separate Java service that a
			// federation-less deployment has no way to reach.
			"EnableIssuer": true,
			"IssuerMode":   "embedded",
			"DbLocation":   filepath.Join(configDir, "origin.sqlite"),
			"RunLocation":  filepath.Join(runtimeDir, "origin"),
			"Exports": []map[string]any{{
				"StoragePrefix":    storageDir,
				"FederationPrefix": standaloneCliPrefix,
				// No PublicReads: every operation below, including the read,
				// has to carry a token minted by this origin's own issuer.
				"Capabilities": []string{"Reads", "Writes", "Listings"},
			}},
		},
	}

	contents, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	configPath := filepath.Join(configDir, "pelican.yaml")
	require.NoError(t, os.WriteFile(configPath, contents, 0644))
	return configPath
}

// clientTrusting returns an HTTP client that verifies certificates against the
// CA at caPath -- the one Pelican generated for this origin.
func clientTrusting(t *testing.T, caPath string) *http.Client {
	t.Helper()

	pem, err := os.ReadFile(caPath)
	require.NoError(t, err, "could not read the origin's CA certificate")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem), "no certificate found in %s", caPath)

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

// runClient invokes the pelican CLI as a separate process with a clean
// environment.  It returns the combined output and the command's error so that
// callers can assert on failure as readily as on success.
func runClient(t *testing.T, ctx context.Context, cliPath, clientConfigDir, caPath string, args ...string) (string, error) {
	t.Helper()
	return runClientWithEnv(t, ctx, cliPath, clientConfigDir, caPath, nil, args...)
}

// runClientWithEnv is runClient with additional environment variables, for the
// cases that turn on what the client can discover for itself rather than on
// what it was handed on the command line.
func runClientWithEnv(t *testing.T, ctx context.Context, cliPath, clientConfigDir, caPath string, extraEnv []string, args ...string) (string, error) {
	t.Helper()

	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Env = pelicanEnv(append([]string{
		// The origin's certificate is signed by a CA that exists only in the
		// origin's config directory, so point the client at it rather than
		// having it skip verification -- which would stop these tests noticing
		// a certificate that does not match what discovery advertises.
		"PELICAN_SERVER_TLSCACERTIFICATEFILE=" + caPath,
		// Keep the client's token cache and config out of the developer's
		// real ~/.config/pelican.
		"PELICAN_CONFIGBASE=" + clientConfigDir,
		"PELICAN_LOGGING_LEVEL=debug",
		"PELICAN_LOGGING_CLIENT_DISABLEPROGRESSBARS=true",
	}, extraEnv...)...)
	out, err := cmd.CombinedOutput()
	t.Logf("$ pelican %s\n%s", strings.Join(args, " "), string(out))
	return string(out), err
}

// createToken drives `pelican token create` in its own process and writes the
// resulting JWT to a file, which is the form `object get/put/ls -t` expects.
//
// tokenDir must outlive every command that will use the token: the CLI reads
// the file lazily, at transfer time, so a token written into a subtest's
// t.TempDir() is deleted out from under a later subtest.
func createToken(t *testing.T, ctx context.Context, cliPath, clientConfigDir, tokenDir, name string, origin *standaloneOriginProcess, extraArgs ...string) string {
	t.Helper()

	args := append([]string{
		"token", "create",
		"--private-key", origin.issuerKeyPath,
		"--lifetime", "600",
	}, extraArgs...)
	out, err := runClient(t, ctx, cliPath, clientConfigDir, origin.caPath, args...)
	require.NoError(t, err, "pelican token create failed: %s", out)

	// The JWT is the last non-empty line; anything before it is log output.
	var tok string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Count(line, ".") == 2 && strings.HasPrefix(line, "ey") {
			tok = line
		}
	}
	require.NotEmpty(t, tok, "could not find a JWT in `pelican token create` output: %s", out)

	tokenPath := filepath.Join(tokenDir, name)
	require.NoError(t, os.WriteFile(tokenPath, []byte(tok), 0600))
	return tokenPath
}

// TestStandaloneOriginCliEndToEnd runs a standalone origin as its own OS
// process and drives it entirely with the pelican client binary run as further
// OS processes.
func TestStandaloneOriginCliEndToEnd(t *testing.T) {
	cliPath := getPelicanBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	origin := startStandaloneOrigin(t, ctx, cliPath)
	clientConfigDir := t.TempDir()
	tokenDir := t.TempDir()

	pelicanUrl := func(objectPath string) string {
		return "pelican://" + strings.TrimPrefix(origin.webUrl, "https://") + standaloneCliPrefix + objectPath
	}

	// The origin is up without a federation.  Reaching this point already proves
	// discovery was skipped; the discovery document it serves shows what it put
	// in the federation's place.
	t.Run("serves-its-own-federation-metadata", func(t *testing.T) {
		resp, err := origin.client.Get(origin.webUrl + "/.well-known/pelican-configuration")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var fed struct {
			DiscoveryEndpoint string `json:"discovery_endpoint"`
			DirectorEndpoint  string `json:"director_endpoint"`
			RegistryEndpoint  string `json:"namespace_registration_endpoint"`
			BrokerEndpoint    string `json:"broker_endpoint"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&fed))
		assert.Equal(t, origin.webUrl, fed.DiscoveryEndpoint)
		assert.Empty(t, fed.DirectorEndpoint,
			"naming no director is what tells a client to resolve objects against this origin directly")
		assert.Empty(t, fed.RegistryEndpoint, "there is no registry to register with")
		assert.Empty(t, fed.BrokerEndpoint, "there is no broker to reverse-connect through")
	})

	// The whole client workflow follows, one OS process per step, with the token
	// obtained from the CLI rather than minted inside the test.
	var readWriteToken string
	t.Run("cli-token-create-against-the-origins-own-issuer", func(t *testing.T) {
		// No --issuer: the CLI has to discover it, which means asking this
		// origin about the object and finding the per-namespace
		// issuer in the X-Pelican-Authorization header, then matching the
		// signing key against that issuer's published JWKS.  That whole chain
		// is served by the standalone origin itself.
		readWriteToken = createToken(t, ctx, cliPath, clientConfigDir, tokenDir, "read-write", origin,
			"--read", "--write", "--modify", pelicanUrl("/roundtrip.txt"))
	})
	require.NotEmpty(t, readWriteToken, "the transfer subtests below need a token from the CLI")

	// A payload large enough that a truncated or re-encoded transfer shows up
	// as a byte difference rather than passing by luck.
	payload := make([]byte, 1<<20)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	sourcePath := filepath.Join(t.TempDir(), "roundtrip.txt")
	require.NoError(t, os.WriteFile(sourcePath, payload, 0644))

	t.Run("cli-put-then-get-round-trip", func(t *testing.T) {
		out, err := runClient(t, ctx, cliPath, clientConfigDir, origin.caPath,
			"object", "put", "-t", readWriteToken, sourcePath, pelicanUrl("/roundtrip.txt"))
		require.NoError(t, err, "object put failed: %s", out)

		// The origin's backing store is a plain directory, so the upload is
		// observable on disk independently of anything the client reports.
		onDisk, err := os.ReadFile(filepath.Join(origin.storageDir, "roundtrip.txt"))
		require.NoError(t, err)
		require.Equal(t, payload, onDisk, "bytes on the origin's disk differ from the uploaded file")

		downloadPath := filepath.Join(t.TempDir(), "roundtrip.txt")
		out, err = runClient(t, ctx, cliPath, clientConfigDir, origin.caPath,
			"object", "get", "-t", readWriteToken, pelicanUrl("/roundtrip.txt"), downloadPath)
		require.NoError(t, err, "object get failed: %s", out)

		downloaded, err := os.ReadFile(downloadPath)
		require.NoError(t, err)
		require.Equal(t, payload, downloaded, "downloaded bytes differ from the uploaded file")
	})

	// Everything above hands the client its credential with -t, which lets it
	// skip straight to the transfer.  Here it is given nothing: to read the
	// object it has to resolve `pelican://<origin>/...` against a federation
	// that publishes no director, learn from the origin's own reply that the
	// namespace requires a token, and then find a credential for that issuer
	// itself -- the whole directorless path, across a process boundary.
	t.Run("cli-get-finds-its-own-token", func(t *testing.T) {
		// Nothing to find yet: the read must fail, or the success below would
		// prove nothing about credential discovery.
		emptyEnv := filepath.Join(t.TempDir(), "no-token-here")
		downloadPath := filepath.Join(t.TempDir(), "discovered.txt")
		out, err := runClientWithEnv(t, ctx, cliPath, clientConfigDir, origin.caPath,
			[]string{"BEARER_TOKEN_FILE=" + emptyEnv},
			"object", "get", pelicanUrl("/roundtrip.txt"), downloadPath)
		require.Error(t, err, "a read with no discoverable credential must fail: %s", out)
		require.NoFileExists(t, downloadPath)

		// The same command, with a credential where WLCG Bearer Token
		// Discovery looks for one and still no -t on the command line.
		out, err = runClientWithEnv(t, ctx, cliPath, clientConfigDir, origin.caPath,
			[]string{"BEARER_TOKEN_FILE=" + readWriteToken},
			"object", "get", pelicanUrl("/roundtrip.txt"), downloadPath)
		require.NoError(t, err, "object get without -t failed: %s", out)

		downloaded, err := os.ReadFile(downloadPath)
		require.NoError(t, err)
		require.Equal(t, payload, downloaded, "downloaded bytes differ from the uploaded file")
	})

	// A listing has the same second chance a download does: it PROPFINDs, is
	// refused, reads the issuer off the refusal, and asks again.  Nothing is
	// handed to it on the command line.
	t.Run("cli-ls-finds-its-own-token", func(t *testing.T) {
		listToken := createToken(t, ctx, cliPath, clientConfigDir, tokenDir, "list-discovered", origin,
			"--read", pelicanUrl(""))

		out, err := runClientWithEnv(t, ctx, cliPath, clientConfigDir, origin.caPath,
			[]string{"BEARER_TOKEN_FILE=" + filepath.Join(t.TempDir(), "no-token-here")},
			"object", "ls", pelicanUrl(""))
		require.Error(t, err, "a listing with no discoverable credential must fail: %s", out)

		out, err = runClientWithEnv(t, ctx, cliPath, clientConfigDir, origin.caPath,
			[]string{"BEARER_TOKEN_FILE=" + listToken},
			"object", "ls", pelicanUrl(""))
		require.NoError(t, err, "object ls without -t failed: %s", out)
		assert.Contains(t, out, "roundtrip.txt")
	})

	t.Run("cli-ls-lists-the-object", func(t *testing.T) {
		// A listing reads the collection, not the object, so it needs a token
		// whose scope covers the namespace root. Asking `token create` for the
		// bare prefix produces exactly that -- which is also a check that the
		// CLI strips the federation prefix correctly when the URL *is* the
		// prefix, the edge case where a naive TrimPrefix yields an empty path.
		listToken := createToken(t, ctx, cliPath, clientConfigDir, tokenDir, "list", origin,
			"--read", pelicanUrl(""))

		out, err := runClient(t, ctx, cliPath, clientConfigDir, origin.caPath,
			"object", "ls", "-t", listToken, pelicanUrl(""))
		require.NoError(t, err, "object ls failed: %s", out)
		assert.Contains(t, out, "roundtrip.txt")
	})

	// Standalone mode removes the federation, not authorization.
	t.Run("cli-put-without-a-token-is-rejected", func(t *testing.T) {
		out, err := runClient(t, ctx, cliPath, clientConfigDir, origin.caPath,
			"object", "put", sourcePath, pelicanUrl("/no-token.txt"))
		require.Error(t, err, "object put with no token unexpectedly succeeded: %s", out)
		// Check *why* it failed, so this cannot pass because of a typo in the
		// URL or an unreachable origin.
		assert.Contains(t, strings.ToLower(out), "authorization",
			"expected an authorization failure, not some other error")
		assert.NoFileExists(t, filepath.Join(origin.storageDir, "no-token.txt"))
	})

	t.Run("cli-put-with-a-token-for-another-path-is-rejected", func(t *testing.T) {
		// Same issuer, same signing key, valid signature -- only the scope
		// path is wrong.  This distinguishes "the origin checks scopes" from
		// "the origin checks that a token exists".
		wrongScopeToken := createToken(t, ctx, cliPath, clientConfigDir, tokenDir, "wrong-scope", origin,
			"--write", "--modify", "--scope-path", "/somewhere-else", pelicanUrl("/wrong-scope.txt"))

		out, err := runClient(t, ctx, cliPath, clientConfigDir, origin.caPath,
			"object", "put", "-t", wrongScopeToken, sourcePath, pelicanUrl("/wrong-scope.txt"))
		require.Error(t, err, "object put with a mis-scoped token unexpectedly succeeded: %s", out)
		// 403 rather than 401: the origin accepted the token as authentic and
		// then refused the scope, which is the distinction being tested.
		assert.Contains(t, out, "403", "expected the origin to reject the token's scope with a 403")
		assert.NoFileExists(t, filepath.Join(origin.storageDir, "wrong-scope.txt"))
	})

	// Nothing in the origin process ever talked to a federation service.  The
	// health report is the origin's own record of which subsystems ran, and
	// reading it over the wire from a separate process means it describes this
	// server and only this server.
	t.Run("health-report-has-no-federation-components", func(t *testing.T) {
		resp, err := origin.client.Get(origin.webUrl + "/api/v1.0/metrics/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var health struct {
			Components map[string]struct {
				Status string `json:"status"`
			} `json:"components"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&health))

		// Sanity check that the report is populated at all, so that the
		// absences below mean something.
		require.NotEmpty(t, health.Components, "health report carried no components at all")

		// Each of these is recorded only by code that advertises to a director,
		// registers at a registry, or runs a director-initiated file transfer
		// test.  Their absence is the evidence that none of that code ran.
		for _, component := range []string{"director", "registry", "federation"} {
			assert.NotContains(t, health.Components, component,
				"a standalone origin must never record the %q health component", component)
		}
	})
}

// TestStandaloneOriginCliFederatedControl is the negative control for
// TestStandaloneOriginCliEndToEnd: the identical configuration with
// Origin.EnableStandaloneMode turned off must fail to start, because it has no
// Federation.DiscoveryUrl and there is no federation for it to find.
//
// Without this, "the standalone origin started" would be a weak claim -- it
// would be consistent with an origin that tolerates a missing federation for
// reasons having nothing to do with the feature under test.
func TestStandaloneOriginCliFederatedControl(t *testing.T) {
	cliPath := getPelicanBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	runtimeDir := filepath.Join(root, "runtime")
	storageDir := filepath.Join(root, "storage")
	issuerKeysDir := filepath.Join(configDir, "issuer-keys")
	for _, dir := range []string{configDir, runtimeDir, storageDir, issuerKeysDir} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}
	configPath := writeStandaloneConfig(t, configDir, runtimeDir, storageDir, issuerKeysDir, false)

	cmd := exec.CommandContext(ctx, cliPath, "origin", "serve", "--config", configPath)
	cmd.Env = pelicanEnv()

	var output bytes.Buffer
	var outputMu sync.Mutex
	cmd.Stdout = &lockedWriter{w: &output, mu: &outputMu}
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start())

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	select {
	case err := <-exited:
		outputMu.Lock()
		defer outputMu.Unlock()
		require.Error(t, err, "a federated origin with no discovery URL must not start; output:\n%s", output.String())
		assert.Contains(t, strings.ToLower(output.String()), strings.ToLower(param.Federation_DiscoveryUrl.GetName()),
			"expected the startup failure to name the missing federation configuration; output:\n%s", output.String())
	case <-time.After(120 * time.Second):
		outputMu.Lock()
		defer outputMu.Unlock()
		t.Fatalf("federated origin with no discovery URL neither started nor exited; output:\n%s", output.String())
	}
}
