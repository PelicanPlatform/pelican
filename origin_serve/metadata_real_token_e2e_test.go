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

// These e2e tests drive the origin's real WLCG token signer against the real,
// compiled sample_metadata_server binary launched as a subprocess. The binary
// binds an OS-assigned port (-addr 127.0.0.1:0) and reports its bound URL on
// stdout, which these tests parse — no port pre-reservation, no bind race.
// They are excluded on Windows to match the other subprocess-launching e2e
// suites (metrics_e2e_test.go, tpc_fed_test.go); the receiver's verification
// matrix is exercised directly by the cmd/sample_metadata_server tests.

package origin_serve

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// sampleServerListeningPrefix must match listeningLinePrefix in
// cmd/sample_metadata_server/main.go — it's the stdout contract the binary uses
// to report its OS-assigned port.
const sampleServerListeningPrefix = "SAMPLE_METADATA_SERVER_LISTENING "

// setupRealTokenIssuer generates the origin's issuer keys and stands up a
// plain-HTTP server publishing the OIDC discovery doc + JWKS exactly as a
// Pelican origin does, so the sample server can discover and verify the real
// token. Returns the issuer URL. Viper globals are saved/restored.
func setupRealTokenIssuer(t *testing.T) string {
	t.Helper()

	prevKeysDir := param.IssuerKeysDirectory.GetString()
	prevIssuerURL := param.Server_IssuerUrl.GetString()
	t.Cleanup(func() {
		_ = param.IssuerKeysDirectory.Set(prevKeysDir)
		_ = param.Server_IssuerUrl.Set(prevIssuerURL)
	})
	if err := param.IssuerKeysDirectory.Set(t.TempDir()); err != nil {
		t.Fatalf("set issuer keys dir: %v", err)
	}

	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/.well-known/issuer.jwks",
		})
	})
	mux.HandleFunc("/.well-known/issuer.jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks, err := config.GetIssuerPublicJWKS()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(jwks)
		_, _ = w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuerURL = srv.URL
	if err := param.Server_IssuerUrl.Set(issuerURL); err != nil {
		t.Fatalf("set issuer url: %v", err)
	}
	return issuerURL
}

// launchSampleServer builds and launches the real sample_metadata_server binary
// on an OS-assigned port and returns its base URL (parsed from the stdout
// readiness line the binary prints). The webhook endpoint is baseURL+"/events".
func launchSampleServer(t *testing.T, args ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sample_metadata_server")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/sample_metadata_server").CombinedOutput(); err != nil {
		t.Fatalf("build sample server: %v\n%s", err, out)
	}

	ctx, cancel := context.WithCancel(context.Background())
	full := append([]string{"-addr", "127.0.0.1:0", "-path", "/events"}, args...)
	cmd := exec.CommandContext(ctx, bin, full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sample server: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		reported := false
		for sc.Scan() {
			line := sc.Text()
			if !reported && strings.HasPrefix(line, sampleServerListeningPrefix) {
				reported = true
				urlCh <- strings.TrimSpace(strings.TrimPrefix(line, sampleServerListeningPrefix))
			}
		}
	}()
	select {
	case base := <-urlCh:
		return base
	case <-time.After(30 * time.Second):
		t.Fatal("sample server never reported its listening address")
		return ""
	}
}

// TestE2EEventual_RealTokenToSampleServer is the flagship end-to-end for the
// metadata publisher. It connects the two halves no other test joined:
//
//   - The ORIGIN mints a real WLCG token via the production signer
//     (config.GetIssuerPrivateJWK + token.NewWLCGToken); signToken is NOT
//     overridden. So the token carries the real issuer, the real
//     `pelican.metadata:/exp` scope, and a real signature.
//   - The RECEIVER is the actual compiled sample_metadata_server binary, which
//     discovers the origin's JWKS via OIDC and verifies the token before
//     accepting.
//
// It also reproduces the eventual-mode bug conditions: POSC on, a NON-root
// export (/exp), a real webdav.Handler that strips its Prefix, and the worker's
// FilesystemForExists existence check. A drained queue means the real token
// verified AND the object published through the standalone path.
func TestE2EEventual_RealTokenToSampleServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary, generates real keys")
	}

	setupRealTokenIssuer(t)
	// No -audience: the origin signs aud == its endpoint, which isn't known
	// until the OS assigns the port; the audience-match path is covered against
	// the binary in cmd/sample_metadata_server. Here we verify signature+scope
	// through the full publish path.
	endpoint := launchSampleServer(t, "-require-namespace-scope") + "/events"

	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	inner := newAferoFileSystem(autoFs, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer posc.Stop()

	const fedPrefix = "/exp"
	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: endpoint,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     20 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		MaxInflight:    2,
		RatePerSecond:  1000,
		FilesystemForExists: func(namespace string) webdav.FileSystem {
			if namespace == fedPrefix {
				return posc
			}
			return nil
		},
	})
	defer ctl.Stop()
	// signToken deliberately NOT overridden — the real WLCG signer runs.
	posc.SetCloseHook(ctl.CommitEventFromCloseHook(fedPrefix))
	ctl.Start(ctx)

	originSrv := newOriginPUTServer(t, posc, fedPrefix)
	defer originSrv.Close()

	putObject(t, originSrv.URL+"/exp/data/run.dat", "real-token-payload", nil)

	// The queue drains iff the sample server accepted the real token.
	requireQueueDrains(t, ctl, 20*time.Second)
}

// TestE2ETransactional_RealTokenToSampleServer exercises the transactional
// close path with a real token: the publish happens inline on the request
// goroutine and its result gates the PUT's HTTP status. The happy subtest
// asserts a verified token yields 2xx + a committed object; the rollback
// subtest configures the receiver with a mismatched audience so the real token
// is rejected (401), the transactional close fails, and POSC rolls the object
// back — the "publish failed → 5xx → object removed" contract.
func TestE2ETransactional_RealTokenToSampleServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary, generates real keys")
	}

	t.Run("happy_path_verified_token", func(t *testing.T) {
		setupRealTokenIssuer(t)
		endpoint := launchSampleServer(t, "-require-namespace-scope") + "/events"

		mem, _, ctl, srv := newTransactionalStack(t, endpoint)
		defer srv.Close()

		putObject(t, srv.URL+"/exp/data/ok.dat", "committed", nil)

		// The webdav.Handler strips its /exp Prefix, so the committed object
		// lands at the export-relative path in the backing FS.
		if _, err := mem.Stat("/data/ok.dat"); err != nil {
			t.Fatalf("object should be committed after a verified transactional publish: %v", err)
		}
		requireQueueEmpty(t, ctl)
	})

	t.Run("rollback_on_auth_failure", func(t *testing.T) {
		setupRealTokenIssuer(t)
		// Receiver expects a DIFFERENT audience than the token carries, so a
		// perfectly-signed real token is rejected with 401.
		endpoint := launchSampleServer(t, "-require-namespace-scope",
			"-audience", "https://definitely-not-the-endpoint.example/events") + "/events"

		mem, _, ctl, srv := newTransactionalStack(t, endpoint)
		defer srv.Close()

		status := putObjectExpectingFailure(t, srv.URL+"/exp/data/bad.dat", "rolled-back")
		if status/100 == 2 {
			t.Fatalf("PUT should have failed when the receiver rejects the token, got %d", status)
		}
		// Export-relative path (webdav strips /exp). POSC's rollback should have
		// removed the just-committed object.
		if _, err := mem.Stat("/data/bad.dat"); err == nil {
			t.Fatal("object should have been rolled back after a transactional auth failure")
		}
		requireQueueEmpty(t, ctl)
	})
}

// newTransactionalStack builds a POSC + real-signer transactional controller
// over an in-memory FS and a real webdav.Handler front end.
func newTransactionalStack(t *testing.T, endpoint string) (afero.Fs, *poscFileSystem, *metadataController, *httptest.Server) {
	t.Helper()
	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	inner := newAferoFileSystem(autoFs, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	t.Cleanup(posc.Stop)

	const fedPrefix = "/exp"
	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: endpoint,
		OriginMode:     ModeTransactional,
		DB:             db,
		RequestTimeout: 5 * time.Second,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	t.Cleanup(ctl.Stop)
	posc.SetCloseHook(ctl.CommitEventFromCloseHook(fedPrefix))

	srv := newOriginPUTServer(t, posc, fedPrefix)
	return mem, posc, ctl, srv
}

// --- shared helpers ---

// newOriginPUTServer wraps a POSC filesystem behind a real webdav.Handler
// (Prefix = fedPrefix, i.e. production-style prefix stripping) and a tiny mux
// that stamps a fake authenticated user + the object-metadata middleware.
func newOriginPUTServer(t *testing.T, fs webdav.FileSystem, fedPrefix string) *httptest.Server {
	t.Helper()
	dav := &webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
		Prefix:     fedPrefix,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rctx := setUserInfo(r.Context(), &userInfo{User: "alice"})
		r = r.WithContext(rctx)
		r = extractObjectMetadataFromRequest(r)
		dav.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	return srv
}

// putObject PUTs body to url and fails the test if the status is not 2xx.
func putObject(t *testing.T, url, body string, headers map[string]string) {
	t.Helper()
	if status := doPut(t, url, body, headers); status/100 != 2 {
		t.Fatalf("PUT %s returned %d, want 2xx", url, status)
	}
}

// putObjectExpectingFailure PUTs and returns the status without asserting.
func putObjectExpectingFailure(t *testing.T, url, body string) int {
	t.Helper()
	return doPut(t, url, body, nil)
}

func doPut(t *testing.T, url, body string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = int64(len(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func requireQueueDrains(t *testing.T, ctl *metadataController, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		var count int64
		if err := ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count).Error; err != nil {
			t.Fatalf("count queue: %v", err)
		}
		if count == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("queue never drained — the sample server likely rejected the token or the row was dropped")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func requireQueueEmpty(t *testing.T, ctl *metadataController) {
	t.Helper()
	var count int64
	ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
	if count != 0 {
		t.Fatalf("queue should be empty, got %d rows", count)
	}
}
