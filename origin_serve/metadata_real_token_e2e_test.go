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

package origin_serve

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
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

// realTokenIssuer bundles the pieces a real-token e2e needs: the origin's
// issuer URL (also configured as Server.IssuerUrl so the production signer
// stamps it) and the PEM path of the HTTPS issuer's CA, which the receiver
// must be told to trust via -ca.
type realTokenIssuer struct {
	url    string
	caPath string
	server *httptest.Server
}

// setupRealTokenIssuer generates the origin's issuer keys and stands up an
// HTTPS server publishing the OIDC discovery doc + JWKS exactly as a Pelican
// origin does. Because the server is TLS with a self-signed cert, the CA PEM
// is written to disk and returned so the sample server can trust it with -ca
// (no "skip verification" anywhere). Viper globals are saved/restored.
func setupRealTokenIssuer(t *testing.T) *realTokenIssuer {
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

	ri := &realTokenIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   ri.url,
			"jwks_uri": ri.url + "/.well-known/issuer.jwks",
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

	// HTTPS issuer: this is what exercises the sample server's -ca path.
	ri.server = httptest.NewTLSServer(mux)
	t.Cleanup(ri.server.Close)
	ri.url = ri.server.URL
	if err := param.Server_IssuerUrl.Set(ri.url); err != nil {
		t.Fatalf("set issuer url: %v", err)
	}

	// Persist the issuer's self-signed cert so the receiver can trust it.
	cert := ri.server.Certificate()
	ri.caPath = filepath.Join(t.TempDir(), "issuer-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(ri.caPath, pemBytes, 0600); err != nil {
		t.Fatalf("write issuer CA: %v", err)
	}
	return ri
}

// TestE2EEventual_RealTokenToSampleServer is the flagship end-to-end for the
// metadata publisher. It connects the two halves no other test joined:
//
//   - The ORIGIN mints a real WLCG token via the production signer
//     (config.GetIssuerPrivateJWK + token.NewWLCGToken); signToken is NOT
//     overridden. So the token carries the real issuer, the real
//     `pelican.metadata:/exp` scope, the endpoint audience, and a real
//     signature.
//   - The RECEIVER is the actual compiled sample_metadata_server binary,
//     which discovers the origin's JWKS over HTTPS (trusting the issuer CA via
//     -ca) and verifies the token before accepting.
//
// It also reproduces the eventual-mode bug conditions: POSC on, a NON-root
// export (/exp), a real webdav.Handler that strips its Prefix, and the
// worker's FilesystemForExists existence check. A drained queue means the
// real token verified AND the object published through the standalone path.
func TestE2EEventual_RealTokenToSampleServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary, generates real keys")
	}

	issuer := setupRealTokenIssuer(t)
	// audience must equal the endpoint the origin posts to; the receiver
	// derives it from the port it binds, so launch first then reuse.
	port := reserveFreePortForE2E(t)
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/events", port)
	launchReceiverOnPort(t, port, endpoint, issuer.caPath)

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
// subtest points the receiver at a mismatched audience so the real token is
// rejected (401), the transactional close fails, and POSC rolls the object
// back — the "publish failed → 5xx → object removed" contract.
func TestE2ETransactional_RealTokenToSampleServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary, generates real keys")
	}

	t.Run("happy_path_verified_token", func(t *testing.T) {
		issuer := setupRealTokenIssuer(t)
		port := reserveFreePortForE2E(t)
		endpoint := fmt.Sprintf("http://127.0.0.1:%d/events", port)
		// Receiver's expected audience == endpoint → real token's aud matches.
		launchReceiverOnPort(t, port, endpoint, issuer.caPath)

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
		issuer := setupRealTokenIssuer(t)
		port := reserveFreePortForE2E(t)
		endpoint := fmt.Sprintf("http://127.0.0.1:%d/events", port)
		// Receiver expects a DIFFERENT audience than the token carries, so a
		// perfectly-signed real token is rejected with 401.
		wrongAudience := fmt.Sprintf("http://127.0.0.1:%d/not-the-endpoint", port)
		launchReceiverOnPort(t, port, wrongAudience, issuer.caPath)

		mem, _, ctl, srv := newTransactionalStack(t, endpoint)
		defer srv.Close()

		status := putObjectExpectingFailure(t, srv.URL+"/exp/data/bad.dat", "rolled-back")
		if status/100 == 2 {
			t.Fatalf("PUT should have failed when the receiver rejects the token, got %d", status)
		}
		// Export-relative path (webdav strips /exp). POSC's rollback should
		// have removed the just-committed object.
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

// launchReceiverOnPort is launchReceiver with a caller-chosen port (so the
// audience can be computed before the process starts).
func launchReceiverOnPort(t *testing.T, port int, audience, caPath string) {
	t.Helper()
	bin := buildSampleServerBinary(t)
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-path", "/events",
		"-audience", audience,
		"-require-namespace-scope",
	}
	if caPath != "" {
		args = append(args, "-ca", caPath)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sample server: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	waitForHealthzE2E(t, fmt.Sprintf("http://127.0.0.1:%d", port))
}

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
			t.Fatalf("queue never drained — the receiver likely rejected the token (see its log above) or the row was dropped")
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

// buildSampleServerBinary compiles cmd/sample_metadata_server into a temp
// binary for use as a subprocess receiver.
func buildSampleServerBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sample_metadata_server")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", bin, "../cmd/sample_metadata_server").CombinedOutput()
	if err != nil {
		t.Fatalf("build sample server: %v\n%s", err, out)
	}
	return bin
}

func reserveFreePortForE2E(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitForHealthzE2E(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sample server never became healthy")
}
