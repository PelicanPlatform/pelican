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

// This test builds and launches the real sample_metadata_server binary as a
// subprocess — the point is to exercise the actual standalone binary, not an
// in-process handler. The server binds an OS-assigned port (:0) and reports the
// bound URL on stdout, which this test parses (no reserve-then-rebind race). It
// is excluded on Windows to match the other subprocess-launching e2e suites;
// the pure-function tests in main_test.go run on every platform.

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestIntegration_SampleServerVerifiesToken builds and launches the real
// binary and drives it with webhook POSTs carrying real origin-style JWTs. A
// fake issuer (httptest, HTTPS so the -ca trust path is exercised) publishes
// the OIDC discovery doc + JWKS, and tokens are minted with jwx. The audience
// is a fixed configured string (independent of the OS-assigned port), so the
// binary can be launched with -audience before its port is known.
func TestIntegration_SampleServerVerifiesToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary")
	}

	privKey, pubSet := genES256Keypair(t, "origin-key")
	untrustedKey, _ := genES256Keypair(t, "attacker-key")
	pubJSON, err := json.Marshal(pubSet)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	var issuerURL string
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   issuerURL,
				"jwks_uri": issuerURL + "/.well-known/issuer.jwks",
			})
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(pubJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	issuerURL = issuer.URL
	caPath := writeIssuerCA(t, issuer)

	// The audience the receiver expects is a fixed string, independent of the
	// bound port, so it can be passed on the command line before launch.
	const audience = "https://receiver.test.example/events"
	baseURL := launchServer(t, "-path", "/events", "-audience", audience,
		"-require-namespace-scope", "-ca", caPath)
	endpoint := baseURL + "/events"

	now := time.Now()
	valid := func(scopes []string, aud string) string {
		return mintToken(t, privKey, issuerURL, aud, scopes, now)
	}

	tests := []struct {
		name       string
		authHeader string
		body       string
		wantStatus int
	}{
		{"valid token, namespaced scope covers event ns",
			"Bearer " + valid([]string{"storage.read", "pelican.metadata:/exp"}, audience),
			`{"id":"e1","type":"object.committed","namespace":"/exp","object":{"path":"/exp/data/x.dat","size":3}}`,
			http.StatusOK},
		{"missing Authorization header", "",
			`{"id":"e2","namespace":"/exp","object":{"path":"/exp/y.dat"}}`, http.StatusUnauthorized},
		{"token minted for a different audience",
			"Bearer " + valid([]string{"pelican.metadata:/exp"}, "https://someone-else.example/hook"),
			`{"id":"e3","namespace":"/exp","object":{"path":"/exp/z.dat"}}`, http.StatusUnauthorized},
		{"token signed by an unpublished (untrusted) key",
			"Bearer " + mintToken(t, untrustedKey, issuerURL, audience, []string{"pelican.metadata:/exp"}, now),
			`{"id":"e4","namespace":"/exp","object":{"path":"/exp/w.dat"}}`, http.StatusUnauthorized},
		{"valid signature but scope path covers a different namespace",
			"Bearer " + valid([]string{"pelican.metadata:/other"}, audience),
			`{"id":"e5","namespace":"/exp","object":{"path":"/exp/v.dat"}}`, http.StatusForbidden},
		{"valid signature but no metadata scope at all",
			"Bearer " + valid([]string{"storage.read:/exp"}, audience),
			`{"id":"e6","namespace":"/exp","object":{"path":"/exp/u.dat"}}`, http.StatusForbidden},
		{"expired token",
			"Bearer " + mintToken(t, privKey, issuerURL, audience, []string{"pelican.metadata:/exp"}, now.Add(-1*time.Hour)),
			`{"id":"e7","namespace":"/exp","object":{"path":"/exp/t.dat"}}`, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if status := postEvent(t, endpoint, tc.authHeader, []byte(tc.body)); status != tc.wantStatus {
				t.Fatalf("POST returned %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

// syncBuffer is a goroutine-safe buffer for capturing subprocess output.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// launchServer builds the binary and starts it with -addr 127.0.0.1:0 plus the
// given args. It parses the OS-assigned bound URL from the server's stdout
// (the listeningLinePrefix line) — no port pre-reservation, so no bind race.
func launchServer(t *testing.T, args ...string) (baseURL string) {
	t.Helper()
	bin := buildSampleServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	full := append([]string{"-addr", "127.0.0.1:0"}, args...)
	cmd := exec.CommandContext(ctx, bin, full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("stdout pipe: %v", err)
	}
	logs := &syncBuffer{}
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("server stderr:\n%s", logs.String())
		}
	})

	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		reported := false
		for sc.Scan() {
			line := sc.Text()
			if !reported && strings.HasPrefix(line, listeningLinePrefix) {
				reported = true
				urlCh <- strings.TrimSpace(strings.TrimPrefix(line, listeningLinePrefix))
			}
		}
	}()

	select {
	case baseURL = <-urlCh:
		return baseURL
	case <-time.After(30 * time.Second):
		t.Fatalf("server never reported its listening address; stderr:\n%s", logs.String())
		return ""
	}
}

// buildSampleServer compiles the current package into a temp binary.
func buildSampleServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sample_metadata_server")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// writeIssuerCA persists the httptest TLS server's self-signed certificate to a
// PEM file so the launched server can trust it via -ca.
func writeIssuerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write issuer CA: %v", err)
	}
	return path
}

func genES256Keypair(t *testing.T, kid string) (jwk.Key, jwk.Set) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}
	return priv, set
}

func mintToken(t *testing.T, key jwk.Key, issuer, audience string, scopes []string, iat time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(issuer).
		Audience([]string{audience}).
		IssuedAt(iat).
		NotBefore(iat).
		Expiration(iat.Add(5*time.Minute)).
		JwtID("evt-"+strings.ReplaceAll(scopes[0], "/", "_")).
		Claim("scope", strings.Join(scopes, " ")).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func postEvent(t *testing.T, url, authHeader string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	return resp.StatusCode
}
