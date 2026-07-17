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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
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

// TestIntegration_SampleServerVerifiesToken builds the sample_metadata_server
// binary, launches it as a real process, and drives it with webhook POSTs
// that carry real origin-style JWTs. A fake issuer (httptest) publishes the
// OIDC discovery doc + JWKS the same way a Pelican origin does, so the
// server's discover→fetch→verify path runs end-to-end.
//
// This is the integration test that "wires" the deliverable: it exercises
// the actual compiled binary and its flag surface, not just the in-package
// helpers.
func TestIntegration_SampleServerVerifiesToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds and launches a binary")
	}

	// --- Fake origin issuer: publishes discovery + JWKS. ---
	privKey, pubSet := genES256Keypair(t, "origin-key")
	// A second key that is NOT published — tokens signed with it must be
	// rejected.
	untrustedKey, _ := genES256Keypair(t, "attacker-key")

	pubJSON, err := json.Marshal(pubSet)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	var issuerURL string
	// HTTPS issuer so the sample server's JWKS fetch runs over TLS and its
	// -ca trust path is exercised (there is no skip-verification flag).
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

	// --- Launch the sample server binary. ---
	bin := buildSampleServer(t)
	port := reserveFreePort(t)
	receiverBase := fmt.Sprintf("http://127.0.0.1:%d", port)
	audience := receiverBase + "/events"

	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-path", "/events",
		"-audience", audience,
		"-require-namespace-scope",
		"-clock-skew", "2m",
		"-ca", caPath,
	)
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sample server: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("sample server output:\n%s", logs.String())
		}
	})
	waitForHealthz(t, receiverBase)

	now := time.Now()
	validToken := func(scopes []string, aud string) string {
		return mintToken(t, privKey, jwa.ES256, issuerURL, aud, scopes, now)
	}

	tests := []struct {
		name       string
		authHeader string
		body       string
		wantStatus int
	}{
		{
			name:       "valid token, namespaced scope covers event ns",
			authHeader: "Bearer " + validToken([]string{"storage.read", "pelican.metadata:/exp"}, audience),
			body:       `{"id":"e1","type":"object.committed","namespace":"/exp","object":{"path":"/exp/data/x.dat","size":3}}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing Authorization header",
			authHeader: "",
			body:       `{"id":"e2","namespace":"/exp","object":{"path":"/exp/y.dat"}}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token minted for a different audience",
			authHeader: "Bearer " + validToken([]string{"pelican.metadata:/exp"}, "https://someone-else.example/hook"),
			body:       `{"id":"e3","namespace":"/exp","object":{"path":"/exp/z.dat"}}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token signed by an unpublished (untrusted) key",
			authHeader: "Bearer " + mintToken(t, untrustedKey, jwa.ES256, issuerURL, audience, []string{"pelican.metadata:/exp"}, now),
			body:       `{"id":"e4","namespace":"/exp","object":{"path":"/exp/w.dat"}}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid signature but scope path covers a different namespace",
			authHeader: "Bearer " + validToken([]string{"pelican.metadata:/other"}, audience),
			body:       `{"id":"e5","namespace":"/exp","object":{"path":"/exp/v.dat"}}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid signature but no metadata scope at all",
			authHeader: "Bearer " + validToken([]string{"storage.read:/exp"}, audience),
			body:       `{"id":"e6","namespace":"/exp","object":{"path":"/exp/u.dat"}}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "expired token",
			authHeader: "Bearer " + mintToken(t, privKey, jwa.ES256, issuerURL, audience, []string{"pelican.metadata:/exp"}, now.Add(-1*time.Hour)),
			body:       `{"id":"e7","namespace":"/exp","object":{"path":"/exp/t.dat"}}`,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := postEvent(t, audience, tc.authHeader, "application/json", []byte(tc.body))
			if status != tc.wantStatus {
				t.Fatalf("POST returned %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

// syncBuffer is a goroutine-safe io.Writer for capturing subprocess output.
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

// writeIssuerCA persists the httptest TLS server's self-signed certificate to
// a PEM file so the launched sample server can trust it via -ca.
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

// buildSampleServer compiles the current package into a temp binary.
func buildSampleServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sample_metadata_server")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// reserveFreePort grabs an ephemeral port and releases it so the child can
// bind it. The brief window between release and re-bind is acceptable for a
// test.
func reserveFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// waitForHealthz polls the receiver's /healthz until it responds or times out.
func waitForHealthz(t *testing.T, base string) {
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

// genES256Keypair returns a private jwk.Key (for signing) and a JWKS holding
// only the corresponding public key (for verification).
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

// mintToken builds and signs a JWT shaped like the one the origin's
// metadata publisher emits: issuer/subject = origin issuer, aud = receiver,
// a space-delimited scope claim, and a jti.
func mintToken(t *testing.T, key jwk.Key, alg jwa.SignatureAlgorithm, issuer, audience string, scopes []string, iat time.Time) string {
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
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// postEvent POSTs a webhook body and returns the HTTP status code.
func postEvent(t *testing.T, url, authHeader, contentType string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
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
