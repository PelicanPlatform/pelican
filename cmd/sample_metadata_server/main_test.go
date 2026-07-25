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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"not-bearer", "Basic abc", "", true},
		{"bearer-empty", "Bearer   ", "", true},
		{"ok", "Bearer abc.def.ghi", "abc.def.ghi", false},
		{"case-insensitive-scheme", "bearer abc.def.ghi", "abc.def.ghi", false},
		{"no-space", "Bearerabc", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bearerToken(tc.header)
			if (err != nil) != tc.wantErr {
				t.Fatalf("bearerToken(%q) err=%v, wantErr=%v", tc.header, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestSplitScope(t *testing.T) {
	tests := []struct {
		in        string
		authority string
		path      string
	}{
		{"pelican.metadata", "pelican.metadata", ""},
		{"pelican.metadata:/foo", "pelican.metadata", "/foo"},
		{"storage.read:/a/b", "storage.read", "/a/b"},
		{"weird:", "weird", ""},
	}
	for _, tc := range tests {
		a, p := splitScope(tc.in)
		if a != tc.authority || p != tc.path {
			t.Fatalf("splitScope(%q) = (%q,%q), want (%q,%q)", tc.in, a, p, tc.authority, tc.path)
		}
	}
}

func TestPathCovers(t *testing.T) {
	tests := []struct {
		scope  string
		target string
		want   bool
	}{
		{"/", "/anything", true},
		{"/foo", "/foo", true},
		{"/foo", "/foo/bar", true},
		{"/foo", "/foobar", false}, // prefix must be path-segment aligned
		{"/foo", "/bar", false},
		{"/foo/bar", "/foo", false}, // narrower scope does not cover parent
		{"foo", "/foo/x", true},     // tolerant of missing leading slash
	}
	for _, tc := range tests {
		if got := pathCovers(tc.scope, tc.target); got != tc.want {
			t.Fatalf("pathCovers(%q, %q) = %v, want %v", tc.scope, tc.target, got, tc.want)
		}
	}
}

func TestCheckScope(t *testing.T) {
	tests := []struct {
		name             string
		scopes           []string
		ns               string
		requireNamespace bool
		wantErr          bool
	}{
		{"bare metadata scope, no ns requirement", []string{"storage.read", "pelican.metadata"}, "/exp", false, false},
		{"no metadata scope at all", []string{"storage.read:/exp"}, "/exp", false, true},
		{"namespaced scope covers event ns", []string{"pelican.metadata:/exp"}, "/exp/data/x.dat", true, false},
		{"namespaced scope does NOT cover event ns", []string{"pelican.metadata:/other"}, "/exp", true, true},
		{"bare scope insufficient when ns required", []string{"pelican.metadata"}, "/exp", true, true},
		{"sibling namespace is not covered", []string{"pelican.metadata:/exp"}, "/experiment", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkScope(tc.scopes, tc.ns, tc.requireNamespace)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkScope(%v, %q, %v) err=%v, wantErr=%v", tc.scopes, tc.ns, tc.requireNamespace, err, tc.wantErr)
			}
		})
	}
}

func TestParseBody_JSON(t *testing.T) {
	body := []byte(`{"id":"e1","type":"object.committed","namespace":"/exp","object":{"path":"/exp/x.dat","size":3}}`)
	ev, blob, err := parseBody("application/json", body)
	if err != nil {
		t.Fatalf("parseBody: %v", err)
	}
	if ev.ID != "e1" || ev.Namespace != "/exp" || ev.Object["path"] != "/exp/x.dat" {
		t.Fatalf("event = %+v", ev)
	}
	if blob != "" {
		t.Fatalf("expected no blob info for plain JSON, got %q", blob)
	}
}

func TestParseBody_MultipartRelated(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	rootHeader := textproto.MIMEHeader{}
	rootHeader.Set("Content-ID", "<event>")
	rootHeader.Set("Content-Type", "application/json")
	rootPart, err := mw.CreatePart(rootHeader)
	if err != nil {
		t.Fatalf("create root part: %v", err)
	}
	_, _ = rootPart.Write([]byte(`{"id":"e2","type":"object.committed","namespace":"/exp","object":{"path":"/exp/run.dat"}}`))
	blobHeader := textproto.MIMEHeader{}
	blobHeader.Set("Content-ID", "<metadata>")
	blobHeader.Set("Content-Type", "application/xml")
	blobPart, err := mw.CreatePart(blobHeader)
	if err != nil {
		t.Fatalf("create blob part: %v", err)
	}
	_, _ = blobPart.Write([]byte(`<datasetSummary><experiment>atlas</experiment></datasetSummary>`))
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	contentType := "multipart/related; boundary=" + mw.Boundary() + `; type="application/json"; start="<event>"`
	ev, blob, err := parseBody(contentType, buf.Bytes())
	if err != nil {
		t.Fatalf("parseBody: %v", err)
	}
	if ev.ID != "e2" || ev.Namespace != "/exp" {
		t.Fatalf("event = %+v", ev)
	}
	if blob == "" {
		t.Fatalf("expected blob info for multipart body, got empty")
	}
}

func TestParseBody_MultipartMissingRoot(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "application/xml")
	part, _ := mw.CreatePart(h)
	_, _ = part.Write([]byte(`<x/>`))
	_ = mw.Close()
	contentType := "multipart/related; boundary=" + mw.Boundary()
	if _, _, err := parseBody(contentType, buf.Bytes()); err == nil {
		t.Fatal("expected error for multipart body with no JSON root part")
	}
}

func TestCanonicalFederation(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"osg-htc.org", "https://osg-htc.org"},
		{"https://osg-htc.org", "https://osg-htc.org"},
		{"https://OSG-HTC.org/", "https://osg-htc.org"},
		{"https://osg-htc.org:443", "https://osg-htc.org"},
		{"http://localhost:80", "http://localhost"},
		{"http://127.0.0.1:9999", "http://127.0.0.1:9999"},
	}
	for _, tc := range tests {
		if got := canonicalFederation(tc.in); got != tc.want {
			t.Fatalf("canonicalFederation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNamespaceJWKSURL(t *testing.T) {
	got, err := namespaceJWKSURL("https://reg.example.org", "/foo/bar")
	if err != nil {
		t.Fatalf("namespaceJWKSURL: %v", err)
	}
	want := "https://reg.example.org/api/v1.0/registry/foo/bar/.well-known/issuer.jwks"
	if got != want {
		t.Fatalf("namespaceJWKSURL = %q, want %q", got, want)
	}
}

// TestVerify_RegistryDiscovery exercises the full registry-based verification
// path: a mock federation-discovery + registry serves the namespace's public
// JWKS, and a token signed with the matching private key verifies. It also
// pins the federation and asserts a mismatched-federation event is rejected.
func TestVerify_RegistryDiscovery(t *testing.T) {
	// Signing key (private) + its public JWKS, as the registry would serve it.
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	priv, err := jwk.FromRaw(rawKey)
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	_ = priv.Set(jwk.KeyIDKey, "test-key-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	pubSet := jwk.NewSet()
	_ = pubSet.AddKey(pub)

	// Mock federation discovery + registry (same server plays both roles).
	var registryURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/pelican-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"namespace_registration_endpoint": registryURL})
	})
	mux.HandleFunc("/api/v1.0/registry/foo/.well-known/issuer.jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(pubSet)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	registryURL = srv.URL
	federation := srv.URL
	const audience = "https://receiver.example/events"

	signToken := func(scope string, aud string, lifetime time.Duration) string {
		tok, err := jwt.NewBuilder().
			Issuer("https://origin.example").
			Subject("https://origin.example").
			Audience([]string{aud}).
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(lifetime)).
			Claim("scope", scope).
			Build()
		if err != nil {
			t.Fatalf("build token: %v", err)
		}
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return "Bearer " + string(signed)
	}

	v := newVerifier(srv.Client())
	ctx := context.Background()

	t.Run("verifies against registry keys (pinned)", func(t *testing.T) {
		claims, err := v.verify(ctx, signToken("pelican.metadata:/foo", audience, 5*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			eventFederation:   federation,
			namespace:         "/foo",
			audience:          audience,
			skew:              time.Minute,
		})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if err := checkScope(claims.scopes, "/foo/data/x.dat", true); err != nil {
			t.Fatalf("scope check: %v", err)
		}
	})

	t.Run("rejects event that claims a different federation than the pin", func(t *testing.T) {
		_, err := v.verify(ctx, signToken("pelican.metadata:/foo", audience, 5*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			eventFederation:   "https://evil.example",
			namespace:         "/foo",
			audience:          audience,
			skew:              time.Minute,
		})
		if err == nil {
			t.Fatal("expected rejection for federation mismatch, got nil")
		}
	})

	t.Run("rejects wrong audience", func(t *testing.T) {
		_, err := v.verify(ctx, signToken("pelican.metadata:/foo", "https://someone-else/", 5*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			eventFederation:   federation,
			namespace:         "/foo",
			audience:          audience,
			skew:              time.Minute,
		})
		if err == nil {
			t.Fatal("expected rejection for wrong audience, got nil")
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		_, err := v.verify(ctx, signToken("pelican.metadata:/foo", audience, -1*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			eventFederation:   federation,
			namespace:         "/foo",
			audience:          audience,
			skew:              time.Second,
		})
		if err == nil {
			t.Fatal("expected rejection for expired token, got nil")
		}
	})

	t.Run("rejects namespace path traversal", func(t *testing.T) {
		_, err := v.verify(ctx, signToken("pelican.metadata:/foo", audience, 5*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			eventFederation:   federation,
			namespace:         "/foo/../secrets",
			audience:          audience,
			skew:              time.Minute,
		})
		if err == nil {
			t.Fatal("expected rejection for namespace traversal, got nil")
		}
	})

	t.Run("rejects when event has no federation and no -issuer is configured", func(t *testing.T) {
		_, err := v.verify(ctx, signToken("pelican.metadata:/foo", audience, 5*time.Minute), verifyRequest{
			trustedFederation: canonicalFederation(federation),
			// eventFederation empty and trustedIssuer empty => no trusted source.
			namespace: "/foo",
			audience:  audience,
			skew:      time.Minute,
		})
		if err == nil {
			t.Fatal("expected rejection when no trusted key source applies, got nil")
		}
	})
}

func TestValidateNamespace(t *testing.T) {
	ok := []string{"/foo", "/foo/bar", "/a/b/c.dat"}
	for _, ns := range ok {
		if got, err := validateNamespace(ns); err != nil || got != ns {
			t.Fatalf("validateNamespace(%q) = (%q,%v), want (%q,nil)", ns, got, err, ns)
		}
	}
	bad := []string{"", "foo", "/foo/../bar", "https://evil/foo", "/foo bar", "/foo\nbar"}
	for _, ns := range bad {
		if _, err := validateNamespace(ns); err == nil {
			t.Fatalf("validateNamespace(%q) = nil error, want rejection", ns)
		}
	}
}
