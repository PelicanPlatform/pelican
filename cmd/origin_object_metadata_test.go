//go:build server

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

// File origin_object_metadata_test.go is a CLI smoke test for
// `pelican origin object-metadata {list|get|history}`. It spins up
// an httptest.Server that captures every request, points the CLI at
// it via --server, and asserts the resulting HTTP request shape
// (URL path, query params, Authorization header).
//
// We deliberately do NOT exercise the federation / token-issuer
// machinery — that's covered by the in-process integration tests.
// This file's job is to lock down the wire format so a typo in URL
// construction or query encoding gets caught at unit-test speed.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// capturedRequest is what the mock receiver records per call.
type capturedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
}

// newObjectMetadataMockServer returns an httptest.Server that
// records every request it sees and returns an empty JSON object.
// Hand the URL to the CLI via --server; the recorded slice receives
// one entry per CLI invocation.
func newObjectMetadataMockServer(t *testing.T) (*httptest.Server, *[]capturedRequest, *sync.Mutex) {
	t.Helper()
	mu := &sync.Mutex{}
	recs := &[]capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*recs = append(*recs, capturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}})
	}))
	t.Cleanup(srv.Close)
	return srv, recs, mu
}

// writeFakeAdminTokenFile drops a non-JWT placeholder string into a
// tempfile. fetchOrGenerateWebAPIAdminToken reads token files as
// opaque text, so any non-empty value works.
func writeFakeAdminTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("fake-admin-token-for-test"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// runCLI invokes a single rootCmd invocation under SetArgs. It
// restores the test-process state on completion so subsequent tests
// see a clean rootCmd.
func runCLI(t *testing.T, args []string) {
	t.Helper()
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute(%v): %v", args, err)
	}
}

// resetSharedDowntimeFlags zeroes the package-level vars shared
// between the downtime and object-metadata subtrees. Without this,
// a leftover --server from a prior subtest leaks into the next.
func resetSharedDowntimeFlags() {
	serverURLStr = ""
	tokenLocation = ""
}

func TestOriginObjectMetadataCLI_List(t *testing.T) {
	defer resetSharedDowntimeFlags()
	srv, recs, mu := newObjectMetadataMockServer(t)
	tok := writeFakeAdminTokenFile(t)

	runCLI(t, []string{
		"origin", "object-metadata", "list",
		"--server", srv.URL,
		"--token", tok,
		"--namespace", "/exp",
		"--limit", "25",
		"--offset", "5",
	})

	mu.Lock()
	defer mu.Unlock()
	if len(*recs) != 1 {
		t.Fatalf("got %d requests, want 1", len(*recs))
	}
	r := (*recs)[0]
	if r.Method != http.MethodGet {
		t.Fatalf("method = %q, want GET", r.Method)
	}
	if r.Path != "/api/v1.0/origin_ui/object_metadata" {
		t.Fatalf("path = %q", r.Path)
	}
	if got := r.Query.Get("namespace"); got != "/exp" {
		t.Fatalf("namespace param = %q", got)
	}
	if got := r.Query.Get("limit"); got != "25" {
		t.Fatalf("limit param = %q", got)
	}
	if got := r.Query.Get("offset"); got != "5" {
		t.Fatalf("offset param = %q", got)
	}
	if auth := r.Header.Get("Authorization"); auth != "Bearer fake-admin-token-for-test" {
		t.Fatalf("Authorization = %q", auth)
	}
}

func TestOriginObjectMetadataCLI_Get(t *testing.T) {
	defer resetSharedDowntimeFlags()
	srv, recs, mu := newObjectMetadataMockServer(t)
	tok := writeFakeAdminTokenFile(t)

	runCLI(t, []string{
		"origin", "object-metadata", "get",
		"--server", srv.URL,
		"--token", tok,
		"--namespace", "/exp",
		"--path", "/exp/data/x.bin",
		"--history", "10",
	})

	mu.Lock()
	defer mu.Unlock()
	if len(*recs) != 1 {
		t.Fatalf("got %d requests, want 1", len(*recs))
	}
	r := (*recs)[0]
	if r.Path != "/api/v1.0/origin_ui/object_metadata/lookup" {
		t.Fatalf("path = %q (want /lookup)", r.Path)
	}
	if got := r.Query.Get("path"); got != "/exp/data/x.bin" {
		t.Fatalf("path param = %q", got)
	}
	if got := r.Query.Get("history"); got != "10" {
		t.Fatalf("history param = %q", got)
	}
}

func TestOriginObjectMetadataCLI_History(t *testing.T) {
	defer resetSharedDowntimeFlags()
	srv, recs, mu := newObjectMetadataMockServer(t)
	tok := writeFakeAdminTokenFile(t)

	runCLI(t, []string{
		"origin", "object-metadata", "history",
		"--server", srv.URL,
		"--token", tok,
		"--namespace", "/exp",
		"--path", "/exp/data/x.bin",
		"--limit", "42",
	})

	mu.Lock()
	defer mu.Unlock()
	r := (*recs)[0]
	if r.Path != "/api/v1.0/origin_ui/object_metadata/history" {
		t.Fatalf("path = %q (want /history)", r.Path)
	}
	if got := r.Query.Get("limit"); got != "42" {
		t.Fatalf("limit param = %q", got)
	}
}

// TestOriginObjectMetadataCLI_LoginCookieSet verifies the login
// cookie is set alongside the Authorization header — Pelican's web
// UI auth middleware accepts either, and we want both for
// belt-and-suspenders parity with the downtime CLI.
func TestOriginObjectMetadataCLI_LoginCookieSet(t *testing.T) {
	defer resetSharedDowntimeFlags()
	srv, recs, mu := newObjectMetadataMockServer(t)
	tok := writeFakeAdminTokenFile(t)

	runCLI(t, []string{
		"origin", "object-metadata", "list",
		"--server", srv.URL,
		"--token", tok,
		"--namespace", "/x",
	})
	mu.Lock()
	defer mu.Unlock()
	r := (*recs)[0]
	cookies := r.Header.Values("Cookie")
	if len(cookies) == 0 {
		t.Fatal("no Cookie header set")
	}
	// "login=fake-admin-token-for-test" should be present somewhere
	// in the combined cookie header.
	found := false
	for _, c := range cookies {
		if want := "login=fake-admin-token-for-test"; len(c) >= len(want) && c[:len(want)] == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("login cookie missing; got cookies = %v", cookies)
	}
}
