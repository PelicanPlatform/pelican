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
	"mime/multipart"
	"net/textproto"
	"testing"
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
