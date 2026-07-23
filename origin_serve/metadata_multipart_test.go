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
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// defaultMultipartConfig is the test fixture used by every splitter
// test that doesn't override a specific field.
func defaultMultipartConfig() multipartConfig {
	return multipartConfig{
		allow:            true,
		maxMetadataBytes: 4 * 1024 * 1024,
		metaPartName:     "metadata",
		objPartName:      "object",
	}
}

// buildTwoPartBody renders a multipart/form-data body with the
// supplied metadata + object parts in that order. Returns the raw
// body bytes and the boundary string.
func buildTwoPartBody(t *testing.T, metaName, metaCT string, metaBody []byte, objName string, objBody []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	if metaName != "" {
		mh := textproto.MIMEHeader{}
		mh.Set("Content-Disposition", `form-data; name="`+metaName+`"`)
		if metaCT != "" {
			mh.Set("Content-Type", metaCT)
		}
		p, err := mw.CreatePart(mh)
		if err != nil {
			t.Fatalf("create meta part: %v", err)
		}
		_, _ = p.Write(metaBody)
	}
	if objName != "" {
		oh := textproto.MIMEHeader{}
		oh.Set("Content-Disposition", `form-data; name="`+objName+`"; filename="object"`)
		oh.Set("Content-Type", "application/octet-stream")
		p, err := mw.CreatePart(oh)
		if err != nil {
			t.Fatalf("create obj part: %v", err)
		}
		_, _ = p.Write(objBody)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), mw.Boundary()
}

// makeRequest assembles a *http.Request modeling the post-routing
// shape rewriteMultipartPUT expects.
func makeRequest(t *testing.T, body []byte, boundary string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/x.dat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	return req
}

// --- isMultipartFormDataPUT -------------------------------------

func TestIsMultipartFormDataPUT(t *testing.T) {
	tests := []struct {
		name   string
		method string
		ct     string
		want   bool
	}{
		{"plain PUT", http.MethodPut, "application/octet-stream", false},
		{"empty CT on PUT", http.MethodPut, "", false},
		{"multipart PUT", http.MethodPut, `multipart/form-data; boundary=x`, true},
		{"multipart GET", http.MethodGet, `multipart/form-data; boundary=x`, false},
		{"multipart POST", http.MethodPost, `multipart/form-data; boundary=x`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/x", nil)
			if tt.ct != "" {
				req.Header.Set("Content-Type", tt.ct)
			}
			if got := isMultipartFormDataPUT(req); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- rewriteMultipartPUT happy path -----------------------------

func TestRewriteMultipartPUT_HappyPath(t *testing.T) {
	cfg := defaultMultipartConfig()
	metaBody := []byte(`<datasetSummary><experiment>atlas</experiment></datasetSummary>`)
	objBody := []byte(`raw object payload`)
	body, boundary := buildTwoPartBody(t, "metadata", "application/xml", metaBody, "object", objBody)
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	newReq, ok := rewriteMultipartPUT(rw, req, cfg)
	if !ok {
		t.Fatalf("expected ok=true, got body=%q status=%d", rw.Body.String(), rw.Code)
	}
	blob := multipartBlobFromContext(newReq.Context())
	if blob == nil {
		t.Fatal("expected blob on context")
	}
	if blob.ContentType != "application/xml" {
		t.Fatalf("ContentType = %q", blob.ContentType)
	}
	if !bytes.Equal(blob.Body, metaBody) {
		t.Fatalf("Body mismatch:\n got  %q\n want %q", blob.Body, metaBody)
	}

	// The rewired request body must stream out exactly the object
	// bytes (no boundary, no headers).
	gotObj, err := io.ReadAll(newReq.Body)
	if err != nil {
		t.Fatalf("read rewired body: %v", err)
	}
	if !bytes.Equal(gotObj, objBody) {
		t.Fatalf("rewired object body mismatch:\n got  %q\n want %q", gotObj, objBody)
	}
	_ = newReq.Body.Close()

	// Content-Length should be unset, transfer-encoding chunked.
	if cl := newReq.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("Content-Length should be cleared; got %q", cl)
	}
	if newReq.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", newReq.ContentLength)
	}
	if len(newReq.TransferEncoding) != 1 || newReq.TransferEncoding[0] != "chunked" {
		t.Fatalf("TransferEncoding = %v, want [chunked]", newReq.TransferEncoding)
	}
}

// --- shape violations -------------------------------------------

func TestRewriteMultipartPUT_WrongOrder(t *testing.T) {
	cfg := defaultMultipartConfig()
	// Build a body with object FIRST, metadata SECOND.
	body, boundary := buildTwoPartBody(t, "object", "application/octet-stream", []byte("raw"), "metadata", []byte("oops"))
	// Swap to flip the order — buildTwoPartBody writes in the
	// argument order, so passing them swapped already does it.
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when parts are in wrong order")
	}
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), `must be named "metadata"`) {
		t.Fatalf("error body = %q", rw.Body.String())
	}
}

func TestRewriteMultipartPUT_MissingObjectPart(t *testing.T) {
	cfg := defaultMultipartConfig()
	// metadata only — no object part.
	body, boundary := buildTwoPartBody(t, "metadata", "application/xml", []byte("<x/>"), "", nil)
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when object part is missing")
	}
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "missing the object part") {
		t.Fatalf("error body = %q", rw.Body.String())
	}
}

func TestRewriteMultipartPUT_UnknownPartName(t *testing.T) {
	cfg := defaultMultipartConfig()
	body, boundary := buildTwoPartBody(t, "random_field", "application/xml", []byte("<x/>"), "object", []byte("raw"))
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when first part has unexpected name")
	}
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
}

func TestRewriteMultipartPUT_OversizedMetadataPart(t *testing.T) {
	cfg := defaultMultipartConfig()
	cfg.maxMetadataBytes = 16 // tight cap so a 32-byte blob is over the line
	body, boundary := buildTwoPartBody(t, "metadata", "application/xml",
		bytes.Repeat([]byte("x"), 32), "object", []byte("raw"))
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when metadata exceeds cap")
	}
	if rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rw.Code)
	}
}

// Exactly-at-cap is the cap-boundary acceptance test.
func TestRewriteMultipartPUT_MetadataAtCapAccepted(t *testing.T) {
	cfg := defaultMultipartConfig()
	cfg.maxMetadataBytes = 16
	body, boundary := buildTwoPartBody(t, "metadata", "application/xml",
		bytes.Repeat([]byte("x"), 16), "object", []byte("raw"))
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	newReq, ok := rewriteMultipartPUT(rw, req, cfg)
	if !ok {
		t.Fatalf("expected ok=true with metadata exactly at cap; got %d %q", rw.Code, rw.Body.String())
	}
	blob := multipartBlobFromContext(newReq.Context())
	if blob == nil || len(blob.Body) != 16 {
		t.Fatalf("blob shape unexpected: %+v", blob)
	}
}

// --- AllowMultipart=false rejection -----------------------------

func TestRewriteMultipartPUT_DisabledOriginRejects(t *testing.T) {
	cfg := defaultMultipartConfig()
	cfg.allow = false
	body, boundary := buildTwoPartBody(t, "metadata", "application/xml", []byte("<x/>"), "object", []byte("raw"))
	req := makeRequest(t, body, boundary)

	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when AllowMultipart is false")
	}
	if rw.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rw.Code)
	}
}

// --- Non-multipart PUTs pass through ----------------------------

func TestRewriteMultipartPUT_PlainPUTIsPassthrough(t *testing.T) {
	cfg := defaultMultipartConfig()
	req := httptest.NewRequest(http.MethodPut, "/x.dat", strings.NewReader("raw body"))
	req.Header.Set("Content-Type", "application/octet-stream")

	rw := httptest.NewRecorder()
	newReq, ok := rewriteMultipartPUT(rw, req, cfg)
	if !ok {
		t.Fatalf("plain PUT must pass through; status=%d body=%q", rw.Code, rw.Body.String())
	}
	if newReq != req {
		t.Fatal("expected the same *Request to be returned for non-multipart PUT")
	}
}

// --- Malformed multipart envelopes ------------------------------

// --- outbound publisher: plain JSON vs multipart/related --------

func TestBuildAttemptBody_NoBlobReturnsPlainJSON(t *testing.T) {
	jsonBody := []byte(`{"id":"abc","object":{}}`)
	event := &ObjectCommitEvent{ID: "abc"}
	reader, contentType, err := buildAttemptBody(jsonBody, event)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if contentType != "application/json" {
		t.Fatalf("ContentType = %q, want application/json", contentType)
	}
	got, _ := io.ReadAll(reader)
	if !bytes.Equal(got, jsonBody) {
		t.Fatalf("body = %q", got)
	}
}

func TestBuildAttemptBody_WithBlobReturnsMultipartRelated(t *testing.T) {
	jsonBody := []byte(`{"id":"abc","object":{},"metadata":{"content_type":"application/xml","size":4}}`)
	event := &ObjectCommitEvent{
		ID:                  "abc",
		MetadataContentType: "application/xml",
		MetadataBody:        []byte(`<x/>`),
	}
	reader, contentType, err := buildAttemptBody(jsonBody, event)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasPrefix(contentType, "multipart/related;") {
		t.Fatalf("ContentType = %q, want multipart/related", contentType)
	}
	if !strings.Contains(contentType, `type="application/json"`) {
		t.Fatalf("ContentType missing type param: %q", contentType)
	}
	if !strings.Contains(contentType, `start="<event>"`) {
		t.Fatalf("ContentType missing start param: %q", contentType)
	}

	// Parse the body back through the multipart reader and assert
	// both parts match what we put in.
	body, _ := io.ReadAll(reader)
	// Extract boundary from Content-Type.
	const boundaryKey = "boundary="
	bi := strings.Index(contentType, boundaryKey)
	if bi < 0 {
		t.Fatal("no boundary param")
	}
	boundary := strings.SplitN(contentType[bi+len(boundaryKey):], ";", 2)[0]
	boundary = strings.Trim(boundary, `" `)

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	first, err := mr.NextPart()
	if err != nil {
		t.Fatalf("first part: %v", err)
	}
	if first.Header.Get("Content-ID") != publisherRootContentID {
		t.Fatalf("first Content-ID = %q", first.Header.Get("Content-ID"))
	}
	gotJSON, _ := io.ReadAll(first)
	if !bytes.Equal(gotJSON, jsonBody) {
		t.Fatalf("first part body mismatch:\n got  %q\n want %q", gotJSON, jsonBody)
	}

	second, err := mr.NextPart()
	if err != nil {
		t.Fatalf("second part: %v", err)
	}
	if second.Header.Get("Content-ID") != publisherBlobContentID {
		t.Fatalf("second Content-ID = %q", second.Header.Get("Content-ID"))
	}
	if ct := second.Header.Get("Content-Type"); ct != "application/xml" {
		t.Fatalf("blob Content-Type = %q", ct)
	}
	gotBlob, _ := io.ReadAll(second)
	if string(gotBlob) != "<x/>" {
		t.Fatalf("blob mismatch: %q", gotBlob)
	}
}

// --- ObjectCommitEvent.MarshalJSON surfaces the metadata descriptor

func TestObjectCommitEvent_MarshalJSON_NoBlob(t *testing.T) {
	ev := NewObjectCommitEvent("/ns", "/ns/x.dat", 7, `"etag"`, time.Unix(1745934855, 0).UTC(), nil)
	out, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), `"metadata":`) {
		t.Fatalf("JSON unexpectedly contained metadata descriptor:\n%s", string(out))
	}
}

func TestObjectCommitEvent_MarshalJSON_WithBlob(t *testing.T) {
	ev := NewObjectCommitEvent("/ns", "/ns/x.dat", 7, `"etag"`, time.Unix(1745934855, 0).UTC(), nil)
	ev.WithMetadataBlob("application/xml", []byte(`<x/>`))
	out, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"metadata":{"content_type":"application/xml","size":4}`) {
		t.Fatalf("JSON did not surface the metadata descriptor:\n%s", string(out))
	}
}

func TestRewriteMultipartPUT_MissingBoundary(t *testing.T) {
	cfg := defaultMultipartConfig()
	req := httptest.NewRequest(http.MethodPut, "/x.dat", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "multipart/form-data") // no boundary= param
	rw := httptest.NewRecorder()
	_, ok := rewriteMultipartPUT(rw, req, cfg)
	if ok {
		t.Fatal("expected rewrite to fail when boundary parameter is missing")
	}
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rw.Code)
	}
}
