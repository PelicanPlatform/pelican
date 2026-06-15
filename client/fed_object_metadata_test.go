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

// File fed_object_metadata_test.go is an end-to-end test of the
// `pelican` client's `WithObjectMetadataFile` option through the
// full federation:
//
//   - The CLI passes --metadata-file as WithObjectMetadataFile(path).
//   - NewTransferJob's option-apply pass loads the file and parses
//     the JSON into a scalar-only map[string]any.
//   - The client renders it as an RFC 9651 Structured Fields header
//     and attaches it to the upload PUT (handle_http.go).
//   - The V2 origin's request middleware parses the header
//     (ParseObjectMetadataHeader) and stashes it on the context.
//   - POSC commits the object on close, fires the metadata-publish
//     hook, which posts a JSON webhook to a receiver under our
//     control.
//   - The webhook body must contain the custom fields the client
//     supplied, with the right types preserved.

package client_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	pconfig "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// receivedEvent is what the receiver records for each webhook call.
type receivedEvent struct {
	body   []byte
	header http.Header
}

// startMetadataReceiver returns an httptest.Server that records every
// request. Test cleanups close the server.
func startMetadataReceiver(t *testing.T) (*httptest.Server, *[]receivedEvent, *sync.Mutex) {
	t.Helper()
	mu := &sync.Mutex{}
	events := &[]receivedEvent{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*events = append(*events, receivedEvent{body: body, header: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, events, mu
}

// objectMetadataTokenForUser mints a WLCG token with read+create+modify
// for the test export, with subject `subject`.
func objectMetadataTokenForUser(t *testing.T, subject string) string {
	t.Helper()
	issuer, err := pconfig.GetServerIssuerURL()
	require.NoError(t, err)

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modifyScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)

	tc := token.NewWLCGToken()
	tc.Lifetime = 5 * time.Minute
	tc.Issuer = issuer
	tc.Subject = subject
	tc.AddAudienceAny()
	tc.AddScopes(readScope, createScope, modifyScope)
	tkn, err := tc.CreateToken()
	require.NoError(t, err)
	return tkn
}

// pelicanURL builds a pelican:// URL for the running test federation.
func pelicanURL(path string) string {
	return fmt.Sprintf("pelican://%s:%d%s",
		param.Server_Hostname.GetString(),
		param.Server_WebPort.GetInt(),
		path)
}

// TestClientWithObjectMetadataFile_BadFileFailsFast confirms that a
// bad --metadata-file path is reported as an error from DoPut before
// any network I/O — the wiring goes through NewTransferJob's option-
// apply pass and surfaces via the standard error return. This locks
// down the lazy-load semantics of WithObjectMetadataFile.
func TestClientWithObjectMetadataFile_BadFileFailsFast(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// We don't actually need the metadata feature wired up on the
	// origin — the failure happens before any HTTP request leaves
	// the client. But we still need a valid federation the client
	// can resolve so the test exercises the *real* DoPut entry
	// point rather than a contrived shortcut.
	originCfg := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`
	ft := fed_test_utils.NewFedTest(t, originCfg)
	require.NotNil(t, ft)

	tkn := objectMetadataTokenForUser(t, "alice")

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	require.NoError(t, os.WriteFile(srcPath, []byte("data"), 0644))

	// Point at a path that does not exist.
	bogus := filepath.Join(t.TempDir(), "no-such-metadata.json")

	_, err := client.DoPut(ft.Ctx, srcPath, pelicanURL("/test/payload.bin"), false,
		client.WithToken(tkn),
		client.WithObjectMetadataFile(bogus),
	)
	require.Error(t, err, "DoPut must fail when WithObjectMetadataFile path is bogus")
	assert.Contains(t, err.Error(), "WithObjectMetadataFile",
		"the error must identify the failing option")
	assert.Contains(t, err.Error(), bogus,
		"the error must mention the offending file path")
}

// TestClientUploadWithObjectMetadata is the headline e2e: the
// `pelican` client uploads a file with a JSON metadata file, and we
// confirm the configured external receiver gets exactly the custom
// fields (with types preserved) embedded into the
// `object.committed` webhook body.
func TestClientUploadWithObjectMetadata(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	receiver, events, mu := startMetadataReceiver(t)

	originCfg := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Posc:
    Enabled: true
  Metadata:
    Enabled: true
    Mode: transactional
    Endpoint: %q
    RequestTimeout: 5s
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, receiver.URL)

	ft := fed_test_utils.NewFedTest(t, originCfg)
	require.NotNil(t, ft)

	// The token's subject doesn't need to map to a real user — POSC
	// will land the file as the origin process. We just need a
	// valid token.
	tkn := objectMetadataTokenForUser(t, "alice")

	// Write the JSON metadata file the CLI consumes.
	metaDir := t.TempDir()
	metaPath := filepath.Join(metaDir, "extra.json")
	require.NoError(t, os.WriteFile(metaPath, []byte(`{
		"experiment":  "atlas",
		"run_number":  4172,
		"weight":      3.14,
		"is_test":     false
	}`), 0644))

	// Build the file we'll upload.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	require.NoError(t, os.WriteFile(srcPath, []byte("client-uploaded payload"), 0644))

	// Upload via the real client.DoPut path. WithObjectMetadataFile
	// is the single public option that does file → SFV → header
	// plumbing; any parse / reserved-key error is reported as an
	// error from DoPut before any network I/O.
	results, err := client.DoPut(ft.Ctx, srcPath, pelicanURL("/test/payload.bin"), false,
		client.WithToken(tkn),
		client.WithObjectMetadataFile(metaPath),
	)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// In transactional mode the publish has already completed by
	// the time DoPut returns.  But the receiver runs in a separate
	// goroutine — give it a small grace period.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(*events)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("receiver never got an object-commit webhook")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, len(*events), "expected exactly one webhook")
	got := (*events)[0]

	// Headers we promise. Non-RFC headers are namespaced with the
	// X-Pelican- prefix per project convention; the bare
	// `Idempotency-Key` from draft-ietf-httpapi-idempotency-key is
	// still a draft, so we use X-Pelican-Idempotency-Key on the
	// wire.
	assert.Equal(t, "application/json", got.header.Get("Content-Type"))
	assert.NotEmpty(t, got.header.Get("Authorization"), "JWT must be present")
	assert.Empty(t, got.header.Get("Idempotency-Key"),
		"the bare Idempotency-Key must NOT be set (it isn't an RFC); use X-Pelican-Idempotency-Key")
	assert.NotEmpty(t, got.header.Get(origin_serve.IdempotencyKeyHeader),
		"event UUID must surface as X-Pelican-Idempotency-Key")

	var parsed struct {
		ID        string         `json:"id"`
		Type      string         `json:"type"`
		Namespace string         `json:"namespace"`
		Object    map[string]any `json:"object"`
	}
	require.NoError(t, json.Unmarshal(got.body, &parsed))

	assert.NotEmpty(t, parsed.ID, "event_id must be set")
	assert.Equal(t, "object.committed", parsed.Type)
	assert.Equal(t, "/test", parsed.Namespace)

	// The path must be federation-rooted (regression cover for the
	// gap-doc P1.1 issue).
	assert.Equal(t, "/test/payload.bin", parsed.Object["path"])

	// All the auto-collected fields are present.
	assert.NotZero(t, parsed.Object["size"], "size must be set")
	assert.NotEmpty(t, parsed.Object["etag"], "etag must be set")
	assert.NotEmpty(t, parsed.Object["created_at"], "created_at must be set")

	// And the inlined custom fields the client supplied. JSON
	// numbers come back as float64 by default — that matches the
	// design (the wire format is JSON, the typing is preserved as
	// far as JSON's grammar allows).
	assert.Equal(t, "atlas", parsed.Object["experiment"])
	assert.Equal(t, float64(4172), parsed.Object["run_number"])
	assert.Equal(t, float64(3.14), parsed.Object["weight"])
	assert.Equal(t, false, parsed.Object["is_test"])
}

// TestClientUploadWithObjectMetadataBlob is the multipart-shape e2e:
// the `pelican` client uploads an XML manifest alongside an object;
// the origin's splitter peels the blob, the close-hook fires, the
// transactional publisher posts to the receiver as
// multipart/related, and the receiver gets:
//
//   - a JSON root part with a `"metadata":{"content_type":...}` descriptor, and
//   - a second part with the *exact* XML bytes the client sent.
//
// This is the headline test for the opaque-blob feature added in
// the v2-origin-posc-and-metadata.md addendum.
func TestClientUploadWithObjectMetadataBlob(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	type capturedRequest struct {
		contentType string
		body        []byte
	}
	mu := &sync.Mutex{}
	requests := &[]capturedRequest{}

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*requests = append(*requests, capturedRequest{contentType: r.Header.Get("Content-Type"), body: body})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	originCfg := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Posc:
    Enabled: true
  Metadata:
    Enabled: true
    Mode: transactional
    Endpoint: %q
    RequestTimeout: 5s
    AllowMultipart: true
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, receiver.URL)

	ft := fed_test_utils.NewFedTest(t, originCfg)
	require.NotNil(t, ft)

	tkn := objectMetadataTokenForUser(t, "alice")

	// Write an XML metadata blob to disk.
	metaDir := t.TempDir()
	metaPath := filepath.Join(metaDir, "manifest.xml")
	xmlPayload := []byte(`<?xml version="1.0"?>
<datasetSummary>
  <experiment>atlas</experiment>
  <runs>4170,4171,4172</runs>
</datasetSummary>
`)
	require.NoError(t, os.WriteFile(metaPath, xmlPayload, 0644))

	// And the object body.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	objPayload := []byte("client-uploaded payload, multipart edition")
	require.NoError(t, os.WriteFile(srcPath, objPayload, 0644))

	results, err := client.DoPut(ft.Ctx, srcPath, pelicanURL("/test/payload.bin"), false,
		client.WithToken(tkn),
		client.WithObjectMetadataBlobFile(metaPath),
	)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// Wait for the receiver to record the webhook.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(*requests)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("receiver never got a webhook")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, len(*requests))
	rec := (*requests)[0]

	// The outbound webhook must be multipart/related, not plain
	// JSON. multipart/related is RFC 2387.
	if !strings.HasPrefix(rec.contentType, "multipart/related") {
		t.Fatalf("Content-Type = %q; want multipart/related", rec.contentType)
	}
	mediaType, params, err := mime.ParseMediaType(rec.contentType)
	require.NoError(t, err)
	require.Equal(t, "multipart/related", mediaType)
	require.Equal(t, `application/json`, params["type"])
	require.Equal(t, `<event>`, params["start"])
	require.NotEmpty(t, params["boundary"])

	// Parse the body. Part 1: JSON event with metadata descriptor.
	// Part 2: the XML manifest, byte-for-byte.
	mr := multipart.NewReader(bytes.NewReader(rec.body), params["boundary"])
	first, err := mr.NextPart()
	require.NoError(t, err)
	require.Equal(t, origin_serve.IdempotencyKeyHeader, "X-Pelican-Idempotency-Key") // sanity assert
	require.Equal(t, "<event>", first.Header.Get("Content-ID"))

	jsonBytes, err := io.ReadAll(first)
	require.NoError(t, err)
	var parsed struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Namespace string `json:"namespace"`
		Object    map[string]any
		Metadata  *struct {
			ContentType string `json:"content_type"`
			Size        int64  `json:"size"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(jsonBytes, &parsed))
	require.Equal(t, "object.committed", parsed.Type)
	require.Equal(t, "/test", parsed.Namespace)
	require.Equal(t, "/test/payload.bin", parsed.Object["path"])
	require.NotNil(t, parsed.Metadata, "JSON root must include a metadata descriptor when a blob is attached")
	assert.Equal(t, "application/xml", parsed.Metadata.ContentType)
	assert.Equal(t, int64(len(xmlPayload)), parsed.Metadata.Size)

	second, err := mr.NextPart()
	require.NoError(t, err)
	require.Equal(t, "<metadata>", second.Header.Get("Content-ID"))
	require.Equal(t, "application/xml", second.Header.Get("Content-Type"))
	gotXML, err := io.ReadAll(second)
	require.NoError(t, err)
	require.Equal(t, xmlPayload, gotXML, "metadata part must be the XML byte-for-byte")

	// And no third part — only the two we shipped.
	_, err = mr.NextPart()
	assert.ErrorIs(t, err, io.EOF, "expected exactly two parts on the outbound webhook")

	// Finally, the on-disk object should match what we uploaded.
	storagePrefix := ft.Exports[0].StoragePrefix
	require.NotEmpty(t, storagePrefix)
	onDisk, err := os.ReadFile(filepath.Join(storagePrefix, "payload.bin"))
	require.NoError(t, err)
	require.Equal(t, objPayload, onDisk, "object body must be streamed through unmolested")
}
