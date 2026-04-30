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
// `pelican` client's `WithObjectMetadata` option through the full
// federation:
//
//   - The CLI loads a JSON file (LoadObjectMetadataFile).
//   - The client renders it as an RFC 9651 Structured Fields header
//     and attaches it to the upload PUT (BuildObjectMetadataHeader,
//     wired in handle_http.go).
//   - The V2 origin's request middleware parses the header
//     (ParseObjectMetadataHeader) and stashes it on the context.
//   - POSC commits the object on close, fires the metadata-publish
//     hook, which posts a JSON webhook to a receiver under our
//     control.
//   - The webhook body must contain the custom fields the client
//     supplied, with the right types preserved.

package client_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	// Plumb the JSON file through the same path the CLI uses.
	customFields, err := client.LoadObjectMetadataFile(metaPath)
	require.NoError(t, err)
	require.NotEmpty(t, customFields)

	// Build the file we'll upload.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	require.NoError(t, os.WriteFile(srcPath, []byte("client-uploaded payload"), 0644))

	// Upload via the real client.DoPut path with our new option.
	results, err := client.DoPut(ft.Ctx, srcPath, pelicanURL("/test/payload.bin"), false,
		client.WithToken(tkn),
		client.WithObjectMetadata(customFields),
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
