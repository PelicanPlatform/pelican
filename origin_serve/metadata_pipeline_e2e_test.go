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
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// TestE2EEventual_InboundMultipartFullLoop drives a real multipart/form-data
// PUT all the way through: the inbound demultiplexer (rewriteMultipartPUT)
// peels the "metadata" part and rewires the body to the "object" part; POSC
// commits the object; the close hook picks the blob off the context; and the
// eventual worker emits a multipart/related webhook carrying the original
// blob byte-for-byte. No prior test connected the inbound splitter to the
// outbound multipart publish.
func TestE2EEventual_InboundMultipartFullLoop(t *testing.T) {
	const (
		wantXML     = `<datasetSummary><experiment>atlas</experiment></datasetSummary>`
		wantObject  = "the-actual-object-bytes"
		xmlMIMEType = "application/xml"
	)

	type outbound struct {
		outerCT  string
		eventNS  string
		objPath  string
		blobCT   string
		blobBody string
	}
	got := make(chan outbound, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer w.WriteHeader(http.StatusOK)
		rec := outbound{outerCT: r.Header.Get("Content-Type")}
		_, params, err := mime.ParseMediaType(rec.outerCT)
		if err != nil {
			got <- rec
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(part)
			if strings.Contains(part.Header.Get("Content-Type"), "application/json") {
				var ev struct {
					Namespace string         `json:"namespace"`
					Object    map[string]any `json:"object"`
				}
				_ = json.Unmarshal(b, &ev)
				rec.eventNS = ev.Namespace
				if p, ok := ev.Object["path"].(string); ok {
					rec.objPath = p
				}
			} else {
				rec.blobCT = part.Header.Get("Content-Type")
				rec.blobBody = string(b)
			}
			_ = part.Close()
		}
		got <- rec
	}))
	defer receiver.Close()

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
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
		FilesystemForExists: func(namespace string) webdav.FileSystem {
			if namespace == fedPrefix {
				return posc
			}
			return nil
		},
	})
	defer ctl.Stop()
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	posc.SetCloseHook(ctl.CommitEventFromCloseHook(fedPrefix))
	ctl.Start(ctx)

	// Origin PUT front end WITH the multipart demultiplexer, mirroring the
	// production handler chain (extract header metadata → split multipart →
	// webdav).
	cfg := multipartConfig{allow: true, maxMetadataBytes: 4 << 20, metaPartName: "metadata", objPartName: "object"}
	dav := &webdav.Handler{FileSystem: posc, LockSystem: webdav.NewMemLS(), Prefix: fedPrefix}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rctx := setUserInfo(r.Context(), &userInfo{User: "alice"})
		r = r.WithContext(rctx)
		r = extractObjectMetadataFromRequest(r)
		nr, ok := rewriteMultipartPUT(w, r, cfg)
		if !ok {
			return
		}
		dav.ServeHTTP(w, nr)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Build the multipart/form-data request body: metadata part first, then
	// object part (order is contractually required).
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	metaHdr := textproto.MIMEHeader{}
	metaHdr.Set("Content-Disposition", `form-data; name="metadata"`)
	metaHdr.Set("Content-Type", xmlMIMEType)
	metaPart, err := mw.CreatePart(metaHdr)
	if err != nil {
		t.Fatalf("create metadata part: %v", err)
	}
	_, _ = metaPart.Write([]byte(wantXML))
	objHdr := textproto.MIMEHeader{}
	objHdr.Set("Content-Disposition", `form-data; name="object"`)
	objHdr.Set("Content-Type", "application/octet-stream")
	objPart, err := mw.CreatePart(objHdr)
	if err != nil {
		t.Fatalf("create object part: %v", err)
	}
	_, _ = objPart.Write([]byte(wantObject))
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/exp/data/run.dat", &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("multipart PUT returned %d, want 2xx", resp.StatusCode)
	}

	// The object part (not the whole multipart body) must be what landed on disk.
	objBytes, err := afero.ReadFile(mem, "/data/run.dat")
	if err != nil {
		t.Fatalf("read committed object: %v", err)
	}
	if string(objBytes) != wantObject {
		t.Fatalf("committed object = %q, want %q (multipart body leaked into the object?)", string(objBytes), wantObject)
	}

	select {
	case rec := <-got:
		if !strings.HasPrefix(rec.outerCT, "multipart/related") {
			t.Fatalf("outbound Content-Type = %q, want multipart/related", rec.outerCT)
		}
		if rec.eventNS != "/exp" || rec.objPath != "/exp/data/run.dat" {
			t.Fatalf("event ns/path = %q / %q, want /exp and /exp/data/run.dat", rec.eventNS, rec.objPath)
		}
		if rec.blobBody != wantXML {
			t.Fatalf("outbound blob = %q, want %q", rec.blobBody, wantXML)
		}
		if !strings.Contains(rec.blobCT, xmlMIMEType) {
			t.Fatalf("outbound blob Content-Type = %q, want to contain %q", rec.blobCT, xmlMIMEType)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver never got the multipart/related webhook")
	}
}

// TestE2EEventual_PerExportEndpointRouting verifies the resolver's per-export
// override in the LIVE worker pipeline: an event for a namespace with a
// per-export endpoint goes to that endpoint, while an event for a namespace
// without an override falls back to the origin-wide endpoint. Only Resolve()
// was unit-tested before; this drives real publishes through the workers.
func TestE2EEventual_PerExportEndpointRouting(t *testing.T) {
	gotA := make(chan string, 4)
	gotB := make(chan string, 4)
	receiverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA <- objectPathFromBody(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiverA.Close()
	receiverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotB <- objectPathFromBody(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiverB.Close()

	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/expA",
			// Per-export override → receiverA.
			Metadata: &server_utils.OriginExportMetadata{Endpoint: receiverA.URL},
		},
		{
			FederationPrefix: "/expB",
			// No override → falls back to the origin-wide endpoint (receiverB).
		},
	}

	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiverB.URL, // origin-wide default
		OriginMode:     ModeEventual,
		Exports:        exports,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    2,
		RatePerSecond:  1000,
	})
	defer ctl.Stop()
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.Start(ctx)

	evA := NewObjectCommitEvent("/expA", "/expA/a.dat", 1, "", time.Now().UTC(), nil)
	evB := NewObjectCommitEvent("/expB", "/expB/b.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), evA); err != nil {
		t.Fatalf("CommitEvent A: %v", err)
	}
	if err := ctl.CommitEvent(context.Background(), evB); err != nil {
		t.Fatalf("CommitEvent B: %v", err)
	}

	// receiverA must get /expA/a.dat; receiverB must get /expB/b.dat. A
	// cross-delivery (either receiver seeing the other's path) is a routing bug.
	assertReceives(t, gotA, "/expA/a.dat")
	assertReceives(t, gotB, "/expB/b.dat")
}

func objectPathFromBody(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var ev struct {
		Object map[string]any `json:"object"`
	}
	_ = json.Unmarshal(body, &ev)
	if p, ok := ev.Object["path"].(string); ok {
		return p
	}
	return ""
}

func assertReceives(t *testing.T, ch chan string, wantPath string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != wantPath {
			t.Fatalf("receiver got object path %q, want %q", got, wantPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("receiver never got a webhook for %q", wantPath)
	}
}
