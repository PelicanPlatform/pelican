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
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// TestTPC_SourceEtag_LandsInDBAndSurfacesOnPropfind is the joined
// regression test for the TPC source-ETag path. The context-stash
// (tpc_handler.go) and the DAO persistence + DeadProps exposure
// (source_etag_test.go) are each covered in isolation, but nothing
// asserted the whole chain: a real HTTP COPY whose source returns an
// ETag must (1) persist that ETag as source_etag on the destination's
// live row and (2) surface it as the Pelican source-etag dead property
// on a later open (PROPFIND). A regression dropping either the ctx stash
// or the UPSERT rider would pass the isolated tests but fail this one.
func TestTPC_SourceEtag_LandsInDBAndSurfacesOnPropfind(t *testing.T) {
	// Allow the TPC GET to reach the localhost httptest source server.
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	if err := param.Server_SSRFProtection_Disabled.Set(true); err != nil {
		t.Fatalf("disable SSRF: %v", err)
	}
	config.ResetSSRFTransportForTest()

	const sourceEtag = `"remote-src-etag-123"`
	content := []byte("third-party-copy payload")

	// Source server: serves the object and advertises an ETag.
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
			w.Header().Set("ETag", sourceEtag)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
		case http.MethodHead:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
			w.Header().Set("ETag", sourceEtag)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer src.Close()

	// Destination stack: an observation-wired aferoFileSystem (so DeadProps
	// can later read the row) beneath a close-notify hook that records the
	// commit (so the copy's source ETag is persisted from the ctx stash).
	dao, _, cleanup := newTestDAO(t)
	defer cleanup()

	afs := newAferoFileSystem(afero.NewMemMapFs(), "", nil)
	afs.setObservation(&observationConfig{
		namespace: "/exp",
		dao:       dao,
		cache:     newObservationCache(0),
	})
	destFs := newCloseNotifyFs(afs, RecordCommitCloseHook(dao, "/exp", false))
	backend := &mockBackend{fs: destFs}
	router := setupTPCRouter(backend)

	// Drive a real COPY.
	req := httptest.NewRequest("COPY", "/data/run.dat", nil)
	req.Header.Set("Source", toLocalhostURL(src.URL)+"/data/run.dat")
	req.Header.Set("Authorization", "Bearer dest-token")
	req.Header.Set("TransferHeaderAuthorization", "Bearer src-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("COPY status = %d, body=%q", w.Code, w.Body.String())
	}

	ctx := context.Background()

	// (1) The source ETag must have landed on the live row's source_etag.
	live, err := dao.LookupLive(ctx, "/exp", "/exp/data/run.dat")
	if err != nil {
		t.Fatalf("LookupLive: %v", err)
	}
	if live == nil {
		t.Fatal("COPY did not create a live row")
	}
	if live.SourceEtag == nil || *live.SourceEtag != sourceEtag {
		t.Fatalf("live.SourceEtag = %v, want %q", live.SourceEtag, sourceEtag)
	}

	// (2) A later open must surface it as the Pelican source-etag dead
	// property (the PROPFIND exposure).
	f, err := afs.OpenFile(ctx, "/data/run.dat", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()
	dph, ok := f.(webdav.DeadPropsHolder)
	if !ok {
		t.Fatal("aferoFile should implement webdav.DeadPropsHolder")
	}
	props, err := dph.DeadProps()
	if err != nil {
		t.Fatalf("DeadProps: %v", err)
	}
	prop, ok := props[xml.Name{Space: PelicanDAVNamespace, Local: PropSourceEtag}]
	if !ok {
		t.Fatalf("expected source-etag dead property; got %v", props)
	}
	if string(prop.InnerXML) != sourceEtag {
		t.Fatalf("source-etag property = %q, want %q", prop.InnerXML, sourceEtag)
	}
}
