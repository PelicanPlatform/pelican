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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// e2eHarness wires together a memfs + POSC + metadata controller so the
// test exercises the same plumbing as production minus the gin/HTTP
// front-end. It returns the constructed wrapper FileSystem and the
// channel of received webhook bodies.
type e2eHarness struct {
	mem      afero.Fs
	fs       *poscFileSystem
	ctl      *metadataController
	receiver *httptest.Server
	bodies   chan []byte

	cancel context.CancelFunc
}

func newE2EHarness(t *testing.T, mode PublishMode) *e2eHarness {
	t.Helper()
	bodies := make(chan []byte, 64)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	mem := afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     mode,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.objectExists = func(_ context.Context, _, p string) bool {
		_, err := mem.Stat(p)
		return err == nil
	}

	posc.SetCloseHook(ctl.CommitEventFromCloseHook("/exp"))

	if mode == ModeEventual {
		ctl.Start(ctx)
	}

	t.Cleanup(func() {
		cancel()
		posc.Stop()
		ctl.Stop()
	})

	return &e2eHarness{
		mem:      mem,
		fs:       posc,
		ctl:      ctl,
		receiver: receiver,
		bodies:   bodies,
		cancel:   cancel,
	}
}

func TestE2ETransactional_HappyPath(t *testing.T) {
	h := newE2EHarness(t, ModeTransactional)
	ctx := setUserInfo(context.Background(), &userInfo{User: "alice"})
	ctx = withObjectMetadata(ctx, CustomFields{"experiment": "atlas", "run": int64(99)})

	f, err := h.fs.OpenFile(ctx, "/exp/data/run99.dat", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case body := <-h.bodies:
		var got struct {
			Type      string         `json:"type"`
			Namespace string         `json:"namespace"`
			Object    map[string]any `json:"object"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if got.Type != "object.committed" {
			t.Fatalf("type = %q", got.Type)
		}
		if got.Namespace != "/exp" {
			t.Fatalf("namespace = %q", got.Namespace)
		}
		if got.Object["path"] != "/exp/data/run99.dat" {
			t.Fatalf("path = %v", got.Object["path"])
		}
		if got.Object["experiment"] != "atlas" {
			t.Fatalf("experiment = %v", got.Object["experiment"])
		}
		if v, _ := got.Object["run"].(float64); v != 99 {
			t.Fatalf("run = %v", got.Object["run"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook delivered")
	}
}

func TestE2ETransactional_RollbackOn5xx(t *testing.T) {
	bodies := make(chan []byte, 8)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer receiver.Close()

	mem := afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer posc.Stop()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeTransactional,
		DB:             db,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	defer ctl.Stop()
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	posc.SetCloseHook(ctl.CommitEventFromCloseHook("/exp"))

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})
	f, err := posc.OpenFile(uctx, "/exp/x.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	closeErr := f.Close()
	if closeErr == nil {
		t.Fatal("expected close to fail when receiver 5xxs in transactional mode")
	}

	// Receiver did get the request.
	select {
	case <-bodies:
	case <-time.After(time.Second):
		t.Fatal("receiver never got the request")
	}

	// In transactional mode, the close-hook failure triggers POSC's
	// rollback path: the just-renamed final object is best-effort
	// removed so the object doesn't exist without metadata.
	if _, err := mem.Stat("/exp/x.bin"); err == nil {
		t.Fatal("expected POSC rollback to have removed /exp/x.bin")
	}

	// The queue row was cleaned up too.
	count := int64(0)
	ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
	if count != 0 {
		t.Fatalf("queue should be empty after transactional failure; got %d rows", count)
	}
}

// TestE2EWebdavHandler_PathIsFederationRooted exercises the full
// stack: an HTTP PUT goes through a real webdav.Handler (which strips
// the federation prefix), through POSC, into memfs, and the close
// hook publishes to a receiver. The test asserts the receiver sees
// the *federation-rooted* path in the JSON body — closing the gap
// that the synthetic (handler-bypassing) e2e test missed.
func TestE2EWebdavHandler_PathIsFederationRooted(t *testing.T) {
	bodies := make(chan []byte, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	inner := newAferoFileSystem(autoFs, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer posc.Stop()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeTransactional,
		DB:             db,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	defer ctl.Stop()
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }

	const fedPrefix = "/exp"
	posc.SetCloseHook(ctl.CommitEventFromCloseHook(fedPrefix))

	// A real webdav.Handler with Prefix set to the federation prefix
	// — exactly how production wires it.
	dav := &webdav.Handler{
		FileSystem: posc,
		LockSystem: webdav.NewMemLS(),
		Prefix:     fedPrefix,
	}

	// Build a tiny gin router that stashes the metadata header (so
	// X-Pelican-Object-Metadata + Content-Length flow through) and
	// then forwards to the webdav handler — this mirrors the
	// handlers.go middleware chain.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Stash a fake authenticated user so POSC builds the
		// staging path under .pelican-posc/alice/.
		ctx := setUserInfo(r.Context(), &userInfo{User: "alice"})
		r = r.WithContext(ctx)
		r = extractObjectMetadataFromRequest(r)
		dav.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := strings.NewReader("hello-from-webdav")
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/exp/data/run99.dat", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Pelican-Object-Metadata", `experiment="atlas"`)
	req.ContentLength = int64(body.Len())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	select {
	case raw := <-bodies:
		var got struct {
			Namespace string         `json:"namespace"`
			Object    map[string]any `json:"object"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if got.Namespace != fedPrefix {
			t.Fatalf("namespace = %q, want %q", got.Namespace, fedPrefix)
		}
		// THE assertion that the synthetic e2e test missed: the
		// path must be federation-rooted, not export-relative.
		if got.Object["path"] != "/exp/data/run99.dat" {
			t.Fatalf("object.path = %v, want /exp/data/run99.dat", got.Object["path"])
		}
		if got.Object["experiment"] != "atlas" {
			t.Fatalf("custom field experiment = %v, want atlas", got.Object["experiment"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receiver never got a webhook")
	}
}

// TestE2EEventual_WebdavHandler_ObjectExistsCheck exercises the same
// production wiring as TestE2EWebdavHandler_PathIsFederationRooted (a real
// webdav.Handler that strips its federation Prefix before OpenFile) but in
// EVENTUAL mode, where the background worker runs the skip-if-deleted
// existence check via FilesystemForExists.
//
// This is the gap the other tests missed: every existing eventual-mode
// test overrides ctl.objectExists with a closure that Stats the SAME path
// space the object was written in, so none of them exercise the real
// FilesystemForExists closure. In production the queue row's ObjectPath is
// federation-rooted (/exp/data/x) while the per-export FileSystem is
// export-relative (/data/x). If the existence check doesn't reconcile the
// two, the worker drops every committed object as "deleted" and NOTHING is
// ever published — which is exactly the "eventual mode doesn't work"
// report. The assertion here is simply that the receiver DOES get the
// webhook.
func TestE2EEventual_WebdavHandler_ObjectExistsCheck(t *testing.T) {
	bodies := make(chan []byte, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
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
		// Wire the existence check exactly like production does: return
		// the export-relative FileSystem for the namespace. We do NOT
		// override ctl.objectExists, so the real FilesystemForExists +
		// path-space reconciliation is what runs.
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

	dav := &webdav.Handler{
		FileSystem: posc,
		LockSystem: webdav.NewMemLS(),
		Prefix:     fedPrefix,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rctx := setUserInfo(r.Context(), &userInfo{User: "alice"})
		r = r.WithContext(rctx)
		r = extractObjectMetadataFromRequest(r)
		dav.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := strings.NewReader("hello-eventual")
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/exp/data/run99.dat", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = int64(body.Len())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	select {
	case raw := <-bodies:
		var got struct {
			Object map[string]any `json:"object"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if got.Object["path"] != "/exp/data/run99.dat" {
			t.Fatalf("object.path = %v, want /exp/data/run99.dat", got.Object["path"])
		}
	case <-time.After(3 * time.Second):
		// Before the fix, the worker's existence check Stats the
		// federation-rooted path against the export-relative FS, misses,
		// and drops the row as "object deleted" — so the webhook never
		// arrives and we land here.
		t.Fatal("eventual worker never delivered the webhook (row likely dropped by a mismatched skip-if-deleted check)")
	}
}

func TestE2EEventual_BackpressureAndDrain(t *testing.T) {
	// Receiver is initially down (5xx). Once we flip it on, the worker
	// drains the queue.
	var (
		mu      sync.Mutex
		failing = true
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := failing
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	mem := afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	posc := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer posc.Stop()

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
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.objectExists = func(_ context.Context, _, p string) bool {
		_, err := mem.Stat(p)
		return err == nil
	}
	posc.SetCloseHook(ctl.CommitEventFromCloseHook("/exp"))
	ctl.Start(ctx)
	defer ctl.Stop()

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})
	for i := 0; i < 3; i++ {
		f, err := posc.OpenFile(uctx, "/exp/x.bin", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, err := f.Write([]byte("d")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	// While the receiver is down, rows should still be in the queue.
	var count int64
	ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
	if count == 0 {
		t.Fatal("queue should have rows while receiver is failing")
	}

	mu.Lock()
	failing = false
	mu.Unlock()

	deadline := time.After(5 * time.Second)
	for {
		ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
		if count == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("queue did not drain (depth=%d)", count)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
