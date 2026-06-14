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

// File object_metadata_more_test.go is the second batch of integration
// tests for the object-metadata tracking subsystem. Each test
// targets a gap that surfaced during pre-PR review:
//
//   P1.1 — full request path: PUT → real webdav.Handler →
//          close hook → DAO → admin endpoint shows the row.
//   P1.2 — composeCloseHooks ordering + error isolation.
//   P2.3 — per-export TrackAccess override actually splits two
//          namespaces (one tracked, one not) inside the same origin.
//   P3.5 — pruner Start/Stop lifecycle, not just onePass.
//   P3.6 — SHA-256 ETag survives end-to-end into the DAO row with
//          etag_source='origin'.

package origin_serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// ============================================================
// P1.2 — composeCloseHooks
// ============================================================

func TestComposeCloseHooks_Nil(t *testing.T) {
	if got := composeCloseHooks(nil, nil); got != nil {
		t.Fatal("composeCloseHooks(nil, nil) should return nil")
	}
}

func TestComposeCloseHooks_PublishOnlyShortCircuits(t *testing.T) {
	publishCalls := 0
	pub := func(context.Context, string, os.FileInfo) error { publishCalls++; return nil }
	got := composeCloseHooks(pub, nil)
	if got == nil {
		t.Fatal("expected non-nil composed hook")
	}
	if err := got(context.Background(), "/x", nil); err != nil {
		t.Fatalf("err: %v", err)
	}
	if publishCalls != 1 {
		t.Fatalf("publishCalls = %d, want 1", publishCalls)
	}
}

func TestComposeCloseHooks_TrackOnlyShortCircuits(t *testing.T) {
	trackCalls := 0
	tr := func(context.Context, string, os.FileInfo) error { trackCalls++; return nil }
	got := composeCloseHooks(nil, tr)
	if got == nil {
		t.Fatal("expected non-nil composed hook")
	}
	_ = got(context.Background(), "/x", nil)
	if trackCalls != 1 {
		t.Fatalf("trackCalls = %d, want 1", trackCalls)
	}
}

// TestComposeCloseHooks_BothFireTrackFirst — track must fire before
// publish so its DB write is already in the batcher when the
// publish-hook's insert coalesces with it.
func TestComposeCloseHooks_BothFireTrackFirst(t *testing.T) {
	order := []string{}
	track := func(context.Context, string, os.FileInfo) error {
		order = append(order, "track")
		return nil
	}
	publish := func(context.Context, string, os.FileInfo) error {
		order = append(order, "publish")
		return nil
	}
	hook := composeCloseHooks(track, publish)
	if err := hook(context.Background(), "/x", nil); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(order) != 2 || order[0] != "track" || order[1] != "publish" {
		t.Fatalf("call order = %v, want [track publish]", order)
	}
}

// TestComposeCloseHooks_TrackErrorSwallowed — a tracking failure
// must not prevent the publish hook from firing nor surface its
// error to the caller. This is the property the design's "best-
// effort tracking" promise depends on.
func TestComposeCloseHooks_TrackErrorSwallowed(t *testing.T) {
	publishFired := false
	publish := func(context.Context, string, os.FileInfo) error {
		publishFired = true
		return nil
	}
	track := func(context.Context, string, os.FileInfo) error {
		return errors.New("tracking blew up")
	}
	hook := composeCloseHooks(track, publish)
	if err := hook(context.Background(), "/x", nil); err != nil {
		t.Fatalf("tracking failure leaked: %v", err)
	}
	if !publishFired {
		t.Fatal("publish hook did not fire despite tracking failure")
	}
}

// TestComposeCloseHooks_PublishErrorReturned — publish failures are
// the only ones that surface. They do NOT block tracking from running.
func TestComposeCloseHooks_PublishErrorReturned(t *testing.T) {
	publishErr := errors.New("publish boom")
	trackFired := false
	publish := func(context.Context, string, os.FileInfo) error { return publishErr }
	track := func(context.Context, string, os.FileInfo) error { trackFired = true; return nil }

	hook := composeCloseHooks(track, publish)
	got := hook(context.Background(), "/x", nil)
	if !errors.Is(got, publishErr) {
		t.Fatalf("returned err = %v, want publishErr", got)
	}
	if !trackFired {
		t.Fatal("track hook did not fire even though publish failed")
	}
}

// TestComposeCloseHooks_VariadicThreeHooks — the variadic shape
// generalizes beyond {track, publish}. With three hooks, they fire
// in argument order, every hook fires regardless of prior errors,
// and the LAST hook's return value (error or nil) is the result.
// nil hooks are silently filtered out of the chain.
func TestComposeCloseHooks_VariadicThreeHooks(t *testing.T) {
	order := []string{}
	mkHook := func(label string, ret error) closeHookFn {
		return func(context.Context, string, os.FileInfo) error {
			order = append(order, label)
			return ret
		}
	}
	audit := mkHook("audit", errors.New("audit failed"))
	track := mkHook("track", nil)
	publish := mkHook("publish", errors.New("publish boom"))
	hook := composeCloseHooks(audit, nil, track, publish)
	got := hook(context.Background(), "/x", nil)
	if got == nil || got.Error() != "publish boom" {
		t.Fatalf("returned err = %v, want 'publish boom' (last hook's return)", got)
	}
	want := []string{"audit", "track", "publish"}
	if len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Fatalf("call order = %v, want %v", order, want)
	}
}

// TestComposeCloseHooks_LastHookNilOverwritesEarlier — explicit
// regression of the "earlier errors are dropped" contract: if the
// last hook returns nil, the composed function returns nil even
// when earlier hooks errored.
func TestComposeCloseHooks_LastHookNilOverwritesEarlier(t *testing.T) {
	errorer := func(context.Context, string, os.FileInfo) error { return errors.New("earlier boom") }
	swallow := func(context.Context, string, os.FileInfo) error { return nil }
	hook := composeCloseHooks(errorer, swallow)
	if err := hook(context.Background(), "/x", nil); err != nil {
		t.Fatalf("expected nil (last hook returned nil); got %v", err)
	}
}

// ============================================================
// P1.1 — full PUT → webdav.Handler → close hook → DAO → admin
// ============================================================

// TestE2E_TrackingThroughWebdavHandler bootstraps the full request
// stack (gin → listing-mode middleware → webdav.Handler → posc →
// aferoFs → memfs) with the tracking close hook composed in, then
// PUTs an object and verifies (a) the live row exists in the DAO,
// (b) the path is federation-rooted, (c) etag_source is 'backend',
// (d) the admin endpoint returns the row.
func TestE2E_TrackingThroughWebdavHandler(t *testing.T) {
	const namespace = "/exp"

	// Storage + DAO + batcher.
	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	db := newObjectMetadataTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batcher := newSQLiteBatcher(ctx, db, 64, 20*time.Millisecond)
	defer batcher.Stop()
	dao := newObjectMetadataDAO(db, batcher)

	// Install the DAO as the package-global so the admin endpoint
	// can find it. Restore on cleanup.
	prevDAO := objectMetaDAO
	objectMetaDAO = dao
	t.Cleanup(func() { objectMetaDAO = prevDAO })

	// Filesystem chain (mirrors the per-export construction in
	// InitializeHandlers): aferoFs → POSC → composed close hook.
	aferoFs := newAferoFileSystem(autoFs, "", nil)
	aferoFs.setObservation(&observationConfig{
		namespace: namespace,
		dao:       dao,
		cache:     newObservationCache(64),
	})
	posc := newPoscFileSystem(ctx, aferoFs, ".pelican-posc", time.Hour, 19*time.Minute)
	posc.SetTouchFS(autoFs)
	defer posc.Stop()
	trackHook := RecordCommitCloseHook(dao, namespace, false)
	posc.SetCloseHook(composeCloseHooks(nil, trackHook))

	// webdav.Handler with the federation prefix the production
	// origin would assign.
	dav := &webdav.Handler{
		FileSystem: posc,
		LockSystem: webdav.NewMemLS(),
		Prefix:     namespace,
	}

	// Gin with the listing-mode middleware, plus a tiny handler
	// that fakes the auth-middleware user-info stash so POSC can
	// build the per-user staging dir.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(listingModeMiddleware())
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(setUserInfo(c.Request.Context(), &userInfo{User: "alice"}))
		c.Next()
	})
	r.NoRoute(gin.WrapH(dav))

	// Also mount the admin endpoint so we can verify the DAO via
	// HTTP rather than via the in-process struct.
	adminGroup := r.Group("/api/v1.0/origin_ui")
	RegisterObjectMetadataAdminAPI(adminGroup)

	srv := httptest.NewServer(r)
	defer srv.Close()

	// PUT the object.
	put, err := http.NewRequest(http.MethodPut, srv.URL+"/exp/data/run42.bin", strings.NewReader("hello world"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	put.ContentLength = 11
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}

	// Force a flush so the durable close-hook insert is on disk.
	if err := dao.batcher.FlushNow(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Direct DAO sanity check.
	live, err := dao.LookupLive(ctx, namespace, "/exp/data/run42.bin")
	if err != nil {
		t.Fatalf("LookupLive: %v", err)
	}
	if live == nil {
		t.Fatal("no live row after PUT through webdav handler")
	}
	if live.ObjectPath != "/exp/data/run42.bin" {
		t.Fatalf("object_path = %q, want /exp/data/run42.bin (federation-rooted)", live.ObjectPath)
	}
	if live.EtagSource != "backend" {
		t.Fatalf("etag_source = %q, want backend (default policy)", live.EtagSource)
	}

	// Admin endpoint sanity check.
	adminResp, err := http.Get(srv.URL + "/api/v1.0/origin_ui/object_metadata/lookup?namespace=/exp&path=/exp/data/run42.bin")
	if err != nil {
		t.Fatalf("admin GET: %v", err)
	}
	defer adminResp.Body.Close()
	if adminResp.StatusCode != 200 {
		t.Fatalf("admin status = %d", adminResp.StatusCode)
	}
	var adminBody struct {
		Live *adminObjectMetadataRow `json:"live"`
	}
	if err := json.NewDecoder(adminResp.Body).Decode(&adminBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if adminBody.Live == nil {
		t.Fatal("admin endpoint missing live row")
	}
	if adminBody.Live.ObjectPath != "/exp/data/run42.bin" {
		t.Fatalf("admin object_path = %q", adminBody.Live.ObjectPath)
	}
}

// ============================================================
// P2.3 — per-export overrides
// ============================================================

func TestResolveTrackAccess_PerExportOverridesOriginWide(t *testing.T) {
	// We don't manipulate the origin-wide default (param viper
	// state) here; we only test the per-export override branch
	// directly, which is sufficient to lock down the resolver
	// contract: if an export sets TrackAccess explicitly, that
	// wins, regardless of the origin-wide default.
	yes := true
	no := false
	mkExp := func(tp *bool) server_utils.OriginExport {
		return server_utils.OriginExport{
			FederationPrefix: "/x",
			Metadata:         &server_utils.OriginExportMetadata{TrackAccess: tp},
		}
	}
	if got := resolveTrackAccess(mkExp(&yes)); !got {
		t.Fatal("explicit per-export TrackAccess=true must resolve true")
	}
	if got := resolveTrackAccess(mkExp(&no)); got {
		t.Fatal("explicit per-export TrackAccess=false must resolve false")
	}
}

func TestResolveTrackExtra_PerExportOverridesOriginWide(t *testing.T) {
	yes := true
	no := false
	mkExp := func(tp *bool) server_utils.OriginExport {
		return server_utils.OriginExport{
			FederationPrefix: "/x",
			Metadata:         &server_utils.OriginExportMetadata{TrackExtra: tp},
		}
	}
	if got := resolveTrackExtra(mkExp(&yes)); !got {
		t.Fatal("TrackExtra=true override must resolve true")
	}
	if got := resolveTrackExtra(mkExp(&no)); got {
		t.Fatal("TrackExtra=false override must resolve false")
	}
}

func TestResolveHistoryRetentionDays_PerExportOverride(t *testing.T) {
	thirty := 30
	exp := server_utils.OriginExport{
		FederationPrefix: "/x",
		Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &thirty},
	}
	if got := resolveHistoryRetentionDays(exp); got != 30 {
		t.Fatalf("got %d, want 30", got)
	}
}

// TestTwoNamespaces_OnlyTrackedNamespaceRecords — two namespaces in
// the same origin process, one with observation installed and one
// without. Both get a commit; only the tracked namespace's row
// appears in the DAO.
func TestTwoNamespaces_OnlyTrackedNamespaceRecords(t *testing.T) {
	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	db := newObjectMetadataTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batcher := newSQLiteBatcher(ctx, db, 64, 20*time.Millisecond)
	defer batcher.Stop()
	dao := newObjectMetadataDAO(db, batcher)

	// Tracked namespace: observation installed, close-hook
	// composed with RecordCommitCloseHook.
	trackedAfero := newAferoFileSystem(autoFs, "/tracked", nil)
	trackedAfero.setObservation(&observationConfig{
		namespace: "/tracked",
		dao:       dao,
		cache:     newObservationCache(8),
	})
	trackedPosc := newPoscFileSystem(ctx, trackedAfero, ".pelican-posc-A", time.Hour, 19*time.Minute)
	trackedPosc.SetTouchFS(autoFs)
	defer trackedPosc.Stop()
	trackedPosc.SetCloseHook(composeCloseHooks(nil, RecordCommitCloseHook(dao, "/tracked", false)))

	// Untracked namespace: NO observation, NO close hook at all.
	untrackedAfero := newAferoFileSystem(autoFs, "/untracked", nil)
	untrackedPosc := newPoscFileSystem(ctx, untrackedAfero, ".pelican-posc-B", time.Hour, 19*time.Minute)
	untrackedPosc.SetTouchFS(autoFs)
	defer untrackedPosc.Stop()

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})

	// Commit to tracked.
	f, err := trackedPosc.OpenFile(uctx, "/a.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("tracked open: %v", err)
	}
	if _, err := f.Write([]byte("tracked data")); err != nil {
		t.Fatalf("tracked write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("tracked close: %v", err)
	}

	// Commit to untracked.
	f2, err := untrackedPosc.OpenFile(uctx, "/b.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("untracked open: %v", err)
	}
	if _, err := f2.Write([]byte("untracked data")); err != nil {
		t.Fatalf("untracked write: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("untracked close: %v", err)
	}

	if err := dao.batcher.FlushNow(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Tracked namespace must have its row.
	live, _ := dao.LookupLive(ctx, "/tracked", "/tracked/a.bin")
	if live == nil {
		t.Fatal("tracked namespace missing live row")
	}
	// Untracked namespace must have NO rows.
	var n int64
	db.Model(&ObjectMetadataRow{}).Where("namespace = ?", "/untracked").Count(&n)
	if n != 0 {
		t.Fatalf("untracked namespace has %d rows; expected 0", n)
	}
}

// ============================================================
// P3.5 — pruner Start/Stop lifecycle
// ============================================================

// TestPruner_StartTickDeleteStop — the pruner's goroutine, started
// with a short interval, actually fires onePass on the timer and
// the IncDeleted hook reflects the deletions. Then Stop returns
// promptly.
func TestPruner_StartTickDeleteStop(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()

	// Plant 5 aged rows in /x.
	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	for i := 0; i < 5; i++ {
		if err := db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("p-%d", i), Namespace: "/x",
			ObjectPath: fmt.Sprintf("/x/%d", i), EventType: "commit", EventTS: old,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	rd := 1 // 1-day retention; all 5 rows are aged out
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/x",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	// 50ms interval so the timer fires twice in well under a sec.
	pruner := newObjectMetadataPruner(d, exports, 50*time.Millisecond, 100)
	var totalDeleted atomic.Int64
	pruner.SetHooks(PrunerHooks{
		IncDeleted:          func(_ string, n int64) { totalDeleted.Add(n) },
		ObservePassDuration: func(time.Duration) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pruner.Start(ctx)

	// Wait up to a second for the first pass.
	deadline := time.After(2 * time.Second)
	for {
		if totalDeleted.Load() == 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("pruner did not delete in time; deleted=%d", totalDeleted.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Stop must return promptly (within, say, a few timer
	// intervals); flakily slow Stop is its own bug.
	stopDone := make(chan struct{})
	go func() { pruner.Stop(); close(stopDone) }()
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("pruner.Stop did not return within 1s")
	}
}

// ============================================================
// P3.6 — SHA-256 ETag round-trips into DAO row
// ============================================================

// TestEtagPolicySHA256_PersistedToDB confirms that when POSC's
// EtagPolicy=sha256 is on and a commit fires the RecordCommit close
// hook, the resulting object_metadata row carries the sha256 digest
// AND etag_source='origin'. This locks down the contract: the
// origin-supplied ETag round-trips end to end, not just to the close
// hook.
func TestEtagPolicySHA256_PersistedToDB(t *testing.T) {
	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)
	db := newObjectMetadataTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batcher := newSQLiteBatcher(ctx, db, 32, 20*time.Millisecond)
	defer batcher.Stop()
	dao := newObjectMetadataDAO(db, batcher)

	aferoFs := newAferoFileSystem(autoFs, "/exp", nil)
	posc := newPoscFileSystem(ctx, aferoFs, ".pelican-posc", time.Hour, 19*time.Minute)
	posc.SetTouchFS(autoFs)
	posc.SetEtagPolicy("sha256")
	posc.SetCloseHook(RecordCommitCloseHook(dao, "/exp", false))
	defer posc.Stop()

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})
	f, err := posc.OpenFile(uctx, "/sha256.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	payload := []byte("hash me end-to-end")
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := dao.batcher.FlushNow(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	live, _ := dao.LookupLive(ctx, "/exp", "/exp/sha256.bin")
	if live == nil {
		t.Fatal("no live row after sha256 commit")
	}
	expected := "sha256-" + hexSHA256(payload)
	if live.ETag != expected {
		t.Fatalf("DAO etag = %q\n         want = %q", live.ETag, expected)
	}
	if live.EtagSource != "origin" {
		t.Fatalf("etag_source = %q, want 'origin'", live.EtagSource)
	}
}

// Suppress unused-import warnings on minimal-test branches.
var (
	_ = io.Discard
	_ sync.Mutex
)
