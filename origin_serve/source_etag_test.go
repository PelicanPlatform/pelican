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

// File source_etag_test.go verifies the end-to-end path for the
// source-etag object-metadata attribute:
//
//   1. RecordCommit persists in.SourceEtag onto the live row and
//      clears it when a subsequent commit carries an empty value.
//   2. The TPC handler's context-stashing helper survives an OpenFile
//      round-trip so RecordCommitCloseHook sees it.
//   3. aferoFile.DeadProps surfaces the stored source_etag via the
//      Pelican DAV property namespace, and Patch refuses to modify it.

package origin_serve

import (
	"context"
	"encoding/xml"
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// TestRecordCommit_PersistsAndClearsSourceEtag drives RecordCommit twice
// — once as a TPC commit (with a source ETag) and once as a direct PUT
// — and asserts the live row's source_etag column transitions from
// the stored value back to NULL.
func TestRecordCommit_PersistsAndClearsSourceEtag(t *testing.T) {
	d, _, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	base := ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/x.bin",
		Size:         42,
		ETag:         `"local"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC().Round(time.Millisecond),
		Actor:        "carol",
	}

	// TPC-flavoured commit: source ETag lands.
	tpc := base
	tpc.SourceEtag = `"remote-abc"`
	if err := d.RecordCommit(ctx, tpc); err != nil {
		t.Fatalf("RecordCommit tpc: %v", err)
	}
	live, err := d.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if err != nil || live == nil {
		t.Fatalf("live lookup after tpc: row=%v err=%v", live, err)
	}
	if live.SourceEtag == nil || *live.SourceEtag != `"remote-abc"` {
		t.Fatalf("source_etag after tpc = %v, want %q", live.SourceEtag, `"remote-abc"`)
	}

	// Direct PUT: no source ETag. The excluded.source_etag rider in
	// the UPSERT is what clears the previous value.
	put := base
	put.ETag = `"local-2"`
	put.SourceEtag = ""
	if err := d.RecordCommit(ctx, put); err != nil {
		t.Fatalf("RecordCommit put: %v", err)
	}
	live, err = d.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if err != nil || live == nil {
		t.Fatalf("live lookup after put: row=%v err=%v", live, err)
	}
	if live.SourceEtag != nil {
		t.Fatalf("source_etag after direct PUT = %q, want NULL", *live.SourceEtag)
	}
	if live.ETag != `"local-2"` {
		t.Fatalf("etag after put = %q, want %q", live.ETag, `"local-2"`)
	}
}

// TestRecordExternalChange_ClearsSourceEtag confirms that an out-of-band
// modification clears the stored TPC source ETag, matching the documented
// contract on the column. Otherwise a stale upstream ETag would be served on
// PROPFIND and a sync client could wrongly skip re-fetching a changed object.
func TestRecordExternalChange_ClearsSourceEtag(t *testing.T) {
	d, _, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	base := ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/x.bin",
		Size:         42,
		ETag:         `"local"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC().Round(time.Millisecond),
		Actor:        "carol",
	}

	// TPC commit stores an upstream source ETag on the live row.
	tpc := base
	tpc.SourceEtag = `"remote-abc"`
	if err := d.RecordCommit(ctx, tpc); err != nil {
		t.Fatalf("RecordCommit tpc: %v", err)
	}
	live, err := d.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if err != nil || live == nil {
		t.Fatalf("live lookup after tpc: row=%v err=%v", live, err)
	}
	if live.SourceEtag == nil || *live.SourceEtag != `"remote-abc"` {
		t.Fatalf("source_etag after tpc = %v, want %q", live.SourceEtag, `"remote-abc"`)
	}

	// Out-of-band modification observed via Stat: a different ETag, no source
	// ETag. The stale upstream value must be cleared.
	ext := base
	ext.ETag = `"changed-out-of-band"`
	if err := d.RecordExternalChange(ctx, ext); err != nil {
		t.Fatalf("RecordExternalChange: %v", err)
	}
	// RecordExternalChange is best-effort (async); force the write behind it.
	_ = d.batcher.FlushNow(ctx)
	live, err = d.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if err != nil || live == nil {
		t.Fatalf("live lookup after external change: row=%v err=%v", live, err)
	}
	if live.SourceEtag != nil {
		t.Fatalf("source_etag after external change = %q, want NULL", *live.SourceEtag)
	}
	if live.ETag != `"changed-out-of-band"` {
		t.Fatalf("etag after external change = %q, want %q", live.ETag, `"changed-out-of-band"`)
	}
}

// TestSourceEtagContextRoundtrip locks the withSourceEtag /
// sourceEtagFromContext helpers so the TPC handler can rely on them.
func TestSourceEtagContextRoundtrip(t *testing.T) {
	ctx := context.Background()
	if got := sourceEtagFromContext(ctx); got != "" {
		t.Fatalf("bare ctx source etag = %q, want empty", got)
	}
	ctx2 := withSourceEtag(ctx, `"upstream-1"`)
	if got := sourceEtagFromContext(ctx2); got != `"upstream-1"` {
		t.Fatalf("stashed etag = %q, want %q", got, `"upstream-1"`)
	}
	// Empty value is a no-op so callers can pass getResp.Header.Get()
	// unconditionally without a nil check.
	ctx3 := withSourceEtag(ctx, "")
	if got := sourceEtagFromContext(ctx3); got != "" {
		t.Fatalf("empty stash produced %q, want empty", got)
	}
}

// TestAferoFile_DeadProps_ExposesSourceEtag seeds a live row via
// RecordCommit, opens the object through aferoFileSystem (which
// requires observation to be wired), and asserts DeadProps returns
// the expected Pelican property.
func TestAferoFile_DeadProps_ExposesSourceEtag(t *testing.T) {
	d, _, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/data/x.bin", []byte("payload"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	afs := newAferoFileSystem(mem, "", nil)
	afs.setObservation(&observationConfig{
		namespace: "/exp",
		dao:       d,
		cache:     newObservationCache(0),
	})

	// Record a commit with a source ETag so the live row exists.
	in := ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/x.bin",
		Size:         7,
		ETag:         `"local"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC(),
		SourceEtag:   `"upstream-9"`,
	}
	if err := d.RecordCommit(ctx, in); err != nil {
		t.Fatalf("RecordCommit: %v", err)
	}

	f, err := afs.OpenFile(ctx, "/data/x.bin", 0, 0)
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
		t.Fatalf("expected source-etag property; got %v", props)
	}
	// InnerXML holds XML-escaped bytes. The value here has no
	// special chars so it round-trips verbatim.
	if string(prop.InnerXML) != `"upstream-9"` {
		t.Fatalf("source-etag InnerXML = %q, want %q", prop.InnerXML, `"upstream-9"`)
	}
}

// TestAferoFile_DeadProps_XMLEscape verifies that ETag values
// containing XML metacharacters don't produce malformed responses.
// HTTP allows any octet in ETag values (RFC 7232), so we defend
// against a mischievous or misconfigured source.
func TestAferoFile_DeadProps_XMLEscape(t *testing.T) {
	d, _, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/data/x.bin", []byte("payload"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	afs := newAferoFileSystem(mem, "", nil)
	afs.setObservation(&observationConfig{
		namespace: "/exp",
		dao:       d,
		cache:     newObservationCache(0),
	})

	nasty := `"tag<with&meta>chars"`
	if err := d.RecordCommit(ctx, ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/x.bin",
		Size:         1,
		ETag:         `"local"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC(),
		SourceEtag:   nasty,
	}); err != nil {
		t.Fatalf("RecordCommit: %v", err)
	}

	f, err := afs.OpenFile(ctx, "/data/x.bin", 0, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	props, err := f.(webdav.DeadPropsHolder).DeadProps()
	if err != nil {
		t.Fatalf("DeadProps: %v", err)
	}
	got := string(props[xml.Name{Space: PelicanDAVNamespace, Local: PropSourceEtag}].InnerXML)
	// Only <, >, & get escaped in element text; " stays as-is
	// because the property is element content, not an attribute
	// value. See xmlEscapeInto for the rationale.
	want := `"tag&lt;with&amp;meta&gt;chars"`
	if got != want {
		t.Fatalf("InnerXML = %q, want %q", got, want)
	}
}

// TestAferoFile_DeadProps_NoObservationEmpty confirms the type stays
// silent when observation is off — no props emitted, no error.
func TestAferoFile_DeadProps_NoObservationEmpty(t *testing.T) {
	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/data/y.bin", []byte("payload"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	afs := newAferoFileSystem(mem, "", nil)
	f, err := afs.OpenFile(context.Background(), "/data/y.bin", 0, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	props, err := f.(webdav.DeadPropsHolder).DeadProps()
	if err != nil {
		t.Fatalf("DeadProps: %v", err)
	}
	if len(props) != 0 {
		t.Fatalf("expected empty props with no observation, got %v", props)
	}
}

// TestAferoFile_Patch_RejectsWrites confirms Pelican dead properties
// are read-only. PROPPATCH targets get a 409.
func TestAferoFile_Patch_RejectsWrites(t *testing.T) {
	mem := afero.NewMemMapFs()
	_ = afero.WriteFile(mem, "/x.bin", []byte("payload"), 0o644)
	afs := newAferoFileSystem(mem, "", nil)
	f, err := afs.OpenFile(context.Background(), "/x.bin", 0, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	patches := []webdav.Proppatch{{
		Props: []webdav.Property{{
			XMLName: xml.Name{Space: PelicanDAVNamespace, Local: PropSourceEtag},
		}},
	}}
	pstats, err := f.(webdav.DeadPropsHolder).Patch(patches)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(pstats) != 1 || pstats[0].Status != 409 {
		t.Fatalf("expected 1 propstat with status 409, got %+v", pstats)
	}
}
