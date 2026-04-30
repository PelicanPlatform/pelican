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
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// newTestPosc creates a POSC layer over a fresh afero in-memory filesystem
// for testing. The returned cleanup function stops the expiry goroutine.
func newTestPosc(t *testing.T) (ctx context.Context, p *poscFileSystem, mem afero.Fs, cleanup func()) {
	t.Helper()
	mem = afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	p = newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	return ctx, p, mem, func() {
		cancel()
		p.Stop()
	}
}

func TestPoscPathFiltering(t *testing.T) {
	ctx, p, _, cleanup := newTestPosc(t)
	defer cleanup()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"exact prefix", "/.pelican-posc", true},
		{"under prefix", "/.pelican-posc/alice/in_progress.foo", true},
		{"normalized", "//.pelican-posc//x", true},
		{"sibling", "/.pelican-posc-other", false},
		{"unrelated", "/foo/bar", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.inPoscDir(tt.path); got != tt.want {
				t.Errorf("inPoscDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
	_ = ctx
}

func TestPoscOpenWriteCloseCommit(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()

	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	f, err := p.OpenFile(ctx, "/data/file.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	pf, ok := f.(*poscFile)
	if !ok {
		t.Fatalf("expected *poscFile, got %T", f)
	}
	if !strings.HasPrefix(pf.tempPath, "/.pelican-posc/alice/in_progress.") {
		t.Fatalf("temp path %q does not look like a POSC staging path", pf.tempPath)
	}

	// File should NOT yet be visible at the final path.
	if _, err := mem.Stat("/data/file.txt"); err == nil {
		t.Fatalf("final path visible before close")
	}

	if _, err := f.Write([]byte("hello, world\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// After close, the temp file is gone and the final file exists.
	if _, err := mem.Stat(pf.tempPath); err == nil {
		t.Fatalf("temp file %q still exists after close", pf.tempPath)
	}
	got, err := afero.ReadFile(mem, "/data/file.txt")
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(got) != "hello, world\n" {
		t.Fatalf("final content = %q", got)
	}

	if got := p.activePoscFiles(); got != 0 {
		t.Fatalf("active count = %d, want 0", got)
	}
}

func TestPoscAbandonedUploadDoesNotCommit(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()

	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	f, err := p.OpenFile(ctx, "/data/abandoned.bin", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("partial")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Simulate a client disconnect — the underlying file is closed but
	// we never invoked f.Close() at the POSC layer. This is the worst
	// case for "leaked staging files"; the expiry goroutine is what
	// catches it.
	pf := f.(*poscFile)
	if err := pf.File.Close(); err != nil {
		t.Fatalf("inner close: %v", err)
	}

	// The final path is not visible to clients.
	if _, err := mem.Stat("/data/abandoned.bin"); err == nil {
		t.Fatal("final path visible after abandoned upload")
	}
	// The staging file IS still present (the expirer would clean it
	// up once it ages past FileTimeout).
	if _, err := mem.Stat(pf.tempPath); err != nil {
		t.Fatalf("staging file vanished: %v", err)
	}
}

func TestPoscFinalPathIsADirectoryPropagatesError(t *testing.T) {
	// MemMapFs does not match POSIX rename-onto-directory semantics, so
	// run this against a real OS filesystem rooted in a tempdir.
	tmp := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmp)
	inner := newAferoFileSystem(osFs, "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer p.Stop()

	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	if err := osFs.MkdirAll("/data/conflict", 0755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	f, err := p.OpenFile(ctx, "/data/conflict", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("oops")); err != nil {
		t.Fatalf("write: %v", err)
	}

	closeErr := f.Close()
	if closeErr == nil {
		t.Fatal("expected close to fail when destination is a directory")
	}

	pf := f.(*poscFile)
	if _, err := osFs.Stat(pf.tempPath); err == nil {
		t.Fatalf("staging file %q still present after failed commit", pf.tempPath)
	}
}

func TestPoscReadsFallThrough(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()

	if err := afero.WriteFile(mem, "/data/already.txt", []byte("preexisting"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	f, err := p.OpenFile(ctx, "/data/already.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile readonly: %v", err)
	}
	defer f.Close()

	if _, isPosc := f.(*poscFile); isPosc {
		t.Fatal("read-only OpenFile should not return *poscFile")
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "preexisting" {
		t.Fatalf("got %q", buf)
	}
}

func TestPoscDirectoryHidden(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()

	// Create the posc dir directly via the inner filesystem so we can
	// test that POSC hides it from above.
	if err := mem.MkdirAll("/.pelican-posc/alice", 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := afero.WriteFile(mem, "/.pelican-posc/alice/in_progress.test", []byte("x"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if _, err := p.Stat(ctx, "/.pelican-posc"); err == nil || !errIsNotExist(err) {
		t.Fatalf("Stat on posc dir = %v, want ENOENT-equivalent", err)
	}
	if _, err := p.OpenFile(ctx, "/.pelican-posc/alice/in_progress.test", os.O_RDONLY, 0); err == nil || !errIsNotExist(err) {
		t.Fatalf("Open inside posc dir = %v, want ENOENT-equivalent", err)
	}
	if err := p.RemoveAll(ctx, "/.pelican-posc"); err == nil || !errIsNotExist(err) {
		t.Fatalf("RemoveAll on posc dir = %v, want ENOENT-equivalent", err)
	}
	if err := p.Mkdir(ctx, "/.pelican-posc/another", 0755); err == nil || !errIsEIO(err) {
		t.Fatalf("Mkdir inside posc dir = %v, want EIO", err)
	}
	if err := p.Rename(ctx, "/.pelican-posc/alice/in_progress.test", "/data/exfil"); err == nil || !errIsNotExist(err) {
		t.Fatalf("Rename out of posc dir = %v, want ENOENT-equivalent", err)
	}
}

func TestPoscPerUserSubdirCreated(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	f, err := p.OpenFile(ctx, "/data/x.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	info, err := mem.Stat("/.pelican-posc/alice")
	if err != nil {
		t.Fatalf("per-user posc dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("/.pelican-posc/alice is not a directory")
	}
}

func TestPoscCloseHookFires(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	var (
		mu      sync.Mutex
		hookFor string
		hookSz  int64
	)
	p.SetCloseHook(func(_ context.Context, finalPath string, info os.FileInfo) error {
		mu.Lock()
		defer mu.Unlock()
		hookFor = finalPath
		if info != nil {
			hookSz = info.Size()
		}
		return nil
	})

	f, err := p.OpenFile(ctx, "/data/hooked.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if hookFor != "/data/hooked.bin" {
		t.Fatalf("hookFor = %q", hookFor)
	}
	if hookSz != 10 {
		t.Fatalf("hookSz = %d (want 10)", hookSz)
	}
	_ = mem
}

func TestPoscCloseHookFailureReturnsError(t *testing.T) {
	ctx, p, _, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	hookErr := errors.New("metadata sink rejected")
	p.SetCloseHook(func(context.Context, string, os.FileInfo) error { return hookErr })

	f, err := p.OpenFile(ctx, "/data/will-fail.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); !errors.Is(err, hookErr) {
		t.Fatalf("close: %v, want %v", err, hookErr)
	}
}

// TestPoscCloseHookFailureRollsBackFinal — when the close hook fails,
// POSC must remove the just-renamed final object so the storage state
// matches the publish state ("metadata service refused → object not
// visible"). This is the rollback the design doc names.
func TestPoscCloseHookFailureRollsBackFinal(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	p.SetCloseHook(func(context.Context, string, os.FileInfo) error {
		return errors.New("metadata refused")
	})

	f, err := p.OpenFile(ctx, "/data/rolled-back.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("expected close to return the hook error")
	}
	if _, err := mem.Stat("/data/rolled-back.bin"); err == nil {
		t.Fatal("expected POSC rollback to have removed final object")
	}
}

// TestPoscRollbackFailureFiresMetric — we cover the unhappy branch
// where the rollback delete itself fails (eg because the final path
// has been recreated as a directory by something else between rename
// and rollback). The IncRollbackFailed hook must fire exactly once.
func TestPoscRollbackFailureFiresMetric(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	var rollbackFailedCount atomic.Int64
	p.SetMetricsHooks(&PoscMetricsHooks{
		IncRollbackFailed: func() { rollbackFailedCount.Add(1) },
	})
	p.SetCloseHook(func(context.Context, string, os.FileInfo) error {
		return errors.New("metadata refused")
	})

	f, err := p.OpenFile(ctx, "/data/sneaky.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("p")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Replace the inner FS with a wrapper that fails RemoveAll on
	// the final path, simulating "the rollback couldn't run." The
	// rename must still succeed first; after that, RemoveAll must
	// error so the IncRollbackFailed hook fires.
	p.inner = &removeAllFailFs{FileSystem: p.inner, failPath: "/data/sneaky.bin"}

	if err := f.Close(); err == nil {
		t.Fatal("expected close to return the hook error")
	}
	if got := rollbackFailedCount.Load(); got != 1 {
		t.Fatalf("IncRollbackFailed = %d, want 1", got)
	}
	_ = mem
}

// removeAllFailFs is a webdav.FileSystem decorator whose RemoveAll
// fails on a configured path; everything else passes through.
type removeAllFailFs struct {
	webdav.FileSystem
	failPath string
}

func (r *removeAllFailFs) RemoveAll(ctx context.Context, name string) error {
	if name == r.failPath {
		return errors.New("synthetic rollback failure")
	}
	return r.FileSystem.RemoveAll(ctx, name)
}

func TestPoscExpiryRemovesStaleStagingFiles(t *testing.T) {
	mem := afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a tight timeout so expireFiles deletes immediately.
	p := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Nanosecond, time.Microsecond)
	defer p.Stop()

	// Plant a stale temp file directly on the memfs.
	if err := mem.MkdirAll("/.pelican-posc/alice", 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	stalePath := "/.pelican-posc/alice/in_progress.123.456"
	if err := afero.WriteFile(mem, stalePath, []byte("x"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	pastMTime := time.Now().Add(-2 * time.Hour)
	if err := mem.Chtimes(stalePath, pastMTime, pastMTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Drive expiry directly rather than waiting on the 5s ticker.
	p.expireFiles(ctx)

	if _, err := mem.Stat(stalePath); err == nil {
		t.Fatalf("stale staging file %q still present", stalePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unexpected error checking stale path: %v", err)
	}
}

// TestPoscContentLengthMismatchAborts confirms the size-verification
// step refuses to commit when the staged file's actual size does not
// match a Content-Length the request stashed on the context.
func TestPoscContentLengthMismatchAborts(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})
	// Tell POSC the client *promised* 1000 bytes, then write only 1.
	ctx = withExpectedContentLength(ctx, 1000)

	f, err := p.OpenFile(ctx, "/data/short.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("expected close to fail when staged size != Content-Length")
	}
	// Final must NOT be visible.
	if _, err := mem.Stat("/data/short.bin"); err == nil {
		t.Fatal("expected /data/short.bin to be absent after size mismatch")
	}
}

// TestPoscContentLengthMatchCommits is the matching happy-path: when
// the staged size matches the declared Content-Length, the commit
// proceeds normally.
func TestPoscContentLengthMatchCommits(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})
	body := []byte("eight!!!")
	ctx = withExpectedContentLength(ctx, int64(len(body)))

	f, err := p.OpenFile(ctx, "/data/exact.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, err := afero.ReadFile(mem, "/data/exact.bin")
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("final content mismatch")
	}
}

// TestPoscFinalPermMatchesRequested verifies the post-rename file
// inherits the perm passed to OpenFile, not the historic 0600
// staging-only perm. Run against a real OsFs because MemMapFs does
// not faithfully track perm bits.
func TestPoscFinalPermMatchesRequested(t *testing.T) {
	tmp := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmp)
	autoFs := newAutoCreateDirFs(osFs)
	inner := newAferoFileSystem(autoFs, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, 19*time.Minute)
	defer p.Stop()

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})
	f, err := p.OpenFile(uctx, "/data/perm-check.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("p")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := osFs.Stat("/data/perm-check.bin")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The exact mode after umask varies by environment; assert that
	// at minimum group/other read bits are intact (so this is *not*
	// 0600 anymore).
	mode := info.Mode().Perm()
	if mode&0044 == 0 {
		t.Fatalf("post-rename mode = %#o; expected at least 0644 (group+other readable)", mode)
	}
}

// TestPoscKeepaliveUpdatesMtime verifies that touchOpenFiles, the
// keepalive routine fired periodically by expireLoop, refreshes the
// staging file's filesystem mtime via Chtimes. Without this, an
// active upload that pauses writing for longer than `keepalive` would
// be erroneously reaped by the very next expiry pass.
func TestPoscKeepaliveUpdatesMtime(t *testing.T) {
	mem := afero.NewMemMapFs()
	inner := newAferoFileSystem(mem, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newPoscFileSystem(ctx, inner, ".pelican-posc", time.Hour, time.Microsecond)
	p.SetTouchFS(mem)
	defer p.Stop()

	uctx := setUserInfo(ctx, &userInfo{User: "alice"})
	f, err := p.OpenFile(uctx, "/data/keepalive.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()
	pf := f.(*poscFile)

	// Force the staging file's mtime far into the past so a fresh
	// keepalive pass has something to update.
	past := time.Now().Add(-1 * time.Hour)
	if err := mem.Chtimes(pf.tempPath, past, past); err != nil {
		t.Fatalf("setup chtimes: %v", err)
	}
	// Mark the in-memory mtime stale so touchIfStale fires.
	pf.mu.Lock()
	pf.mtime = past
	pf.mu.Unlock()

	p.touchOpenFiles(ctx)

	info, err := mem.Stat(pf.tempPath)
	if err != nil {
		t.Fatalf("post-touch stat: %v", err)
	}
	if !info.ModTime().After(past.Add(time.Minute)) {
		t.Fatalf("keepalive did not refresh mtime: still %v", info.ModTime())
	}
}

func TestPoscExpiryDoesNotRemoveActiveFile(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	f, err := p.OpenFile(ctx, "/data/inflight.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	pf := f.(*poscFile)

	// Drive expiry; the file mtime is recent (just created).
	p.expireFiles(ctx)
	if _, err := mem.Stat(pf.tempPath); err != nil {
		t.Fatalf("expiry erroneously removed active file: %v", err)
	}
}

func TestPoscConcurrentCreatesUseDistinctTempFiles(t *testing.T) {
	ctx, p, mem, cleanup := newTestPosc(t)
	defer cleanup()
	ctx = setUserInfo(ctx, &userInfo{User: "alice"})

	const N = 8
	var (
		wg    sync.WaitGroup
		paths = make([]string, N)
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f, err := p.OpenFile(ctx, "/concurrent/x.bin", os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				t.Errorf("OpenFile: %v", err)
				return
			}
			pf := f.(*poscFile)
			paths[i] = pf.tempPath
			_ = f.Close()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool)
	for _, p := range paths {
		if p == "" {
			t.Fatal("missing temp path from a goroutine")
		}
		if seen[p] {
			t.Fatalf("temp path %q reused across goroutines", p)
		}
		seen[p] = true
	}

	// All N goroutines raced for the same final path; exactly one
	// should win — the rest see EEXIST (or rename failure) and the
	// final path resolves to one of them.
	final, err := afero.ReadFile(mem, "/concurrent/x.bin")
	if err != nil {
		t.Fatalf("final missing: %v", err)
	}
	_ = final
}

// errIsNotExist treats both wrapped os.ErrNotExist and an explicit syscall.ENOENT as ENOENT-equivalent.
func errIsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if errors.Is(err, syscall.ENOENT) {
		return true
	}
	var pe *os.PathError
	if errors.As(err, &pe) && pe.Err == syscall.ENOENT {
		return true
	}
	return false
}

func errIsEIO(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EIO) {
		return true
	}
	var pe *os.PathError
	if errors.As(err, &pe) && pe.Err == syscall.EIO {
		return true
	}
	return false
}

func mustReadDir(t *testing.T, fs afero.Fs, dir string) []os.FileInfo {
	t.Helper()
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		t.Fatalf("readdir %q: %v", dir, err)
	}
	return entries
}

func mustReadAll(t *testing.T, fs afero.Fs, p string) []byte {
	t.Helper()
	b, err := afero.ReadFile(fs, p)
	if err != nil {
		t.Fatalf("readfile %q: %v", p, err)
	}
	return b
}

// keep linter happy: ensure helpers compile when not all tests use them
var (
	_ = path.Join
	_ = mustReadDir
	_ = mustReadAll
)
