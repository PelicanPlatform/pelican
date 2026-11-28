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

package client

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Following a file:// redirect means letting a cache tell this client to read
// a path off the local filesystem.  That inverts the usual trust direction:
// normally a cache can only hand us bytes it holds, whereas here a
// compromised or misconfigured one could point a transfer at any file the
// invoking user can read, and in the contexts Pelican runs in -- the client
// agent, HTCondor file transfer, a subsequent `object put` -- those bytes
// then move on somewhere.
//
// So this is off unless the operator names the roots it is allowed within.
// There is deliberately no separate on/off switch: the empty list is the
// off state, which makes "enabled but unscoped" unrepresentable.
//
// The scheme is only ever used for a storage tier the client already shares
// with the cache (a mounted filesystem the cache also writes to), so naming
// the mount point is a thing an operator can actually do.
//
// Within a root, the client also checks that the directory the redirect
// points into is the one the cache wrote to (server_structs.FileTarget):
// anyone who can rearrange a directory above the cache's could otherwise
// rename it away and put their own in its place, and every redirected
// client would read their files.  The check is made once per directory and
// transfer engine; the verified directory is then held open and every later
// object is opened relative to it, so a swap made after the check cannot
// reach that engine at all.
//
// All of this state -- the open roots, the verified directories, and the
// HTTP clients able to follow a file:// redirect -- belongs to a
// fileRedirector, which each TransferEngine owns and closes when it shuts
// down.

// fileRedirectRoot is one allowed root, held open.
//
// Containment is os.Root's: it resolves each path component against the open
// directory and refuses anything -- a "..", an absolute component, or a
// symlink -- that leaves the tree.  Letting the standard library do this,
// rather than resolving the path ourselves and comparing prefixes, also
// closes a time-of-check-to-time-of-use window: there is no gap between
// deciding a path is inside the root and opening it.
type fileRedirectRoot struct {
	root *os.Root
	// abs is the configured path made absolute, and canonical is that with
	// symlinks resolved.  Both exist only to work out which root a requested
	// absolute path belongs to and what the remainder is -- an operator may
	// name a root either way and the cache may send either.  Neither is
	// trusted for containment.
	abs       string
	canonical string
}

// fileRedirector holds what one transfer engine needs to follow file://
// redirects.  A nil fileRedirector follows none.
type fileRedirector struct {
	// mu guards the roots and the verified directories.  It is held across
	// the filesystem calls that open and check them, so two transfers
	// redirected into one directory check it once between them.
	mu       sync.Mutex
	rootsRaw []string // the raw config the open roots were built from
	roots    []fileRedirectRoot
	verified map[string]*verifiedFileTarget // by the directory's path, as the cache sent it

	clientsMu sync.Mutex
	clients   map[*http.Client]*http.Client
}

// verifiedFileTarget is a cache's shared-filesystem directory that an
// engine has checked against what the cache said it should be, held open.
type verifiedFileTarget struct {
	inode uint64
	id    string
	root  *os.Root
}

// fileTargetsVerifiable reports whether this platform can check a
// directory's inode; where it cannot, the client does not offer to follow
// file:// redirects at all.
const fileTargetsVerifiable = runtime.GOOS != "windows"

func newFileRedirector() *fileRedirector {
	return &fileRedirector{
		verified: map[string]*verifiedFileTarget{},
		clients:  map[*http.Client]*http.Client{},
	}
}

// openRoots opens each configured root and keeps it open.  Roots that
// cannot be opened are dropped with a warning rather than silently widening
// or narrowing the allowlist.
//
// The result is memoised against the raw config rather than computed once,
// so a long-lived engine whose configuration is reloaded picks up the change.
func (fr *fileRedirector) openRoots() []fileRedirectRoot {
	if fr == nil {
		return nil
	}
	raw := param.Client_FileRedirectRoots.GetStringSlice()

	fr.mu.Lock()
	defer fr.mu.Unlock()
	if slices.Equal(raw, fr.rootsRaw) {
		return fr.roots
	}

	opened := make([]fileRedirectRoot, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		abs, err := filepath.Abs(entry)
		if err != nil {
			log.Warnf("Ignoring Client.FileRedirectRoots entry %q: %v", entry, err)
			continue
		}
		root, err := os.OpenRoot(abs)
		if err != nil {
			log.Warnf("Ignoring Client.FileRedirectRoots entry %q: %v", entry, err)
			continue
		}
		canonical := abs
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			canonical = resolved
		}
		opened = append(opened, fileRedirectRoot{root: root, abs: abs, canonical: canonical})
	}

	// Directories verified under the previous roots are checked again under
	// the new ones.
	fr.closeLocked()
	if len(opened) > 0 {
		log.Debugf("Will follow file:// redirects under %v", raw)
	}
	fr.rootsRaw = slices.Clone(raw)
	fr.roots = opened
	return fr.roots
}

// close releases the open roots and verified directories.  Each holds its
// directory open, which on Windows keeps it from being removed.
func (fr *fileRedirector) close() {
	if fr == nil {
		return
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.closeLocked()
}

func (fr *fileRedirector) closeLocked() {
	for _, r := range fr.roots {
		_ = r.root.Close()
	}
	fr.rootsRaw, fr.roots = nil, nil
	fr.forgetVerifiedLocked()
}

// forgetVerified closes every verified directory, so that each is checked
// again on its next redirect.
func (fr *fileRedirector) forgetVerified() {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.forgetVerifiedLocked()
}

func (fr *fileRedirector) forgetVerifiedLocked() {
	for path, v := range fr.verified {
		_ = v.root.Close()
		delete(fr.verified, path)
	}
}

// errOutsideFileRoots marks a directory that is not under any configured
// root.
var errOutsideFileRoots = errors.New("outside Client.FileRedirectRoots")

// openVerified returns the directory target names, held open, checking
// first -- unless this engine already has -- that the directory at that path
// is the cache's: the inode it reports and the ID in its identity file.
// fresh reports that the check was made now.
func (fr *fileRedirector) openVerified(target server_structs.FileTarget, roots []fileRedirectRoot) (dir *os.Root, fresh bool, err error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if v, ok := fr.verified[target.Root]; ok && v.inode == target.Inode && v.id == target.ID {
		return v.root, false, nil
	}
	parent, rel, ok := relativeToRoot(target.Root, roots)
	if !ok {
		return nil, false, errOutsideFileRoots
	}
	dir, err = parent.OpenRoot(rel)
	if err != nil {
		return nil, false, fmt.Errorf("cannot open %s: %w", target.Root, err)
	}
	check := func() error {
		info, err := dir.Stat(".")
		if err != nil {
			return err
		}
		_, inode, ok := utils.FileVFSID(info)
		if !ok {
			return errors.New("this platform reports no inode to check")
		}
		if inode != target.Inode {
			return fmt.Errorf("its inode is %d, but the cache's is %d; it may have been replaced", inode, target.Inode)
		}
		id, err := dir.ReadFile(server_structs.FileTargetIdentityFile)
		if err != nil {
			return fmt.Errorf("cannot read its identity file: %w", err)
		}
		if strings.TrimSpace(string(id)) != target.ID {
			return errors.New("its identity file does not match the cache's; it is another directory")
		}
		return nil
	}
	if err := check(); err != nil {
		_ = dir.Close()
		return nil, false, fmt.Errorf("%s is not the cache's directory: %w", target.Root, err)
	}
	if previous, ok := fr.verified[target.Root]; ok {
		_ = previous.root.Close()
	}
	fr.verified[target.Root] = &verifiedFileTarget{inode: target.Inode, id: target.ID, root: dir}
	return dir, true, nil
}

// forget drops dir, if it is still the verified directory at path, so that
// the next redirect there checks again.
func (fr *fileRedirector) forget(path string, dir *os.Root) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if v, ok := fr.verified[path]; ok && v.root == dir {
		_ = v.root.Close()
		delete(fr.verified, path)
	}
}

// pathWithin returns requested relative to dir, if it lies below it.
func pathWithin(requested, dir string) (string, bool) {
	cleaned := filepath.Clean(requested)
	if !strings.HasPrefix(cleaned, dir+string(filepath.Separator)) {
		return "", false
	}
	return cleaned[len(dir)+1:], true
}

// enabled reports whether any root is configured.
func (fr *fileRedirector) enabled() bool { return len(fr.openRoots()) > 0 }

// advertise tells a cache, on req, which non-HTTP redirect schemes this
// engine can follow.  A cache sends such a redirect only to a client that
// asked for it, so staying silent is what keeps the default safe.  The
// client offers file:// only where it can check the directory it would read
// from, and says so.
func (fr *fileRedirector) advertise(req *http.Request) {
	if fileTargetsVerifiable && fr.enabled() {
		req.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFileVerified)
	}
}

// relativeToRoot picks the root a requested absolute path belongs to and
// returns the path relative to it.
//
// This only selects a candidate; it decides nothing about safety.  A path
// that matches a root's prefix lexically may still escape through a symlink,
// which is what the os.Root operations on the returned root catch.  That
// separation is what lets the matching here be lenient: when the lexical
// comparison fails, the requested path's directory is resolved and tried
// again, so a root reached through a symlinked mount point matches whichever
// spelling the cache happens to send.  Resolving an attacker-influenced path
// would be unsafe if containment depended on it, and it no longer does.
func relativeToRoot(requested string, roots []fileRedirectRoot) (*os.Root, string, bool) {
	match := func(candidate string) (*os.Root, string, bool) {
		for i := range roots {
			for _, base := range [...]string{roots[i].abs, roots[i].canonical} {
				if candidate == base {
					return roots[i].root, ".", true
				}
				if strings.HasPrefix(candidate, base+string(filepath.Separator)) {
					return roots[i].root, candidate[len(base)+1:], true
				}
			}
		}
		return nil, "", false
	}

	cleaned := filepath.Clean(requested)
	if root, rel, ok := match(cleaned); ok {
		return root, rel, true
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(cleaned)); err == nil {
		return match(filepath.Join(dir, filepath.Base(cleaned)))
	}
	return nil, "", false
}

// fileRedirectTransport serves file:// URLs from an engine's configured
// roots.  It is registered on a dedicated transport, not the shared one, so
// only object transfers can follow such a redirect -- a director or registry
// API call cannot.
type fileRedirectTransport struct{ fr *fileRedirector }

func (t fileRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deny := func(status int, reason string) (*http.Response, error) {
		log.Warnf("Refusing file:// redirect to %q: %s", req.URL.Path, reason)
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, reason),
			Proto:      "HTTP/1.1",
			Request:    req,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(reason)),
		}, nil
	}

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return deny(http.StatusMethodNotAllowed, "only GET is supported for file:// URLs")
	}
	// A file URL addresses the local filesystem; a host would mean some
	// other machine's, which we cannot satisfy.
	if req.URL.Host != "" && !strings.EqualFold(req.URL.Host, "localhost") {
		return deny(http.StatusForbidden, "file:// URL names a remote host")
	}

	// URL.Path is already percent-decoded; decoding it again would turn a
	// file named "a%41" into "aA".
	requested := utils.FileURLToPath(req.URL)
	roots := t.fr.openRoots()
	if len(roots) == 0 {
		return deny(http.StatusForbidden, "file:// redirects are not enabled")
	}

	// The redirect that brought us here says which directory the path lies
	// in; nothing is read until that directory is shown to be the cache's.
	if req.Response == nil {
		return deny(http.StatusForbidden, "file:// URL was not reached by a cache's redirect")
	}
	target, err := server_structs.ParseFileTarget(req.Response.Header.Get(server_structs.FileTargetHeader))
	if err != nil {
		return deny(http.StatusForbidden, "the cache did not say which directory the path lies in: "+err.Error())
	}
	rel, ok := pathWithin(requested, target.Root)
	if !ok {
		return deny(http.StatusForbidden, "path is outside the directory the cache named")
	}

	// A directory verified earlier is used as held; if it fails us (removed
	// on the server, say), it is checked afresh once.
	for {
		dir, fresh, err := t.fr.openVerified(target, roots)
		if errors.Is(err, errOutsideFileRoots) {
			return deny(http.StatusForbidden, "path is outside Client.FileRedirectRoots")
		}
		if err != nil {
			return deny(http.StatusForbidden, err.Error())
		}
		f, info, status, reason := openFileRedirectObject(dir, rel)
		if status != http.StatusOK && status != http.StatusNotFound && !fresh {
			t.fr.forget(target.Root, dir)
			continue
		}
		if status != http.StatusOK {
			return deny(status, reason)
		}
		return fileRedirectResponse(req, info, f), nil
	}
}

// openFileRedirectObject opens the object at rel below dir, which enforces
// containment.  A path that leaves the tree fails with an escape error
// rather than fs.ErrNotExist, which is what separates "you may not look
// there" from "the object is gone" -- worth distinguishing, since the second
// is what an eviction from the shared filesystem looks like.
//
// The file is looked at before it is opened only so that a FIFO is never
// opened (which would block); the size and the regular-file check that
// count come from the opened file itself.
func openFileRedirectObject(dir *os.Root, rel string) (*os.File, fs.FileInfo, int, string) {
	info, err := dir.Stat(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, http.StatusNotFound, "no such file"
		}
		return nil, nil, http.StatusForbidden, "path is outside the directory the cache named"
	}
	if !info.Mode().IsRegular() {
		return nil, nil, http.StatusForbidden, "not a regular file"
	}
	f, err := dir.Open(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, http.StatusNotFound, "no such file"
		}
		return nil, nil, http.StatusForbidden, "cannot open file"
	}
	if info, err = f.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, http.StatusForbidden, "not a regular file"
	}
	return f, info, http.StatusOK, ""
}

// fileRedirectValidators are the headers of the cache's redirect that
// describe the object rather than the redirect.  The file response carries
// them, so a client reading the file is told what it would have been told
// had the cache sent the bytes: an expected ETag and checksums are checked
// against them.
var fileRedirectValidators = []string{"ETag", "Digest", "Last-Modified", "Age", "Cache-Control"}

// fileRange returns the bytes from start to end, inclusive, that a Range
// header asks for in a file of size bytes.  Only a single range is
// understood -- all the client sends -- and any other header is answered
// with the whole file, as HTTP allows.  satisfiable is false for a range
// that starts past the end.
func fileRange(header string, size int64) (start, end int64, ranged, satisfiable bool) {
	whole := func() (int64, int64, bool, bool) { return 0, size - 1, false, true }
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return whole()
	}
	first, last, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return whole()
	}
	if first == "" { // the final n bytes
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return whole()
		}
		if size == 0 {
			return 0, 0, true, false
		}
		return max(size-n, 0), size - 1, true, true
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 {
		return whole()
	}
	end = size - 1
	if last != "" {
		e, err := strconv.ParseInt(last, 10, 64)
		if err != nil || e < start {
			return whole()
		}
		end = min(e, size-1)
	}
	if start >= size {
		return 0, 0, true, false
	}
	return start, end, true, true
}

// fileRedirectResponse answers req with the opened file, or the part of it
// that req's Range header asks for.
func fileRedirectResponse(req *http.Request, info fs.FileInfo, f *os.File) *http.Response {
	size := info.Size()
	header := http.Header{}
	if req.Response != nil {
		for _, name := range fileRedirectValidators {
			for _, v := range req.Response.Header.Values(name) {
				header.Add(name, v)
			}
		}
	}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("Accept-Ranges", "bytes")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Request:    req,
		Header:     header,
	}

	start, end, ranged, satisfiable := fileRange(req.Header.Get("Range"), size)
	if !satisfiable {
		_ = f.Close()
		header.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		header.Set("Content-Length", "0")
		resp.StatusCode, resp.Status = http.StatusRequestedRangeNotSatisfiable, "416 Requested Range Not Satisfiable"
		resp.Body = http.NoBody
		return resp
	}
	if ranged {
		header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		resp.StatusCode, resp.Status = http.StatusPartialContent, "206 Partial Content"
	}
	length := end - start + 1
	header.Set("Content-Length", strconv.FormatInt(length, 10))
	resp.ContentLength = length
	if req.Method == http.MethodHead {
		_ = f.Close()
		resp.Body = http.NoBody
		return resp
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.NewSectionReader(f, start, length), f}
	return resp
}

// httpClient returns a client that can follow file:// redirects, reusing
// base's transport (and therefore its connection pool) for everything else.
// When no roots are configured it returns base unchanged, so the default
// path is untouched.
func (fr *fileRedirector) httpClient(base *http.Client) *http.Client {
	if !fr.enabled() || base == nil {
		return base
	}
	fr.clientsMu.Lock()
	defer fr.clientsMu.Unlock()
	if existing, ok := fr.clients[base]; ok {
		return existing
	}
	// Only *http.Transport can register a per-scheme RoundTripper; anything
	// else (a test double, say) is left alone.
	transport, ok := base.Transport.(*http.Transport)
	if !ok {
		// Nothing to register on; leave the caller's client alone and do not
		// memoise, since the transport may differ next time.
		return base
	}
	cloned := transport.Clone()
	cloned.RegisterProtocol("file", fileRedirectTransport{fr: fr})
	derived := &http.Client{
		Transport:     cloned,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
	fr.clients[base] = derived
	return derived
}
