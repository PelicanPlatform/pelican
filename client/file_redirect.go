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
	"slices"
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

var (
	fileRootsMu   sync.Mutex
	fileRootsRaw  []string // the raw config the open roots were built from
	fileRootsOpen []fileRedirectRoot

	fileClientsMu sync.Mutex
	fileClients   = map[*http.Client]*http.Client{}
)

// allowedFileRedirectRoots opens each configured root and keeps it open.
// Roots that cannot be opened are dropped with a warning rather than
// silently widening or narrowing the allowlist.
//
// The result is memoised against the raw config rather than computed once,
// so a long-lived process that reloads its configuration picks up the change
// -- and so tests can set the parameter without fighting a sync.Once.
func allowedFileRedirectRoots() []fileRedirectRoot {
	raw := param.Client_FileRedirectRoots.GetStringSlice()

	fileRootsMu.Lock()
	defer fileRootsMu.Unlock()
	if slices.Equal(raw, fileRootsRaw) {
		return fileRootsOpen
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

	for _, previous := range fileRootsOpen {
		_ = previous.root.Close()
	}
	if len(opened) > 0 {
		log.Debugf("Will follow file:// redirects under %v", raw)
	}
	fileRootsRaw = slices.Clone(raw)
	fileRootsOpen = opened
	return fileRootsOpen
}

// closeFileRedirectRoots releases the open roots.  A root holds its
// directory open, which on Windows keeps the directory from being removed.
func closeFileRedirectRoots() {
	fileRootsMu.Lock()
	defer fileRootsMu.Unlock()
	for _, r := range fileRootsOpen {
		_ = r.root.Close()
	}
	fileRootsRaw, fileRootsOpen = nil, nil
}

// fileRedirectsEnabled reports whether any root is configured.
func fileRedirectsEnabled() bool { return len(allowedFileRedirectRoots()) > 0 }

// setAcceptRedirectHeader advertises the non-HTTP redirect schemes this
// client can follow.  A cache sends such a redirect only to a client that
// asked for it, so staying silent is what keeps the default safe.
func setAcceptRedirectHeader(req *http.Request) {
	if fileRedirectsEnabled() {
		req.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFile)
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

// fileRedirectTransport serves file:// URLs from the configured roots.  It is
// registered on a dedicated transport, not the shared one, so only object
// transfers can follow such a redirect -- a director or registry API call
// cannot.
type fileRedirectTransport struct{}

func (fileRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
	roots := allowedFileRedirectRoots()
	if len(roots) == 0 {
		return deny(http.StatusForbidden, "file:// redirects are not enabled")
	}
	root, rel, ok := relativeToRoot(requested, roots)
	if !ok {
		return deny(http.StatusForbidden, "path is outside Client.FileRedirectRoots")
	}

	// From here the root enforces containment.  A path that leaves the tree
	// fails with an escape error rather than fs.ErrNotExist, which is what
	// separates "you may not look there" from "the object is gone" -- worth
	// distinguishing, since the second is what an eviction from the shared
	// filesystem looks like.
	info, err := root.Stat(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return deny(http.StatusNotFound, "no such file")
		}
		return deny(http.StatusForbidden, "path is outside Client.FileRedirectRoots")
	}
	if !info.Mode().IsRegular() {
		return deny(http.StatusForbidden, "not a regular file")
	}
	f, err := root.Open(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return deny(http.StatusNotFound, "no such file")
		}
		return deny(http.StatusForbidden, "cannot open file")
	}

	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		Request:       req,
		Header:        header,
		ContentLength: info.Size(),
		Body:          f,
	}, nil
}

// withFileRedirects returns a client that can follow file:// redirects,
// reusing base's transport (and therefore its connection pool) for
// everything else.  When no roots are configured it returns base unchanged,
// so the default path is untouched.
func withFileRedirects(base *http.Client) *http.Client {
	if !fileRedirectsEnabled() || base == nil {
		return base
	}
	fileClientsMu.Lock()
	defer fileClientsMu.Unlock()
	if existing, ok := fileClients[base]; ok {
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
	cloned.RegisterProtocol("file", fileRedirectTransport{})
	derived := &http.Client{
		Transport:     cloned,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
	fileClients[base] = derived
	return derived
}
