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

package server_structs

import (
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// AcceptRedirectHeader is the request header through which a client tells a
// cache which non-HTTP URL schemes it is able to follow if redirected to one.
// Its value is a comma-separated list of schemes.
//
// It lives here, rather than as a literal on each side, because the client
// writing it and the cache reading it are in different packages and a
// mismatch would not fail to compile -- it would silently disable the
// feature, or worse, silently enable a redirect the client cannot follow.
//
// See docs/pelican-http-headers.md.
const AcceptRedirectHeader = "X-Pelican-Accept-Redirect"

// RedirectSchemeFile is the scheme of a redirect to an object on a
// filesystem the client shares with the cache.  A client does not advertise
// it bare; see RedirectSchemeFileVerified.
const RedirectSchemeFile = "file"

// RedirectSchemeFileVerified is advertised by a client that can read objects
// straight off a filesystem it shares with the cache, and that will first
// check that the directory it reaches is the one the cache means (see
// FileTargetHeader).  A cache sends a file:// redirect only to a client that
// advertises it.
//
// The check is what makes following such a redirect safe when someone other
// than the cache can rearrange the directories above its own: without it, a
// user who could rename the cache's directory away and put one of their own
// in its place would have every redirected client read their files instead.
const RedirectSchemeFileVerified = "file-verified"

// FileTargetHeader accompanies a file:// redirect.  It identifies the
// directory the redirected path lies in, so the client can check, before
// reading anything, that the directory at that path is the one the cache
// wrote to.  Its value is a FileTarget.
const FileTargetHeader = "X-Pelican-File-Target"

// FileTargetIdentityFile is where, below the directory a FileTarget names,
// the file holding its ID lies.
const FileTargetIdentityFile = "objects/.pelican-cache-id"

// FileTarget identifies the directory a file:// redirect points into: its
// absolute path as the cache sees it, its inode, and the ID the cache keeps
// in FileTargetIdentityFile there.
//
// The inode is what defeats a swapped directory: a user who renames the
// cache's directory away and puts their own in its place cannot give theirs
// the same inode, since the original still exists.  The ID tells apart a
// different filesystem mounted at the same path, whose directory could
// happen to have the same inode number.  The device number is left out:
// on a network filesystem it is assigned by each host's kernel when the
// filesystem is mounted, and differs from host to host.
type FileTarget struct {
	Root  string
	Inode uint64
	ID    string
}

// String encodes the target as a FileTargetHeader value, in the form of a
// URL query: "id=<id>&inode=<inode>&root=<percent-encoded path>".
func (t FileTarget) String() string {
	return url.Values{
		"root":  {t.Root},
		"inode": {strconv.FormatUint(t.Inode, 10)},
		"id":    {t.ID},
	}.Encode()
}

// ParseFileTarget decodes a FileTargetHeader value.
func ParseFileTarget(value string) (FileTarget, error) {
	values, err := url.ParseQuery(value)
	if err != nil {
		return FileTarget{}, errors.Wrap(err, "malformed file target")
	}
	t := FileTarget{Root: values.Get("root"), ID: values.Get("id")}
	if !filepath.IsAbs(t.Root) || filepath.Clean(t.Root) != t.Root {
		return FileTarget{}, errors.Errorf("file target root %q is not a clean absolute path", t.Root)
	}
	if t.ID == "" {
		return FileTarget{}, errors.New("file target has no ID")
	}
	if t.Inode, err = strconv.ParseUint(values.Get("inode"), 10, 64); err != nil || t.Inode == 0 {
		return FileTarget{}, errors.Errorf("file target inode %q is not a valid inode", values.Get("inode"))
	}
	return t, nil
}

// AcceptsRedirectScheme reports whether an X-Pelican-Accept-Redirect header
// value advertises the given scheme.
//
// http and https are deliberately not special-cased here: every client can
// follow those, so callers never need to ask about them, and answering "true"
// for an absent header would make the only interesting question -- did the
// client opt in? -- impossible to express.
//
// The answer is an assertion by the client about itself, which a server
// cannot verify.  That is exactly why an advertisement is required for these
// schemes: a cache must not direct a client to read a local path unless the
// client said it could.
func AcceptsRedirectScheme(headerValue, scheme string) bool {
	if scheme == "" {
		return false
	}
	for _, advertised := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(advertised), scheme) {
			return true
		}
	}
	return false
}
