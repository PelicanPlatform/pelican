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

package local_cache

import (
	"context"
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

// TierTokenSource supplies the bearer token a tiering backend presents to its
// storage service.
//
// It is an interface, rather than a token file path threaded through the
// backend, so that a token acquired some other way -- an OAuth client
// credentials flow, say -- can be plugged in without the backend knowing.  A
// source is consulted on every request, so it must be cheap and must do its
// own caching and refreshing.
type TierTokenSource interface {
	// Token returns the current token, or "" to send no Authorization header.
	Token(ctx context.Context) (string, error)
}

// fileTokenSource reads the token from a file on every call, so a token that
// an external process rotates in place is picked up without a restart.  The
// file is small and in the page cache; re-reading it costs far less than the
// request it authorizes.
type fileTokenSource struct {
	path string
}

func (f fileTokenSource) Token(_ context.Context) (string, error) {
	if f.path == "" {
		return "", nil
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return "", errors.Wrap(err, "failed to read the tiering target's token file")
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		// A configured file that is empty is far more likely a rotation
		// caught halfway (truncate, then write) than a deliberate request
		// for anonymous access; sending none would only earn a 401.
		return "", errors.Errorf("the tiering target's token file %s is empty", f.path)
	}
	return token, nil
}

// webdavTierBackend implements TierBackend over plain WebDAV: PUT, ranged GET,
// HEAD, DELETE, MKCOL and PROPFIND.  It is written with dCache in mind, the
// WebDAV service a cache is most likely to tier to, but uses nothing
// dCache-specific.  It cannot issue redirect URLs, so its objects are proxied.
//
// It does not use gowebdav, which the origin's HTTPS backend and the client
// do: gowebdav takes no context, so a slow server could not be abandoned when
// the cache shuts down or a client goes away, and it hides the response
// headers this backend depends on -- the entity tag and the Content-Range of a
// conditional ranged read.
type webdavTierBackend struct {
	// root is the collection WebDavUrl names, which must already exist.
	// Everything the cache writes lives under root/prefix, and keys are
	// relative to that.
	root    *url.URL
	prefix  string
	client  *http.Client
	tokens  TierTokenSource
	display string

	// putClient sends uploads.  It differs from client only in waiting
	// longer for the response: an upload goes through the door, which
	// answers only once the pool has closed, flushed and checksummed the
	// file -- for a large object on a busy pool, far longer than the
	// transport's usual response-header timeout.  Timing out there would
	// remove a complete upload as a partial one and redo it.
	putClient *http.Client

	// knownDirs records collections (relative to root) this process has
	// created or found, so that an upload into an existing aa/bb directory
	// costs one PUT rather than a MKCOL per level.  It only grows -- by at
	// most 65536 + 256 entries for the cache's layout -- and is cleared for
	// a key whose PUT reports a missing parent.
	dirsMu    sync.Mutex
	knownDirs map[string]struct{}
}

var _ TierBackend = (*webdavTierBackend)(nil)

// webdavMaxListingBytes bounds a single PROPFIND response.  One collection in
// the cache's layout holds at most a few thousand entries; anything near this
// size is not a listing the cache produced.
const webdavMaxListingBytes = 64 << 20

// newWebDAVTierBackend builds the backend for cfg.  No I/O happens here.
func newWebDAVTierBackend(cfg TierTargetConfig, tokens TierTokenSource) (*webdavTierBackend, error) {
	parsed, err := url.Parse(cfg.WebDavUrl)
	if err != nil {
		// Do not quote the URL: validate() has already refused anything
		// that could carry a credential, but this is cheap insurance.
		return nil, errors.New("WebDavUrl is not a valid URL")
	}
	root := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: strings.TrimRight(parsed.Path, "/")}
	b := &webdavTierBackend{
		root:      root,
		prefix:    trimTierPrefix(cfg.Prefix),
		client:    &http.Client{Transport: config.GetTransport(), CheckRedirect: followReadRedirects},
		putClient: &http.Client{Transport: putTransport(), CheckRedirect: followReadRedirects},
		tokens:    tokens,
		display:   cfg.DisplayURL(),
		knownDirs: make(map[string]struct{}),
	}
	return b, nil
}

func (b *webdavTierBackend) DisplayURL() string { return b.display }

// Close releases nothing: the HTTP transport is the process's shared one.
func (b *webdavTierBackend) Close() error { return nil }

// followReadRedirects follows redirects for reads only.  A dCache door sends
// GETs to a pool this way, with a URL that needs no credential -- and net/http
// drops the Authorization header on the cross-host hop, so the token stays
// with the door.  Any other method is left to fail on the 3xx: net/http would
// turn a redirected DELETE, MKCOL or PROPFIND into a GET, and report the
// GET's success as theirs.
func followReadRedirects(req *http.Request, via []*http.Request) error {
	if m := via[0].Method; m != http.MethodGet && m != http.MethodHead {
		return http.ErrUseLastResponse
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// webdavPutResponseTimeout bounds the wait for the answer to an upload, once
// its body has been sent.
const webdavPutResponseTimeout = 10 * time.Minute

// putTransport is the process's transport with a response-header timeout long
// enough for an upload; see putClient.
func putTransport() *http.Transport {
	t := config.GetTransport().Clone()
	t.ResponseHeaderTimeout = webdavPutResponseTimeout
	return t
}

// rootRel is key's path relative to root.
func (b *webdavTierBackend) rootRel(key string) string {
	key = strings.Trim(key, "/")
	if b.prefix == "" {
		return key
	}
	if key == "" {
		return b.prefix
	}
	return b.prefix + "/" + key
}

// objectPath is the unescaped URL path of key.
func (b *webdavTierBackend) objectPath(key string) string {
	return b.root.Path + "/" + b.rootRel(key)
}

// urlFor is the URL of rel (relative to root).  Collections get the trailing
// slash WebDAV servers expect.
func (b *webdavTierBackend) urlFor(rel string, collection bool) string {
	u := *b.root
	u.Path = b.root.Path + "/" + strings.Trim(rel, "/")
	if collection && !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String()
}

// do issues one request with the backend's credentials.
func (b *webdavTierBackend) do(ctx context.Context, method, target string, body io.Reader, size int64, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	for k, v := range header {
		req.Header[k] = v
	}
	token, err := b.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == http.MethodPut {
		return b.putClient.Do(req)
	}
	return b.client.Do(req)
}

// drain discards what is left of a response body, so the connection can be
// reused, and closes it.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// statusError describes an unexpected response without quoting its body,
// which a misbehaving server could fill with anything.
func (b *webdavTierBackend) statusError(op, key string, resp *http.Response) error {
	return errors.Errorf("%s of %s on cache tier target %s failed: %s", op, key, b.display, resp.Status)
}

// ensureParents creates the collections above key that this process has not
// already seen, shallowest first.  A collection that already exists answers
// MKCOL with 405, which is success here.
func (b *webdavTierBackend) ensureParents(ctx context.Context, key string) error {
	parent := path.Dir(b.rootRel(key))
	if parent == "." || parent == "/" {
		return nil
	}
	parts := strings.Split(parent, "/")
	for i := range parts {
		dir := strings.Join(parts[:i+1], "/")
		b.dirsMu.Lock()
		_, known := b.knownDirs[dir]
		b.dirsMu.Unlock()
		if known {
			continue
		}
		resp, err := b.do(ctx, "MKCOL", b.urlFor(dir, true), nil, 0, nil)
		if err != nil {
			return errors.Wrapf(err, "failed to create collection %s on cache tier target %s", dir, b.display)
		}
		drain(resp)
		switch resp.StatusCode {
		case http.StatusCreated, http.StatusOK, http.StatusNoContent, http.StatusMethodNotAllowed:
		case http.StatusConflict:
			if i == 0 {
				return errors.Errorf("the collection WebDavUrl names on cache tier target %s does not exist", b.display)
			}
			return b.statusError("MKCOL", dir, resp)
		default:
			return b.statusError("MKCOL", dir, resp)
		}
		b.dirsMu.Lock()
		b.knownDirs[dir] = struct{}{}
		b.dirsMu.Unlock()
	}
	return nil
}

// forgetParents drops key's ancestors from knownDirs, after a PUT says one of
// them is missing (someone removed it behind the cache's back).
func (b *webdavTierBackend) forgetParents(key string) {
	b.dirsMu.Lock()
	defer b.dirsMu.Unlock()
	for dir := path.Dir(b.rootRel(key)); dir != "." && dir != "/"; dir = path.Dir(dir) {
		delete(b.knownDirs, dir)
	}
}

// exactReader yields exactly n bytes from r, failing -- and so aborting the
// request it is the body of -- if r ends early.
type exactReader struct {
	r      io.Reader
	remain int64
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.remain <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > e.remain {
		p = p[:e.remain]
	}
	n, err := e.r.Read(p)
	e.remain -= int64(n)
	if err == io.EOF {
		if e.remain > 0 {
			return n, io.ErrUnexpectedEOF
		}
		return n, io.EOF
	}
	return n, err
}

// Put uploads body with a single PUT.  No Expect: 100-continue is sent: dCache
// answers that by redirecting the upload to a pool, which would need the body
// a second time, while without it the door accepts the upload itself.
func (b *webdavTierBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error) {
	if err := b.ensureParents(ctx, key); err != nil {
		return TierObjectInfo{}, err
	}
	header := http.Header{}
	if contentType = uploadContentType(contentType); contentType != "" {
		header.Set("Content-Type", contentType)
	}
	var reqBody io.Reader = http.NoBody
	if size > 0 {
		reqBody = &exactReader{r: body, remain: size}
	}
	resp, err := b.do(ctx, http.MethodPut, b.urlFor(b.rootRel(key), false), reqBody, size, header)
	if err != nil {
		// The upload was cut off -- a short body, a dropped connection.
		// WebDAV has no way to abort a PUT, and a server may keep what
		// arrived, so remove it rather than leave a short object that a
		// later Stat would report as present.
		b.removePartial(ctx, key)
		return TierObjectInfo{}, errors.Wrapf(err, "failed to upload %s to cache tier target %s", key, b.display)
	}
	drain(resp)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
	case http.StatusConflict:
		// A parent collection disappeared.  The body is spent, so the
		// upload is not retried here; the uploader tries again later, and
		// by then the parents will be recreated.
		b.forgetParents(key)
		return TierObjectInfo{}, b.statusError("PUT", key, resp)
	default:
		return TierObjectInfo{}, b.statusError("PUT", key, resp)
	}
	// Read back what the server stored, as the blob backend does: it is
	// where the entity tag comes from, and the only end-to-end check that
	// the whole object landed.
	info, exists, err := b.Stat(ctx, key)
	if err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to confirm the upload of %s to cache tier target %s", key, b.display)
	}
	if !exists || info.Size != size {
		b.removePartial(ctx, key)
		return TierObjectInfo{}, errors.Errorf("upload of %s to cache tier target %s stored %d bytes; expected %d",
			key, b.display, info.Size, size)
	}
	return info, nil
}

// uploadContentType is the Content-Type an upload of an object of type
// contentType is sent with: the object's own, unless the server could take it
// as an instruction to parse the body.  A servlet container reads a body
// labelled as a form as form parameters as soon as anything asks for one --
// Jetty does so for PUT as well as POST, and dCache's door asks (for authz) --
// after which the upload finds the body already consumed: dCache stores
// nothing and answers 500 "insufficient data written".  The bytes are opaque
// to the target, so such an object goes up as application/octet-stream; the
// cache keeps its real type in its own metadata.
func uploadContentType(contentType string) string {
	if contentType == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Not a type a server could act on, but no use to it either.
		return "application/octet-stream"
	}
	switch mediaType {
	case "application/x-www-form-urlencoded", "multipart/form-data":
		return "application/octet-stream"
	}
	return contentType
}

// removePartial deletes what a failed upload may have left at key.  It runs
// even when ctx is already cancelled -- a cancelled upload is one of the cases
// it exists for -- but on a short deadline of its own.
func (b *webdavTierBackend) removePartial(ctx context.Context, key string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := b.Delete(ctx, key); err != nil {
		log.Debugf("Failed to remove a partial upload of %s from cache tier target %s: %v", key, b.display, err)
	}
}

// isWeakETag reports whether an entity tag is weak.  If-Match uses the strong
// comparison, under which a weak tag never matches -- sending one would make
// every pinned read fail as though the object had changed.
func isWeakETag(etag string) bool { return strings.HasPrefix(etag, "W/") }

// sameETag compares entity tags with the weak comparison function, which is
// the strongest check available when either side is weak.
func sameETag(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// OpenRange starts a GET at offset.  A read pinned to expect sends If-Match
// with the recorded entity tag when it is a strong one, and in every case
// checks the entity tag of the response, so a server that ignores If-Match
// (or redirects to a pool that does) cannot hand back a replaced object.
func (b *webdavTierBackend) OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	header := http.Header{}
	if offset > 0 {
		header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	if expect != nil && expect.ETag != "" && !isWeakETag(expect.ETag) {
		header.Set("If-Match", expect.ETag)
	}
	resp, err := b.do(ctx, http.MethodGet, b.urlFor(b.rootRel(key), false), nil, 0, header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s on cache tier target %s", key, b.display)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
	case http.StatusPreconditionFailed:
		drain(resp)
		return nil, b.confirmChanged(ctx, key, expect)
	default:
		drain(resp)
		return nil, b.statusError("GET", key, resp)
	}
	if expect != nil && expect.ETag != "" {
		if got := resp.Header.Get("ETag"); got != "" && !sameETag(got, expect.ETag) {
			drain(resp)
			return nil, b.confirmChanged(ctx, key, expect)
		}
	}
	if offset > 0 {
		if resp.StatusCode == http.StatusOK {
			// The server ignored the range and is sending the whole object.
			if _, err := io.CopyN(io.Discard, resp.Body, offset); err != nil {
				resp.Body.Close()
				return nil, errors.Wrapf(err, "failed to skip to offset %d of %s on cache tier target %s", offset, key, b.display)
			}
		} else if start, ok := contentRangeStart(resp.Header.Get("Content-Range")); !ok || start != offset {
			drain(resp)
			return nil, errors.Errorf("cache tier target %s answered a read of %s at offset %d with a different range",
				b.display, key, offset)
		}
	}
	return resp.Body, nil
}

// confirmChanged decides what a failed precondition means.  The caller drops
// the cache's record of the object -- and the remote copy with it -- on
// ErrTierObjectChanged, so that is reported only when a HEAD agrees the object
// is no longer the recorded copy.  A server whose conditional GET disagrees
// with its own HEAD (comparing a different form of the entity tag, say) then
// costs a failed read, not a good object.
func (b *webdavTierBackend) confirmChanged(ctx context.Context, key string, expect *TierObjectInfo) error {
	current, exists, err := b.Stat(ctx, key)
	if err != nil {
		return errors.Wrapf(err, "cache tier target %s refused a conditional read of %s, and checking it failed", b.display, key)
	}
	if exists && current.Size == expect.Size && sameETag(current.ETag, expect.ETag) {
		return errors.Errorf("cache tier target %s refused a conditional read of %s although it still reports the recorded copy",
			b.display, key)
	}
	return errors.Wrapf(ErrTierObjectChanged, "%s on cache tier target %s", key, b.display)
}

// contentRangeStart parses the first byte position of a Content-Range header
// ("bytes 100-199/1000").
func contentRangeStart(header string) (int64, bool) {
	rest, ok := strings.CutPrefix(header, "bytes ")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	return start, err == nil
}

// Stat issues a HEAD.  The entity tag it reports is the one OpenRange later
// pins reads to, so both must come from the same kind of request.
func (b *webdavTierBackend) Stat(ctx context.Context, key string) (TierObjectInfo, bool, error) {
	resp, err := b.do(ctx, http.MethodHead, b.urlFor(b.rootRel(key), false), nil, 0, nil)
	if err != nil {
		return TierObjectInfo{}, false, errors.Wrapf(err, "failed to stat %s on cache tier target %s", key, b.display)
	}
	drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return TierObjectInfo{}, false, nil
	default:
		return TierObjectInfo{}, false, b.statusError("HEAD", key, resp)
	}
	if resp.ContentLength < 0 {
		return TierObjectInfo{}, false, errors.Errorf("cache tier target %s reported no size for %s", b.display, key)
	}
	info := TierObjectInfo{Size: resp.ContentLength, ETag: resp.Header.Get("ETag")}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			info.ModTime = t
		}
	}
	return info, true, nil
}

// Delete removes key; a missing object is not an error.
func (b *webdavTierBackend) Delete(ctx context.Context, key string) error {
	resp, err := b.do(ctx, http.MethodDelete, b.urlFor(b.rootRel(key), false), nil, 0, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to delete %s from cache tier target %s", key, b.display)
	}
	drain(resp)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusNotFound, http.StatusGone:
		return nil
	default:
		return b.statusError("DELETE", key, resp)
	}
}

// List walks the collection tree depth first with one PROPFIND (Depth: 1) per
// collection, yielding objects in ascending key order.
//
// Ordering each collection by name is not quite enough for that: a sibling
// "a-b" sorts after "a" but its key sorts before every "a/..." key, because
// '-' < '/'.  So entries are ordered by name with a "/" appended to
// collections, which is exactly how their keys compare.
func (b *webdavTierBackend) List(ctx context.Context, fn func(key string, size int64, modified time.Time) error) error {
	return b.listCollection(ctx, "", fn)
}

func (b *webdavTierBackend) listCollection(ctx context.Context, dir string, fn func(key string, size int64, modified time.Time) error) error {
	entries, found, err := b.propfind(ctx, dir)
	if err != nil {
		return err
	}
	if !found {
		// Nothing has been written yet (or the collection was removed);
		// either way there is nothing to list.
		return nil
	}
	for _, e := range entries {
		key := e.name
		if dir != "" {
			key = dir + "/" + e.name
		}
		if e.isDir {
			if err := b.listCollection(ctx, key, fn); err != nil {
				return err
			}
			continue
		}
		if err := fn(key, e.size, e.modified); err != nil {
			return err
		}
	}
	return nil
}

// davEntry is one member of a collection.
type davEntry struct {
	name     string
	isDir    bool
	size     int64
	modified time.Time
}

// davMultistatus is the subset of a PROPFIND response this backend reads.
type davMultistatus struct {
	Responses []struct {
		Href      string `xml:"DAV: href"`
		Propstats []struct {
			Status string `xml:"DAV: status"`
			Prop   struct {
				ResourceType struct {
					Collection *struct{} `xml:"DAV: collection"`
				} `xml:"DAV: resourcetype"`
				ContentLength string `xml:"DAV: getcontentlength"`
				LastModified  string `xml:"DAV: getlastmodified"`
			} `xml:"DAV: prop"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

const propfindBody = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop></D:propfind>`

// propfind lists the direct members of dir (relative to the cache's
// collection), sorted in key order.  found is false when the collection does
// not exist.
func (b *webdavTierBackend) propfind(ctx context.Context, dir string) (entries []davEntry, found bool, err error) {
	rel := b.rootRel(dir)
	header := http.Header{}
	header.Set("Depth", "1")
	header.Set("Content-Type", "application/xml; charset=utf-8")
	resp, err := b.do(ctx, "PROPFIND", b.urlFor(rel, true), strings.NewReader(propfindBody), int64(len(propfindBody)), header)
	if err != nil {
		return nil, false, errors.Wrapf(err, "failed to list cache tier target %s", b.display)
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusMultiStatus:
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, b.statusError("PROPFIND", "/"+dir, resp)
	}
	var ms davMultistatus
	if err := xml.NewDecoder(io.LimitReader(resp.Body, webdavMaxListingBytes)).Decode(&ms); err != nil {
		return nil, false, errors.Wrapf(err, "failed to parse the listing of %s on cache tier target %s", "/"+dir, b.display)
	}

	collection := strings.TrimRight(b.root.Path+"/"+rel, "/")
	for _, r := range ms.Responses {
		href, err := url.Parse(r.Href)
		if err != nil {
			continue
		}
		hrefPath := strings.TrimRight(href.Path, "/")
		name, ok := strings.CutPrefix(hrefPath, collection+"/")
		if !ok || name == "" || strings.Contains(name, "/") {
			// The collection itself, or an entry that is not a direct
			// member (which a Depth: 1 listing should not contain).
			continue
		}
		for _, ps := range r.Propstats {
			if !propstatOK(ps.Status) {
				continue
			}
			e := davEntry{name: name, isDir: ps.Prop.ResourceType.Collection != nil}
			if !e.isDir {
				if e.size, err = strconv.ParseInt(strings.TrimSpace(ps.Prop.ContentLength), 10, 64); err != nil || e.size < 0 {
					// dCache reports no size for a file still being
					// written.  That is no reason to abandon the walk --
					// a failed listing skips the whole consistency sweep,
					// and a size-less leftover would then block every
					// sweep -- so it is listed with its size unknown.
					log.Debugf("Cache tier target %s listed %s/%s without a size", b.display, dir, name)
					e.size = -1
				}
				if t, err := http.ParseTime(strings.TrimSpace(ps.Prop.LastModified)); err == nil {
					e.modified = t
				}
			}
			entries = append(entries, e)
			break
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sortKey() < entries[j].sortKey() })
	return entries, true, nil
}

// sortKey is the string a member's keys compare as; see List.
func (e davEntry) sortKey() string {
	if e.isDir {
		return e.name + "/"
	}
	return e.name
}

// propstatOK reports whether a propstat's status line ("HTTP/1.1 200 OK")
// says its properties were found.
func propstatOK(status string) bool {
	fields := strings.Fields(status)
	return len(fields) >= 2 && fields[1] == "200"
}
