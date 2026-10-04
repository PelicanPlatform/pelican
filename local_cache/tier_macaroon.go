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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/macaroon.v2"
)

// dCache macaroons as a pre-signed URL mechanism.
//
// A macaroon is a bearer credential built as an HMAC chain: the issuer signs
// an identifier with a secret only it knows, and each caveat (a condition such
// as "path:/data" or "before:<time>") is folded in as
// sig' = HMAC(sig, caveat).  Anyone holding a macaroon can therefore append
// caveats -- narrowing what it permits -- without the secret, but cannot remove
// one, because that would mean inverting the HMAC.  The issuer verifies by
// recomputing the chain from its secret and checking every caveat.
//
// That is what makes it a replacement for S3 pre-signing.  The cache asks the
// dCache door for one macaroon covering its whole collection, read-only, and
// then mints a URL per redirect entirely locally, by appending caveats that
// confine it to one object and a short lifetime.  No request to dCache sits on
// the redirect path.
//
// The protocol (dCache's MacaroonRequestHandler): POST to the WebDAV URL of
// the path the macaroon should cover, with Content-Type exactly
// "application/macaroon-request" and a JSON body
// {"caveats": [...], "validity": "<ISO-8601 duration>"}; the answer is JSON
// whose "macaroon" member is the macaroon in libmacaroons' v1 binary format,
// base64url-encoded without padding.  The door accepts it back as
// "Authorization: Bearer <macaroon>" or as the "?authz=<macaroon>" query
// parameter, the form a redirect can carry.
//
// The caveats dCache understands are "activity:" (a comma-separated subset of
// READ_METADATA, UPDATE_METADATA, LIST, DOWNLOAD, MANAGE, UPLOAD, DELETE),
// "path:", "root:", "home:", "before:" (an ISO-8601 instant), "ip:" (CIDRs),
// "max-upload:", and the identity caveats "id:" and "iid:" it writes itself.
// It rejects a macaroon carrying any other caveat.

const (
	// macaroonRequestType is the request content type dCache's handler
	// matches -- exactly, so no charset parameter may be added.
	macaroonRequestType = "application/macaroon-request"
	// macaroonRequestTimeout bounds one request for a root macaroon.
	macaroonRequestTimeout = 30 * time.Second
	// macaroonMaxResponseBytes bounds the response to one; a macaroon is a
	// few hundred bytes.
	macaroonMaxResponseBytes = 64 << 10
	// macaroonMaxErrorPageBytes bounds how much of a refusal's error page
	// is read for its reason.
	macaroonMaxErrorPageBytes = 16 << 10
	// macaroonValidityHeadroom is how much longer than a redirect URL's
	// lifetime the root macaroon is requested for.  A minted URL cannot
	// outlive the root it was minted from, and a root with less left than
	// the URL lifetime is not used (see mint), so this is how long
	// refreshing can fail before redirects stop: about ten minutes, with
	// the default five-minute URLs making the fifteen-minute root.
	macaroonValidityHeadroom = 10 * time.Minute
	// javaInstantFormat is how "before:" instants are written: the
	// ISO-8601 form java.time.Instant.parse reads.
	javaInstantFormat = "2006-01-02T15:04:05.000Z"
)

// tierMacaroonRefreshInterval is how often a fresh root macaroon is requested.
// A variable only so tests can shorten it.
var tierMacaroonRefreshInterval = time.Minute

// errMacaroonsRefused reports that the server answered a macaroon request in a
// way that says it does not issue them -- it is not dCache, or macaroons are
// disabled, or it will not issue one for this credential -- as opposed to a
// failure that might clear up on its own.
var errMacaroonsRefused = errors.New("the server does not issue macaroons")

// errScopedTokenRefused is dCache's refusal to issue a macaroon for a token
// that carries storage.* scopes.  The WLCG and SciTokens profiles turn those
// scopes into a restriction dCache cannot write as macaroon caveats, whatever
// paths the scopes name, so it answers every such request with
// "400 Cannot serialise restriction MultiTargetedRestriction".  It is a kind
// of errMacaroonsRefused.
var errScopedTokenRefused = fmt.Errorf("%w for a token with storage.* scopes", errMacaroonsRefused)

// scopedTokenRemedy says what to do about errScopedTokenRefused.
const scopedTokenRemedy = "give the cache a token without storage.* scopes, which the door maps to a dCache " +
	"user that owns the target's directory"

// dcacheMacaroons keeps a root macaroon for one collection on a dCache door,
// refreshed in the background, and mints per-object macaroons from it.
type dcacheMacaroons struct {
	requestURL string
	client     *http.Client
	tokens     TierTokenSource
	display    string
	validity   time.Duration
	// refreshEvery is how often a fresh root macaroon is requested.
	refreshEvery time.Duration
	now          func() time.Time

	root atomic.Pointer[rootMacaroon]

	// failures counts consecutive failed refreshes; only the refresher
	// goroutine touches it once started.
	failures int

	// mu guards the refresher's lifecycle: cancel ends it and done is
	// closed once it has returned (both nil until start launches it), and
	// stopped keeps start from launching one after stop.
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	stopped bool
}

// rootMacaroon is a macaroon as the door issued it, with what the cache needs
// to know about it to attenuate it.
type rootMacaroon struct {
	m *macaroon.Macaroon
	// expiry is the earliest of its "before:" caveats.
	expiry time.Time
	// scope is its "path:" caveats composed, as path elements; empty when
	// it is not restricted by path.
	scope []string
}

// newDCacheMacaroons prepares an issuer for the collection at requestURL.  No
// request is made until start.
func newDCacheMacaroons(requestURL string, client *http.Client, tokens TierTokenSource, display string) *dcacheMacaroons {
	// The request must not follow a redirect: a POST that is redirected is
	// not one the macaroon handler answered.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &dcacheMacaroons{
		requestURL:   requestURL,
		client:       &noRedirect,
		tokens:       tokens,
		display:      display,
		validity:     tierRedirectExpiry() + macaroonValidityHeadroom,
		refreshEvery: tierMacaroonRefreshInterval,
		now:          time.Now,
	}
}

// start requests the first root macaroon and launches the refresher, which
// runs until ctx ends or stop is called.  It fails only when the door refuses
// macaroons outright (errMacaroonsRefused); any other failure is left to the
// refresher to retry, and until it succeeds every mint fails, so the cache
// proxies.
func (d *dcacheMacaroons) start(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, macaroonRequestTimeout)
	root, err := d.fetch(reqCtx)
	cancel()
	switch {
	case errors.Is(err, errMacaroonsRefused):
		return err
	case err != nil:
		d.failures = 1
		log.Warnf("Failed to obtain a macaroon from cache tier target %s: %v; objects on it will be proxied "+
			"until one is issued", d.display, err)
	default:
		d.root.Store(root)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopped {
		runCtx, cancel := context.WithCancel(ctx)
		d.cancel, d.done = cancel, make(chan struct{})
		go d.run(runCtx, d.done)
	}
	return nil
}

// stop ends the refresher, abandoning any request it has in flight, and
// returns once it has exited.  It may be called more than once, and before
// start.
func (d *dcacheMacaroons) stop() {
	d.mu.Lock()
	d.stopped = true
	cancel, done := d.cancel, d.done
	d.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (d *dcacheMacaroons) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(d.refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refresh(ctx)
		}
	}
}

// refresh replaces the root macaroon.  On failure the current one stays in
// use until it is too close to expiry to mint from.
func (d *dcacheMacaroons) refresh(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, macaroonRequestTimeout)
	defer cancel()
	root, err := d.fetch(reqCtx)
	if err != nil {
		if ctx.Err() != nil {
			// Stopped, not failed.
			return
		}
		d.failures++
		// Warn once per outage rather than every minute.
		if d.failures == 1 {
			until := "it is unavailable"
			if cur := d.root.Load(); cur != nil {
				until = "the current one nears its expiry at " + cur.expiry.UTC().Format(time.RFC3339)
			}
			remedy := ""
			if errors.Is(err, errScopedTokenRefused) {
				remedy = "; to have clients redirected to it again, " + scopedTokenRemedy
			}
			log.Warnf("Failed to refresh the macaroon for cache tier target %s: %v; redirects continue until %s, "+
				"then objects are proxied%s", d.display, err, until, remedy)
		} else {
			log.Debugf("Failed to refresh the macaroon for cache tier target %s (%d consecutive failures): %v",
				d.display, d.failures, err)
		}
		return
	}
	if d.failures > 0 {
		log.Infof("Cache tier target %s issued a macaroon after %d failed attempts", d.display, d.failures)
	}
	d.failures = 0
	d.root.Store(root)
}

// fetch requests a root macaroon.  The validity asked for can be refused:
// dCache will not issue a macaroon that outlives a login session carrying an
// expiry of its own, and in dCache 11.2 the only such login is one made with a
// macaroon (MacaroonLoginStrategy attaches the macaroon's own before: as the
// session's Expiry), which is what the cache presents when its TokenFile holds
// a dCache macaroon; an OIDC token login carries none.  A 400 is retried once
// without a validity, taking whatever lifetime the door grants; mint then
// decides whether it is long enough to use.  A refusal for the token's scopes
// is not retried: no validity changes it.
func (d *dcacheMacaroons) fetch(ctx context.Context) (*rootMacaroon, error) {
	root, status, err := d.request(ctx, true)
	if status == http.StatusBadRequest && !errors.Is(err, errScopedTokenRefused) {
		root, status, err = d.request(ctx, false)
	}
	if status == http.StatusBadRequest && !errors.Is(err, errScopedTokenRefused) {
		err = errors.Wrap(err, "the door refused to issue a macaroon for this token")
	}
	return root, err
}

// macaroonRequest is the JSON body of a macaroon request.
type macaroonRequest struct {
	Caveats  []string `json:"caveats"`
	Validity string   `json:"validity,omitempty"`
}

func (d *dcacheMacaroons) request(ctx context.Context, withValidity bool) (*rootMacaroon, int, error) {
	// The root macaroon is read-only, so even it -- held only in memory,
	// never handed out -- cannot be used to change the target.
	body := macaroonRequest{Caveats: []string{"activity:DOWNLOAD"}}
	if withValidity {
		body.Validity = fmt.Sprintf("PT%dS", int64(d.validity/time.Second))
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", macaroonRequestType)
	req.Header.Set("Accept", "application/json")
	token, err := d.tokens.Token(ctx)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, errors.Wrap(err, "macaroon request failed")
	}
	defer drain(resp)

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented:
		// A credential problem or an outage: worth retrying.
		return nil, resp.StatusCode, errors.Errorf("macaroon request answered %s", resp.Status)
	case resp.StatusCode == http.StatusBadRequest && refusedForScopes(resp):
		return nil, resp.StatusCode, errors.Wrapf(errScopedTokenRefused, "macaroon request answered %s", resp.Status)
	default:
		return nil, resp.StatusCode, errors.Wrapf(errMacaroonsRefused, "macaroon request answered %s", resp.Status)
	}

	var answer struct {
		Macaroon string `json:"macaroon"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, macaroonMaxResponseBytes)).Decode(&answer); err != nil || answer.Macaroon == "" {
		// A server that answers the POST with something other than a
		// macaroon is not issuing them.
		return nil, resp.StatusCode, errors.Wrap(errMacaroonsRefused, "the response carried no macaroon")
	}
	root, err := parseRootMacaroon(answer.Macaroon)
	if err != nil {
		return nil, resp.StatusCode, errors.Wrapf(errMacaroonsRefused, "unusable macaroon: %v", err)
	}
	return root, resp.StatusCode, nil
}

// refusedForScopes reports whether a 400 answer to a macaroon request is
// dCache's refusal for a token with storage.* scopes.  dCache names the
// restriction it could not serialise in the status line's reason phrase and
// in its error page; HTTP/2 has no reason phrase, so the page is checked too.
func refusedForScopes(resp *http.Response) bool {
	const marker = "MultiTargetedRestriction"
	if strings.Contains(resp.Status, marker) {
		return true
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, macaroonMaxErrorPageBytes))
	return bytes.Contains(page, []byte(marker))
}

// parseRootMacaroon decodes a macaroon as dCache serializes it and works out
// its expiry and path scope.
func parseRootMacaroon(encoded string) (*rootMacaroon, error) {
	raw, err := macaroon.Base64Decode([]byte(strings.TrimSpace(encoded)))
	if err != nil {
		return nil, errors.Wrap(err, "not base64")
	}
	m := &macaroon.Macaroon{}
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, err
	}

	root := &rootMacaroon{m: m}
	sawPath := false
	var activities map[string]bool // nil: not restricted by activity
	for _, c := range m.Caveats() {
		if c.VerificationId != nil {
			// A client could not discharge it, so no URL minted from
			// this macaroon would work.
			return nil, errors.New("it has a third-party caveat")
		}
		kind, value, _ := strings.Cut(string(c.Id), ":")
		switch kind {
		case "before":
			t, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return nil, errors.Errorf("its expiry %q is not an ISO-8601 instant", value)
			}
			if root.expiry.IsZero() || t.Before(root.expiry) {
				root.expiry = t
			}
		case "path":
			root.scope = chrootPath(root.scope, value)
			sawPath = true
		case "root":
			// dCache resolves a later root: against the path so far.  It
			// writes root: before any path:, where it only sets the frame
			// that both path: caveats and request URLs are relative to;
			// in any other order the scope cannot be worked out here.
			if sawPath {
				return nil, errors.New("it has a root caveat after a path caveat")
			}
		case "activity":
			allowed := make(map[string]bool)
			for _, a := range strings.Split(value, ",") {
				if a = strings.TrimSpace(a); a != "" && (activities == nil || activities[a]) {
					allowed[a] = true
				}
			}
			activities = allowed
		case "iid", "id", "home", "ip", "max-upload":
			// dCache's own caveats; none of them affects what the cache
			// adds.
		default:
			// dCache rejects a macaroon with a caveat it does not know,
			// so one here means the issuer is not dCache -- XRootD, say,
			// which speaks the same request protocol, adds a name:
			// caveat, and reads each path: as absolute rather than
			// relative to the one before.  Attenuating it as though it
			// were dCache's would mint URLs that fail at the server.
			return nil, errors.Errorf("it has a caveat dCache does not issue (%q), so the server is not dCache", kind)
		}
	}
	if root.expiry.IsZero() {
		return nil, errors.New("it has no expiry")
	}
	if activities != nil && !activities["DOWNLOAD"] {
		return nil, errors.New("it does not permit downloads")
	}
	return root, nil
}

// chrootPath resolves p against base the way dCache composes successive path
// caveats (FsPath.chroot): p is taken as relative to base even when it starts
// with "/", and ".." never climbs above base.
func chrootPath(base []string, p string) []string {
	out := append([]string(nil), base...)
	for _, elem := range strings.Split(p, "/") {
		switch elem {
		case "", ".":
		case "..":
			if len(out) > len(base) {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, elem)
		}
	}
	return out
}

// mint returns a macaroon, attenuated from the root one, that allows only
// downloading the object at objPath (an unescaped URL path) until expiry from
// now.  It fails when there is no root macaroon, or when the one there is
// would expire before the minted one -- the door honours the earliest
// "before:", so the URL would die early -- in which case the cache proxies.
func (d *dcacheMacaroons) mint(objPath string, expiry time.Duration) (string, error) {
	root := d.root.Load()
	if root == nil {
		return "", errors.Wrap(ErrTierRedirectUnavailable, "no macaroon is available")
	}
	until := d.now().Add(expiry)
	if root.expiry.Before(until) {
		return "", errors.Wrapf(ErrTierRedirectUnavailable, "the current macaroon expires at %s, too soon for a %s redirect",
			root.expiry.UTC().Format(time.RFC3339), expiry)
	}
	elems := chrootPath(nil, objPath)
	if len(elems) <= len(root.scope) {
		return "", errors.New("the object is outside the macaroon's path")
	}
	for i, e := range root.scope {
		if elems[i] != e {
			return "", errors.New("the object is outside the macaroon's path")
		}
	}

	// Each path: caveat is relative to the scope before it (see
	// chrootPath), so the object is named relative to the root's scope.
	m := root.m.Clone()
	for _, caveat := range []string{
		"activity:DOWNLOAD",
		"path:/" + strings.Join(elems[len(root.scope):], "/"),
		"before:" + until.UTC().Format(javaInstantFormat),
	} {
		if err := m.AddFirstPartyCaveat([]byte(caveat)); err != nil {
			return "", err
		}
	}
	data, err := m.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
