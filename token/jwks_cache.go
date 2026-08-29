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

package token

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/pelicanplatform/pelican/config"
)

// JwksCache caches the public keys of remote issuers.  Callers key it by
// whatever identifies the issuer to them (a namespace prefix, an issuer URL)
// and supply a resolver that turns that key into a JWKS URL; the resolver runs
// once per cached entry.
//
// The cache is built around two bounds that callers can reason about:
//
//   - Keys are re-fetched once they are older than the revalidate interval, so
//     that is the routine upper bound on how long a key rotation goes
//     unnoticed.  Revalidation happens out of band: the request that notices
//     the keys are stale is served from the existing set rather than made to
//     wait for the network.
//   - Keys are served through a fetch failure, so an unreachable issuer does
//     not break verification for issuers already in use, but only up to the
//     maximum staleness.  Past that the cache fails closed rather than keep
//     trusting keys it has not been able to confirm.
//
// Fetch attempts for one key are throttled and collapsed, so neither a down
// issuer nor a burst of concurrent requests turns into a burst of outbound
// requests.  Nothing here starts a goroutine per cached issuer: an entry holds
// a keyset and some timestamps, so evicting one actually reclaims it.
type JwksCache struct {
	ctx     context.Context
	opts    jwksCacheOptions
	entries *ttlcache.Cache[string, *jwksEntry]
	group   singleflight.Group
}

// JwksUrlResolver returns the JWKS URL for a cache key.  It is called once per
// entry, on the first fetch, and may perform I/O (e.g. OIDC discovery).
type JwksUrlResolver func(ctx context.Context) (string, error)

type jwksCacheOptions struct {
	ttl           time.Duration
	capacity      uint64
	revalidate    time.Duration
	maxStale      time.Duration
	retry         time.Duration
	fetchTimeout  time.Duration
	dropOnAbsence bool
}

type JwksCacheOption func(*jwksCacheOptions)

// WithJwksTTL bounds how long an unused entry is retained.  Entries still in
// use are kept alive as they are read; this only reclaims idle ones.
func WithJwksTTL(d time.Duration) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.ttl = d }
}

// WithJwksCapacity bounds how many issuers are tracked at once, evicting the
// least recently used first.  Set this whenever the key is influenced by a
// remote caller, so that unknown keys cannot grow the cache without limit.
func WithJwksCapacity(n uint64) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.capacity = n }
}

// WithJwksRevalidateInterval sets how old a keyset may become before it is
// refreshed out of band.
func WithJwksRevalidateInterval(d time.Duration) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.revalidate = d }
}

// WithJwksMaxStaleness sets the ceiling on serving keys that could not be
// re-fetched.  Past it, Keys fails instead of returning the cached set.
func WithJwksMaxStaleness(d time.Duration) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.maxStale = d }
}

// WithJwksRetryInterval sets the minimum spacing between fetch attempts for a
// single key.
func WithJwksRetryInterval(d time.Duration) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.retry = d }
}

// WithJwksFetchTimeout bounds a single JWKS fetch.
func WithJwksFetchTimeout(d time.Duration) JwksCacheOption {
	return func(o *jwksCacheOptions) { o.fetchTimeout = d }
}

// WithJwksDropOnAbsence makes the cache discard an issuer's keys when the
// issuer is reachable and reports that they should not be used: HTTP 404 or
// 410 (no such issuer) or 403 (known but not permitted).  Verification then
// fails immediately rather than coasting on cached keys until the staleness
// ceiling.
//
// Enable it only where those codes are known to mean revocation.  Pelican's
// registry says exactly that: 404 for a namespace that is not registered, 403
// for one whose approval has been withdrawn.  For a general OIDC issuer the
// same codes are more likely to be a misconfigured proxy, and dropping keys
// would turn that into an outage.
//
// The report has to be repeated before the keys are dropped, so that a single
// bad response cannot revoke a namespace.
func WithJwksDropOnAbsence() JwksCacheOption {
	return func(o *jwksCacheOptions) { o.dropOnAbsence = true }
}

// JwksFetchError reports a JWKS endpoint that answered with something other
// than a keyset.
type JwksFetchError struct {
	URL        string
	StatusCode int
}

func (e *JwksFetchError) Error() string {
	return fmt.Sprintf("JWKS endpoint %s returned HTTP %d", e.URL, e.StatusCode)
}

// IsAbsence reports whether the issuer is telling us these keys should not be
// used, as opposed to being unable to answer.  A server that is reachable
// enough to say "no such issuer" (404, 410) or "not permitted" (403) has given
// a real answer; a timeout, a refused connection, or a 5xx has not.
func (e *JwksFetchError) IsAbsence() bool {
	switch e.StatusCode {
	case http.StatusNotFound, http.StatusGone, http.StatusForbidden:
		return true
	}
	return false
}

// absenceConfirmations is how many consecutive absence reports it takes to drop
// an issuer's keys.  More than one, so that a single bad response from a
// misconfigured or half-migrated registry cannot revoke a namespace.
const absenceConfirmations = 2

// maxJwksBytes bounds how much of a JWKS response is read, so a misbehaving or
// hostile endpoint cannot feed unbounded data into the parser.
const maxJwksBytes = 1 << 20

const (
	defaultJwksTTL          = time.Hour
	defaultJwksRevalidate   = 15 * time.Minute
	defaultJwksRetry        = 30 * time.Second
	defaultJwksFetchTimeout = 10 * time.Second

	// defaultJwksMaxStale is deliberately long enough to ride out an issuer
	// outage that starts on a Friday and is not looked at until Monday.
	defaultJwksMaxStale = 72 * time.Hour
)

// jwksEntry holds one issuer's keys.  lastGood records successful fetches only,
// which is what bounds staleness; lastAttempt records every attempt, including
// failures, which is what throttles retries.
type jwksEntry struct {
	mu          sync.RWMutex
	url         string
	set         jwk.Set
	lastGood    time.Time
	lastAttempt time.Time
	// absences counts consecutive reports from the issuer that these keys
	// should not be used.  Reset by anything else, so an outage in the middle
	// of a run of them does not carry the count forward.
	absences int
}

func (e *jwksEntry) keys() (jwk.Set, time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.set, e.lastGood
}

// beginAttempt records a fetch attempt unless one happened too recently,
// reporting whether the caller should proceed.  Checking and stamping under one
// lock keeps two callers from both deciding to fetch.
func (e *jwksEntry) beginAttempt(retry time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.lastAttempt.IsZero() && time.Since(e.lastAttempt) < retry {
		return false
	}
	e.lastAttempt = time.Now()
	return true
}

func (e *jwksEntry) recordSuccess(url string, set jwk.Set) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.url = url
	e.set = set
	e.lastGood = time.Now()
	e.absences = 0
}

// recordAbsence notes that the issuer reported these keys should not be used,
// and reports how many such reports have arrived in a row.
func (e *jwksEntry) recordAbsence() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.absences++
	return e.absences
}

// clearAbsences forgets the run of absence reports, so that an unrelated
// failure does not count toward dropping the keys.
func (e *jwksEntry) clearAbsences() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.absences = 0
}

// dropKeys discards the cached keys, so the next lookup has to fetch.
func (e *jwksEntry) dropKeys() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.set = nil
	e.lastGood = time.Time{}
}

func (e *jwksEntry) resolvedUrl() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.url
}

// NewJwksCache builds a key cache.  The context bounds the lifetime of the
// cache and of every fetch it performs.
func NewJwksCache(ctx context.Context, egrp *errgroup.Group, options ...JwksCacheOption) *JwksCache {
	opts := jwksCacheOptions{
		ttl:          defaultJwksTTL,
		revalidate:   defaultJwksRevalidate,
		maxStale:     defaultJwksMaxStale,
		retry:        defaultJwksRetry,
		fetchTimeout: defaultJwksFetchTimeout,
	}
	for _, o := range options {
		o(&opts)
	}

	cacheOpts := []ttlcache.Option[string, *jwksEntry]{
		ttlcache.WithTTL[string, *jwksEntry](opts.ttl),
		// Touch-on-hit stays enabled: an entry holds keys plus the time they
		// were fetched, and staleness is enforced from those timestamps rather
		// than from the entry's expiry.  Extending a busy entry therefore
		// cannot prolong a stale key, while dropping one would discard the keys
		// that let verification survive an issuer outage.
		ttlcache.WithLoader[string, *jwksEntry](
			ttlcache.NewSuppressedLoader[string, *jwksEntry](
				ttlcache.LoaderFunc[string, *jwksEntry](
					func(cache *ttlcache.Cache[string, *jwksEntry], key string) *ttlcache.Item[string, *jwksEntry] {
						return cache.Set(key, &jwksEntry{}, ttlcache.DefaultTTL)
					},
				), nil),
		),
	}
	if opts.capacity > 0 {
		cacheOpts = append(cacheOpts, ttlcache.WithCapacity[string, *jwksEntry](opts.capacity))
	}

	kc := &JwksCache{
		ctx:     ctx,
		opts:    opts,
		entries: ttlcache.New(cacheOpts...),
	}

	egrp.Go(func() error {
		kc.entries.Start()
		return nil
	})
	egrp.Go(func() error {
		<-ctx.Done()
		kc.entries.Stop()
		kc.entries.DeleteAll()
		return nil
	})

	return kc
}

// Keys returns the issuer's public keys, fetching them if they are not cached
// and refreshing them once they age past the revalidate interval.  Cached keys
// are returned through a fetch failure until they exceed the maximum staleness,
// after which an error is returned instead.
func (c *JwksCache) Keys(ctx context.Context, key string, resolve JwksUrlResolver) (jwk.Set, error) {
	entry := c.entry(key)
	if entry == nil {
		return nil, errors.Errorf("failed to create a key cache entry for %s", key)
	}

	set, lastGood := entry.keys()
	if set != nil && set.Len() > 0 {
		age := time.Since(lastGood)
		switch {
		case age < c.opts.revalidate:
			return set, nil
		case age < c.opts.maxStale:
			// Serve the keys we have and refresh behind the request, so a
			// routine refresh never shows up as request latency.
			go func() {
				if _, err := c.fetch(c.ctx, key, entry, resolve); err != nil {
					log.Debugf("Background key refresh for %s failed (serving keys fetched %v ago): %v",
						key, age.Truncate(time.Second), err)
				}
			}()
			return set, nil
		}

		// The keys are older than we are willing to trust.  Try once more, and
		// refuse to hand them out if that does not work.
		fresh, err := c.fetch(ctx, key, entry, resolve)
		if err == nil && fresh != nil {
			return fresh, nil
		}
		return nil, errors.Errorf("refusing to use public keys for %s: the last successful refresh was %v ago, over the %v limit",
			key, age.Truncate(time.Second), c.opts.maxStale)
	}

	fresh, err := c.fetch(ctx, key, entry, resolve)
	if err != nil {
		return nil, err
	}
	if fresh == nil {
		return nil, errors.Errorf("no public keys cached for %s and the last fetch attempt was too recent to retry", key)
	}
	return fresh, nil
}

// Refresh fetches an issuer's keys out of band, subject to the same throttle as
// any other attempt.  It returns nil without error when the throttle suppressed
// the fetch, and leaves the cached keys in place when the fetch fails.  Use it
// when something suggests the cached keys are out of date before they are due
// for revalidation, such as a token naming an unknown key ID.
func (c *JwksCache) Refresh(ctx context.Context, key string, resolve JwksUrlResolver) (jwk.Set, error) {
	entry := c.entry(key)
	if entry == nil {
		return nil, errors.Errorf("failed to create a key cache entry for %s", key)
	}
	return c.fetch(ctx, key, entry, resolve)
}

// Set installs a keyset directly, as though it had just been fetched.  It is
// for callers that obtain an issuer's keys through some channel other than an
// HTTP fetch, and for tests that would otherwise have to stand up a JWKS
// endpoint.  The keys age from here like any other, so they are revalidated
// against the issuer once they pass the revalidate interval.
func (c *JwksCache) Set(key string, set jwk.Set) {
	entry := c.entry(key)
	if entry == nil {
		return
	}
	entry.recordSuccess(entry.resolvedUrl(), set)
}

// fetchJwks retrieves and parses a keyset.  It checks the HTTP status itself
// rather than using jwk.Fetch, which does not: without that check a non-200
// response reaches the parser and surfaces as a confusing parse failure, and
// the status code that says whether the issuer actually answered is lost.
func fetchJwks(ctx context.Context, url string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build a request for %s", url)
	}

	client := &http.Client{Transport: config.GetBasicTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to reach %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &JwksFetchError{URL: url, StatusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJwksBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the response from %s", url)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse the keyset from %s", url)
	}
	return set, nil
}

func (c *JwksCache) entry(key string) *jwksEntry {
	item := c.entries.Get(key)
	if item == nil {
		return nil
	}
	return item.Value()
}

// fetch retrieves the issuer's keys, collapsing concurrent callers for the same
// key into one request.  It returns a nil set, and no error, when the throttle
// suppressed the attempt.
func (c *JwksCache) fetch(ctx context.Context, key string, entry *jwksEntry, resolve JwksUrlResolver) (jwk.Set, error) {
	ch := c.group.DoChan(key, func() (interface{}, error) {
		if !entry.beginAttempt(c.opts.retry) {
			return nil, nil
		}

		// Fetches are shared between callers, so they run under the cache's
		// context rather than any one request's.
		fetchCtx, cancel := context.WithTimeout(c.ctx, c.opts.fetchTimeout)
		defer cancel()

		url := entry.resolvedUrl()
		if url == "" {
			resolved, err := resolve(fetchCtx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to determine the JWKS URL for %s", key)
			}
			url = resolved
		}

		set, err := fetchJwks(fetchCtx, url)
		if err != nil {
			var fetchErr *JwksFetchError
			if errors.As(err, &fetchErr) && fetchErr.IsAbsence() {
				// The issuer answered, and the answer is that these keys are
				// not to be used.  Wait for it to say so more than once before
				// acting, so one bad response cannot revoke an issuer.
				if seen := entry.recordAbsence(); c.opts.dropOnAbsence && seen >= absenceConfirmations {
					log.Warningf("Discarding cached public keys for %s: %v (reported %d times in a row)", key, err, seen)
					entry.dropKeys()
					c.entries.Delete(key)
				}
			} else {
				entry.clearAbsences()
			}
			return nil, errors.Wrapf(err, "failed to fetch public keys for %s", key)
		}
		entry.recordSuccess(url, set)
		log.Debugf("Fetched %d public key(s) for %s from %s", set.Len(), key, url)
		return set, nil
	})

	select {
	case <-ctx.Done():
		// The caller went away; any fetch already in flight continues for
		// whoever else is waiting on it.
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		if res.Val == nil {
			return nil, nil
		}
		set, ok := res.Val.(jwk.Set)
		if !ok {
			return nil, errors.Errorf("key cache returned an unexpected type for %s", key)
		}
		return set, nil
	}
}
