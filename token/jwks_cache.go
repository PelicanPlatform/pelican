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
	ttl          time.Duration
	capacity     uint64
	revalidate   time.Duration
	maxStale     time.Duration
	retry        time.Duration
	fetchTimeout time.Duration
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

		client := &http.Client{Transport: config.GetBasicTransport()}
		set, err := jwk.Fetch(fetchCtx, url, jwk.WithHTTPClient(client))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch public keys for %s from %s", key, url)
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
