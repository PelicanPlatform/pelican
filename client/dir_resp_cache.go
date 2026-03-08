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
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

// dirRespCacheEntry is a single cached director response with an expiry.
type dirRespCacheEntry struct {
	resp   server_structs.DirectorResponse
	expiry time.Time
}

// inflightResult is the result type stored by the singleflight group.
type inflightResult struct {
	resp   server_structs.DirectorResponse
	prefix string // namespace prefix returned by the director
}

// DirRespCache caches DirectorResponse values keyed by namespace prefix.
//
// It supports longest-prefix matching: given a path like
// "/federation/data/subdir/file.txt", it will match an entry stored
// under the prefix "/federation/data" (but not "/federation/other").
//
// Concurrent cache misses for paths that would map to the same
// singleflight key are coalesced: only one director query is issued
// and all waiters receive the same result.
//
// Entries expire after a configurable TTL.  The cache is safe for
// concurrent use.
type DirRespCache struct {
	mu      sync.RWMutex
	entries map[string]dirRespCacheEntry
	ttl     time.Duration

	// sfMu protects the inflight map.
	sfMu     sync.Mutex
	inflight map[string]*call
}

// call represents an in-flight or completed singleflight call.
type call struct {
	wg  sync.WaitGroup
	val inflightResult
	err error
}

// NewDirRespCache creates a new prefix-matching cache for director
// responses.  Entries are considered valid for `ttl` after they are
// stored.
func NewDirRespCache(ttl time.Duration) *DirRespCache {
	return &DirRespCache{
		entries:  make(map[string]dirRespCacheEntry),
		inflight: make(map[string]*call),
		ttl:      ttl,
	}
}

// stripFederationPaths returns a shallow copy of resp where each
// ObjectServer URL has had objectPath trimmed from the end of its
// Path.  This ensures the cached response stores only the server-side
// base path, so it can safely be reused for different files under the
// same namespace prefix.
func stripFederationPaths(resp server_structs.DirectorResponse, objectPath string) server_structs.DirectorResponse {
	objectPath = path.Clean(objectPath)
	if objectPath == "" || objectPath == "/" || objectPath == "." {
		return resp
	}
	stripped := make([]*url.URL, len(resp.ObjectServers))
	for i, u := range resp.ObjectServers {
		if u == nil {
			continue
		}
		clone := *u
		clone.Path = strings.TrimSuffix(clone.Path, objectPath)
		stripped[i] = &clone
	}
	resp.ObjectServers = stripped
	return resp
}

// reconstitutePaths returns a shallow copy of resp where each
// ObjectServer URL has objectPath appended to its Path.  This is the
// inverse of stripFederationPaths and is applied on every cache
// lookup so callers always receive complete ObjectServer URLs.
func reconstitutePaths(resp server_structs.DirectorResponse, objectPath string) server_structs.DirectorResponse {
	objectPath = path.Clean(objectPath)
	if objectPath == "" || objectPath == "/" || objectPath == "." {
		return resp
	}
	reconstituted := make([]*url.URL, len(resp.ObjectServers))
	for i, u := range resp.ObjectServers {
		if u == nil {
			continue
		}
		clone := *u
		clone.Path = clone.Path + objectPath
		reconstituted[i] = &clone
	}
	resp.ObjectServers = reconstituted
	return resp
}

// Store saves a DirectorResponse under the given prefix.  Any previous
// entry for the same prefix is replaced.
//
// objectPath is the federation object path (e.g. "/test/file.txt")
// that was used to obtain this response from the director.  It is
// stripped from each ObjectServer URL so the cached entry contains
// only the server-side base path.  Pass "" if no stripping is needed.
func (c *DirRespCache) Store(prefix string, objectPath string, resp server_structs.DirectorResponse) {
	prefix = path.Clean(prefix)
	resp = stripFederationPaths(resp, objectPath)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[prefix] = dirRespCacheEntry{
		resp:   resp,
		expiry: time.Now().Add(c.ttl),
	}
	log.Debugf("DirRespCache: stored entry for prefix %q (TTL %s)", prefix, c.ttl)
}

// Lookup finds the longest cached prefix that matches `objectPath`.
//
// For example, if the cache contains entries for "/a/b" and "/a", a
// lookup for "/a/b/c/d.txt" will return the entry for "/a/b".
//
// Returns the cached DirectorResponse and true if a valid (non-expired)
// entry was found, or the zero value and false otherwise.
func (c *DirRespCache) Lookup(objectPath string) (server_structs.DirectorResponse, bool) {
	objectPath = path.Clean(objectPath)
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	// Walk up the path hierarchy from the full path to "/", looking
	// for the longest matching prefix.
	candidate := objectPath
	for {
		if entry, ok := c.entries[candidate]; ok {
			if now.Before(entry.expiry) {
				log.Debugf("DirRespCache: hit for path %q → prefix %q", objectPath, candidate)
				return reconstitutePaths(entry.resp, objectPath), true
			}
			// Entry expired — don't return it, but continue looking
			// for a shorter (potentially still-valid) prefix.
		}

		// Move to the parent directory.
		parent := path.Dir(candidate)
		if parent == candidate {
			// Reached the root; no match.
			break
		}
		candidate = parent
	}

	log.Debugf("DirRespCache: miss for path %q", objectPath)
	return server_structs.DirectorResponse{}, false
}

// DirRespLoader is a function that queries the director for a given
// object path.  It returns the DirectorResponse and the namespace
// prefix that should be used as the cache key.
type DirRespLoader func(ctx context.Context) (resp server_structs.DirectorResponse, prefix string, err error)

// LookupOrLoad checks the cache first; on a miss it calls `loader`
// exactly once per unique objectPath, coalescing concurrent callers
// via singleflight.
//
// If the context is cancelled while waiting for an in-flight query,
// the waiter returns ctx.Err() immediately.  The underlying query
// keeps running so that other waiters (with live contexts) still
// receive the result.
//
// On success the response is automatically stored in the cache under
// the prefix returned by the loader.
func (c *DirRespCache) LookupOrLoad(ctx context.Context, objectPath string, loader DirRespLoader) (server_structs.DirectorResponse, error) {
	// Fast path: cache hit.
	if resp, ok := c.Lookup(objectPath); ok {
		return resp, nil
	}

	objectPath = path.Clean(objectPath)

	// Check for an in-flight request for this path.
	c.sfMu.Lock()
	if cl, ok := c.inflight[objectPath]; ok {
		c.sfMu.Unlock()
		// Wait with context awareness.
		resp, err := c.waitForCall(ctx, cl)
		if err != nil {
			return resp, err
		}
		return reconstitutePaths(resp, objectPath), nil
	}

	// No in-flight request; create one.
	cl := &call{}
	cl.wg.Add(1)
	c.inflight[objectPath] = cl
	c.sfMu.Unlock()

	// Execute the loader.  We run it in a goroutine so we can
	// respect ctx cancellation on this caller while still letting
	// the load complete for other waiters.
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, prefix, err := loader(context.WithoutCancel(ctx))

		// On success, store in cache (stripping the federation
		// object path from ObjectServer URLs).
		if err == nil && prefix != "" {
			c.Store(prefix, objectPath, resp)
		}

		// Store the stripped version; waitForCall callers will
		// reconstitute with their objectPath before returning.
		cl.val = inflightResult{resp: stripFederationPaths(resp, objectPath), prefix: prefix}
		cl.err = err

		cl.wg.Done()

		// Clean up the inflight map.
		c.sfMu.Lock()
		delete(c.inflight, objectPath)
		c.sfMu.Unlock()
	}()

	resp, err := c.waitForCall(ctx, cl)
	if err != nil {
		return resp, err
	}
	return reconstitutePaths(resp, objectPath), nil
}

// waitForCall waits for the in-flight call to complete, respecting
// context cancellation.  If ctx is cancelled before the call
// finishes, ctx.Err() is returned.
func (c *DirRespCache) waitForCall(ctx context.Context, cl *call) (server_structs.DirectorResponse, error) {
	// Use a channel to bridge sync.WaitGroup with select.
	ch := make(chan struct{})
	go func() {
		cl.wg.Wait()
		close(ch)
	}()

	select {
	case <-ch:
		if cl.err != nil {
			return server_structs.DirectorResponse{}, cl.err
		}
		return cl.val.resp, nil
	case <-ctx.Done():
		return server_structs.DirectorResponse{}, fmt.Errorf("director lookup for path cancelled: %w", ctx.Err())
	}
}

// Invalidate removes the entry for the given prefix.
func (c *DirRespCache) Invalidate(prefix string) {
	prefix = path.Clean(prefix)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, prefix)
}

// InvalidateAll removes all cached entries.
func (c *DirRespCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]dirRespCacheEntry)
}

// Len returns the number of entries in the cache (including expired
// ones that haven't been cleaned up yet).
func (c *DirRespCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cleanExpired removes all expired entries.  This is not called
// automatically; callers can invoke it periodically if desired.
func (c *DirRespCache) cleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for prefix, entry := range c.entries {
		if now.After(entry.expiry) {
			delete(c.entries, prefix)
		}
	}
}

// matchesPrefix returns true if objectPath starts with prefix.
// Both paths should be cleaned before calling.
func matchesPrefix(objectPath, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if objectPath == prefix {
		return true
	}
	return strings.HasPrefix(objectPath, prefix+"/")
}
