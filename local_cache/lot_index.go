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
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// LotID is the cache's accounting bucket identifier. Every cached object is
// assigned to the lot that owns its path; per-(StorageID, LotID) counters then
// track usage and feed eviction. It replaces the older first-path-component
// "namespace" bucket with a longest-prefix lot resolution.
type LotID uint32

// DefaultLotName is the catch-all lot for objects whose path matches no other
// lot. It always exists and always has a stable LotID.
const DefaultLotName = "default"

// lotPathEntry is one path association used to resolve objects to lots. Paths
// are normalized (absolute, cleaned, no trailing slash).
type lotPathEntry struct {
	lotName   string
	path      string
	recursive bool
	exclude   bool

	// The owning lot's lifecycle window, so resolution can ignore generations
	// that are not live. Renewal mints a fresh-UUID successor lot on the same
	// path rather than extending the old one, so at any moment several
	// generations of a namespace exist side by side and only one of them is
	// the one objects should be attributed to. All-zero means non-expiring.
	creationMs   int64
	expirationMs int64
	deletionMs   int64
}

// lotIndex resolves object paths to owning lot names via longest-prefix
// matching, entirely in memory so the object hot path never touches the lot
// database. It is rebuilt (via setEntries) whenever lots change. Safe for
// concurrent use.
//
// It performs pure resolution (path -> lot name); the stable accounting bucket
// id for a lot name is assigned and persisted by the cache (reusing its
// namespace-mapping table), so ids survive restarts.
//
// The matching rules mirror the lotman core's point-in-time resolution: a path
// entry covers a query iff it equals the query exactly or is a recursive
// ancestor of it; within a single lot a longer covering exclusion suppresses a
// shorter covering inclusion; the longest surviving inclusion across lots wins;
// unmatched queries fall to the default lot.
type lotIndex struct {
	mu      sync.RWMutex
	entries []lotPathEntry
}

// newLotIndex returns an empty index.
func newLotIndex() *lotIndex {
	return &lotIndex{}
}

// setEntries replaces the index's path entries (e.g. after lots change).
func (li *lotIndex) setEntries(entries []lotPathEntry) {
	li.mu.Lock()
	defer li.mu.Unlock()
	li.entries = entries
}

// Resolve returns the name of the lot that owns objectPath, or DefaultLotName
// if no lot matches.
func (li *lotIndex) Resolve(objectPath string) string {
	return li.resolveNameAt(normalizeLotPath(objectPath), time.Now().UnixMilli())
}

// ResolveAt is Resolve at an explicit instant, for tests and for callers that
// need to ask what owned a path at some other time.
func (li *lotIndex) ResolveAt(objectPath string, atMs int64) string {
	return li.resolveNameAt(normalizeLotPath(objectPath), atMs)
}

// resolveName returns the owning lot for a normalized query path, or the
// default lot if none matches.
func (li *lotIndex) resolveNameAt(q string, atMs int64) string {
	li.mu.RLock()
	defer li.mu.RUnlock()

	// Per lot, track the longest covering inclusion and exclusion path lengths,
	// plus the generation's creation time for tie-breaking.
	type agg struct {
		maxIncl, maxExcl int
		creationMs       int64
	}
	byLot := map[string]*agg{}
	for _, e := range li.entries {
		if !pathCovers(e.path, e.recursive, q) {
			continue
		}
		// Skip generations that are not live at this instant. Without this a
		// retired generation stays in the running and, because ties used to
		// break on the lexicographically smallest name, an expired UUID lot
		// would usually win and stay pinned for the whole retention window.
		if !core.LotActiveAt(e.creationMs, e.expirationMs, e.deletionMs, atMs) {
			continue
		}
		a := byLot[e.lotName]
		if a == nil {
			a = &agg{maxIncl: -1, maxExcl: -1, creationMs: e.creationMs}
			byLot[e.lotName] = a
		}
		if e.exclude {
			if len(e.path) > a.maxExcl {
				a.maxExcl = len(e.path)
			}
		} else if len(e.path) > a.maxIncl {
			a.maxIncl = len(e.path)
		}
	}

	best := DefaultLotName
	bestLen := -1
	var bestCreation int64
	for name, a := range byLot {
		if a.maxIncl < 0 || a.maxExcl > a.maxIncl {
			continue // no covering inclusion, or suppressed by a longer exclusion
		}
		if a.maxIncl > bestLen {
			best, bestLen, bestCreation = name, a.maxIncl, a.creationMs
			continue
		}
		if a.maxIncl != bestLen {
			continue
		}
		// Same specificity: prefer the newer generation, then the lower name so
		// the outcome stays deterministic. Preferring the newer one is what
		// keeps a namespace's objects landing in its current lot rather than an
		// arbitrary older sibling that happens to sort first.
		if a.creationMs > bestCreation || (a.creationMs == bestCreation && name < best) {
			best, bestLen, bestCreation = name, a.maxIncl, a.creationMs
		}
	}
	return best
}

// pathCovers reports whether a lot path covers a query path. A non-recursive
// path covers only its exact path; a recursive path also covers descendants.
func pathCovers(lotPath string, recursive bool, q string) bool {
	if lotPath == q {
		return true
	}
	if !recursive {
		return false
	}
	if lotPath == "/" {
		return strings.HasPrefix(q, "/") && q != "/"
	}
	return strings.HasPrefix(q, lotPath+"/")
}

// federationQualifiedKey builds the resolution key for an object, prefixing the
// path with the object's federation discovery host so that the same path in two
// federations resolves to two different lots. The cache can serve multiple
// federations (Cache.AllowedFederations), and an object's federation is carried
// in its pelican:// URL host; bare/host-less inputs fall back to defaultFed
// (the cache's primary federation).
//
// Lots are stored with matching federation-qualified paths (e.g.
// "/osg-htc.org/atlas"), so resolution stays a pure longest-prefix match and the
// lot core needs no federation dimension of its own.
func federationQualifiedKey(pelicanURL, defaultFed string) string {
	host := defaultFed
	p := pelicanURL
	if u, err := url.Parse(pelicanURL); err == nil && u.Scheme != "" {
		if u.Host != "" {
			host = u.Host
		}
		p = u.Path
	}
	return normalizeLotPath("/" + host + "/" + p)
}

// normalizeLotPath canonicalizes an object/lot path: absolute, cleaned, and
// without a trailing slash (except root). Mirrors the core's normalization so
// in-memory resolution matches the database's.
func normalizeLotPath(p string) string {
	if strings.Contains(p, "://") {
		if u, err := url.Parse(p); err == nil {
			p = u.Path
		}
	}
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// buildLotEntries snapshots every lot's paths from the manager into resolution
// entries. Called to (re)build the index when lots change.
func buildLotEntries(mgr *core.Manager) ([]lotPathEntry, error) {
	names, err := mgr.ListAllLots()
	if err != nil {
		return nil, err
	}
	var entries []lotPathEntry
	for _, n := range names {
		view, err := mgr.GetLot(n)
		if err != nil {
			return nil, err
		}
		for _, p := range view.Paths {
			entries = append(entries, lotPathEntry{
				lotName:      n,
				path:         normalizeLotPath(p.Path),
				recursive:    p.Recursive,
				exclude:      p.Exclude,
				creationMs:   view.CreationTime,
				expirationMs: view.ExpirationTime,
				deletionMs:   view.DeletionTime,
			})
		}
	}
	return entries, nil
}

// rebuildFromManager refreshes the index from the current set of lots.
func (li *lotIndex) rebuildFromManager(mgr *core.Manager) error {
	entries, err := buildLotEntries(mgr)
	if err != nil {
		return err
	}
	li.setEntries(entries)
	return nil
}

// federationHostKey types the request-scoped federation discovery host so it
// cannot collide with another package's context value.
type federationHostKey struct{}

// WithFederationHost tags ctx with the federation an object belongs to. The
// multi-federation cache route (/api/v1.0/cache/data/:discovery/*path) strips
// the discovery host out of the URL before the handler ever sees it, so without
// carrying it forward every object would be attributed to the cache's primary
// federation -- and two federations' copies of the same path would share one
// lot's quota.
func WithFederationHost(ctx context.Context, host string) context.Context {
	if host == "" {
		return ctx
	}
	return context.WithValue(ctx, federationHostKey{}, host)
}

// FederationHostFrom returns the federation host tagged onto ctx, or "" when the
// request did not name one (single-federation route), in which case callers fall
// back to the cache's primary federation.
func FederationHostFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	host, _ := ctx.Value(federationHostKey{}).(string)
	return host
}
