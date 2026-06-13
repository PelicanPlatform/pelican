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
	"net/url"
	"path"
	"strings"
	"sync"

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
}

// lotIndex resolves object paths to owning lots via longest-prefix matching,
// entirely in memory so the object hot path never touches the lot database. It
// is rebuilt (via setEntries) whenever lots change; LotID assignments are stable
// across rebuilds. Safe for concurrent use.
//
// The matching rules mirror the lotman core's point-in-time resolution: a path
// entry covers a query iff it equals the query exactly or is a recursive
// ancestor of it; within a single lot a longer covering exclusion suppresses a
// shorter covering inclusion; the longest surviving inclusion across lots wins;
// unmatched queries fall to the default lot.
type lotIndex struct {
	mu      sync.RWMutex
	entries []lotPathEntry
	ids     map[string]LotID
	next    LotID
}

// newLotIndex returns an empty index with the default lot pre-assigned id 1.
func newLotIndex() *lotIndex {
	li := &lotIndex{ids: make(map[string]LotID), next: 1}
	li.ids[DefaultLotName] = li.next
	li.next++
	return li
}

// setEntries replaces the index's path entries (e.g. after lots change) and
// assigns a stable LotID to any newly-seen lot. Existing ids are preserved.
func (li *lotIndex) setEntries(entries []lotPathEntry) {
	li.mu.Lock()
	defer li.mu.Unlock()
	li.entries = entries
	for _, e := range entries {
		if _, ok := li.ids[e.lotName]; !ok {
			li.ids[e.lotName] = li.next
			li.next++
		}
	}
}

// idFor returns the stable LotID for a lot name, assigning one if necessary.
func (li *lotIndex) idFor(name string) LotID {
	li.mu.RLock()
	if id, ok := li.ids[name]; ok {
		li.mu.RUnlock()
		return id
	}
	li.mu.RUnlock()

	li.mu.Lock()
	defer li.mu.Unlock()
	if id, ok := li.ids[name]; ok {
		return id
	}
	id := li.next
	li.next++
	li.ids[name] = id
	return id
}

// Resolve maps an object path to its owning lot name and stable LotID.
func (li *lotIndex) Resolve(objectPath string) (string, LotID) {
	name := li.resolveName(normalizeLotPath(objectPath))
	return name, li.idFor(name)
}

// resolveName returns the owning lot for a normalized query path, or the
// default lot if none matches.
func (li *lotIndex) resolveName(q string) string {
	li.mu.RLock()
	defer li.mu.RUnlock()

	// Per lot, track the longest covering inclusion and exclusion path lengths.
	type agg struct{ maxIncl, maxExcl int }
	byLot := map[string]*agg{}
	for _, e := range li.entries {
		if !pathCovers(e.path, e.recursive, q) {
			continue
		}
		a := byLot[e.lotName]
		if a == nil {
			a = &agg{maxIncl: -1, maxExcl: -1}
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
	for name, a := range byLot {
		if a.maxIncl < 0 || a.maxExcl > a.maxIncl {
			continue // no covering inclusion, or suppressed by a longer exclusion
		}
		if a.maxIncl > bestLen || (a.maxIncl == bestLen && name < best) {
			best = name
			bestLen = a.maxIncl
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
				lotName:   n,
				path:      normalizeLotPath(p.Path),
				recursive: p.Recursive,
				exclude:   p.Exclude,
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
