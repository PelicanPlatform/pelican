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

package core

import (
	"path"
	"sort"
	"strings"
)

// normalizePath canonicalizes a lot/object path: absolute, cleaned, and without
// a trailing slash (except the root "/"). All stored paths and resolution
// queries use this form so longest-prefix matching is exact at segment
// boundaries (no "/foobar" vs "/foo" confusion).
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// normalizedPaths returns a copy of the given path specs with normalized paths.
func normalizedPaths(in []PathSpec) []PathSpec {
	out := make([]PathSpec, len(in))
	for i, p := range in {
		out[i] = p
		out[i].Path = normalizePath(p.Path)
	}
	return out
}

// ancestorPrefixesInclusive returns the normalized query path together with all
// of its ancestor directories down to the root, e.g. "/a/b/c" yields
// ["/", "/a", "/a/b", "/a/b/c"]. These are exactly the stored paths that could
// cover the query under longest-prefix matching, so the resolver only needs to
// load rows whose path is in this (depth-bounded) set.
func ancestorPrefixesInclusive(q string) []string {
	q = normalizePath(q)
	if q == "/" {
		return []string{"/"}
	}
	out := []string{"/"}
	cur := ""
	for _, seg := range strings.Split(strings.TrimPrefix(q, "/"), "/") {
		cur += "/" + seg
		out = append(out, cur)
	}
	return out
}

// lotActiveAt reports whether a lot with the given lifecycle timestamps is
// active at instant t. A non-expiring (all-zero) lot is always active;
// otherwise the active window is the half-open interval [creation, expiration).
func lotActiveAt(creation, expiration, deletion, t int64) bool {
	if IsNonExpiring(creation, expiration, deletion) {
		return true
	}
	return creation <= t && expiration > t
}

// isReclaimedAt reports whether the named lot is reclaimed as of instant t
// (i.e. a reclamation row exists with reclaimed_at <= t).
func (m *Manager) isReclaimedAt(name string, t int64) (bool, error) {
	var recs []LotReclamation
	// Find (not First) avoids logging a spurious ErrRecordNotFound for the
	// common case of a lot that has never been reclaimed.
	if err := m.db.Where("lot_name = ?", name).Limit(1).Find(&recs).Error; err != nil {
		return false, wrap(err, "checking reclamation")
	}
	if len(recs) == 0 {
		return false, nil
	}
	return recs[0].ReclaimedAt <= t, nil
}

// pathRow is a joined lot_paths + lots (+ reclamation) row used during resolution.
type pathRow struct {
	LotName        string `gorm:"column:lot_name"`
	Path           string `gorm:"column:path"`
	Recursive      bool   `gorm:"column:recursive"`
	Exclude        bool   `gorm:"column:exclude"`
	CreationTime   int64  `gorm:"column:creation_time"`
	ExpirationTime int64  `gorm:"column:expiration_time"`
	DeletionTime   int64  `gorm:"column:deletion_time"`
	ReclaimedAt    *int64 `gorm:"column:reclaimed_at"`
}

// lotPathCand is a per-lot resolution candidate: the lot has at least one
// covering inclusion path that survives any longer covering exclusion on the
// same lot, with claimLen the length of that longest surviving inclusion.
type lotPathCand struct {
	lotName     string
	claimLen    int
	creation    int64
	expiration  int64
	deletion    int64
	hasReclaim  bool
	reclaimedAt int64
}

// pathCandidates resolves the per-lot candidates for query path q. It applies
// the exclusion-override rule (an inclusion is dropped when the same lot has a
// strictly longer covering exclusion) but NOT the active-window or reclamation
// filters — callers apply those, since they differ between the point-in-time
// and windowed variants.
func (m *Manager) pathCandidates(q string) ([]lotPathCand, error) {
	prefixes := ancestorPrefixesInclusive(q)
	var rows []pathRow
	err := m.db.Table("lot_paths AS lp").
		Select("lp.lot_name, lp.path, lp.recursive, lp.exclude, l.creation_time, l.expiration_time, l.deletion_time, r.reclaimed_at").
		Joins("JOIN lots l ON l.lot_name = lp.lot_name").
		Joins("LEFT JOIN lot_reclamations r ON r.lot_name = lp.lot_name").
		Where("lp.path IN ?", prefixes).
		Scan(&rows).Error
	if err != nil {
		return nil, wrap(err, "loading path candidates")
	}

	type agg struct {
		maxIncl, maxExcl int
		creation         int64
		expiration       int64
		deletion         int64
		reclaimedAt      *int64
	}
	byLot := map[string]*agg{}
	for _, r := range rows {
		// Every stored path here is an ancestor prefix of q (or equals q), so a
		// path covers q iff it equals q exactly or is recursive.
		if r.Path != q && !r.Recursive {
			continue
		}
		a := byLot[r.LotName]
		if a == nil {
			a = &agg{maxIncl: -1, maxExcl: -1, creation: r.CreationTime, expiration: r.ExpirationTime, deletion: r.DeletionTime, reclaimedAt: r.ReclaimedAt}
			byLot[r.LotName] = a
		}
		if r.Exclude {
			if len(r.Path) > a.maxExcl {
				a.maxExcl = len(r.Path)
			}
		} else if len(r.Path) > a.maxIncl {
			a.maxIncl = len(r.Path)
		}
	}

	out := make([]lotPathCand, 0, len(byLot))
	for name, a := range byLot {
		if a.maxIncl < 0 {
			continue // no covering inclusion
		}
		if a.maxExcl > a.maxIncl {
			continue // a longer covering exclusion suppresses the inclusion
		}
		c := lotPathCand{lotName: name, claimLen: a.maxIncl, creation: a.creation, expiration: a.expiration, deletion: a.deletion}
		if a.reclaimedAt != nil {
			c.hasReclaim = true
			c.reclaimedAt = *a.reclaimedAt
		}
		out = append(out, c)
	}
	return out, nil
}

// LotsFromDir resolves the lot that owns dir at instant atMs, using
// longest-prefix matching with recursive/exclude semantics. When recursive is
// true the owning lot's ancestors are appended. A path matching no active,
// unreclaimed lot resolves to the "default" lot.
func (m *Manager) LotsFromDir(dir string, recursive bool, atMs int64) ([]string, error) {
	return m.lotsFromDir(dir, recursive, atMs, false)
}

// lotsFromDir is LotsFromDir with an attribution flag. When forAttribution is
// true and no lot is active at atMs, it falls back to the longest-prefix match
// ignoring the active window (preferring a generation created at or before atMs
// and closest to it) so physically-present bytes are not stranded on "default"
// during a generation-rotation gap.
func (m *Manager) lotsFromDir(dir string, recursive bool, atMs int64, forAttribution bool) ([]string, error) {
	q := normalizePath(dir)
	cands, err := m.pathCandidates(q)
	if err != nil {
		return nil, err
	}

	best := pickBest(cands, atMs, true, false)
	if best == "" && forAttribution {
		best = pickBest(cands, atMs, false, true)
	}
	if best == "" {
		best = "default"
	}

	result := []string{best}
	if recursive && best != "default" {
		parents, err := m.GetParents(best, true, false)
		if err != nil {
			return nil, err
		}
		for _, p := range parents {
			reclaimed, err := m.isReclaimedAt(p, atMs)
			if err != nil {
				return nil, err
			}
			if !reclaimed {
				result = append(result, p)
			}
		}
	}
	return result, nil
}

// pickBest chooses the winning lot among candidates at instant t. Reclaimed
// (at t) lots are always excluded. When requireActive is set, only lots active
// at t are considered. The longest claim wins; ties break deterministically by
// lot name, except in attribution mode where a generation created at or before
// t and closest to t is preferred (the sentinel lot, creation 0, ranks far).
func pickBest(cands []lotPathCand, t int64, requireActive, attribution bool) string {
	best := ""
	bestLen := -1
	var bestCreation int64
	bestFuture := 0
	for _, c := range cands {
		if c.hasReclaim && c.reclaimedAt <= t {
			continue
		}
		if requireActive && !lotActiveAt(c.creation, c.expiration, c.deletion, t) {
			continue
		}
		future := 0
		if c.creation > t {
			future = 1
		}
		better := false
		switch {
		case c.claimLen > bestLen:
			better = true
		case c.claimLen == bestLen:
			if attribution {
				switch {
				case future < bestFuture:
					better = true
				case future == bestFuture:
					dc, db := absInt64(c.creation-t), absInt64(bestCreation-t)
					if dc < db || (dc == db && c.lotName < best) {
						better = true
					}
				}
			} else if c.lotName < best {
				better = true
			}
		}
		if better {
			best, bestLen, bestCreation, bestFuture = c.lotName, c.claimLen, c.creation, future
		}
	}
	return best
}

// LotsForPath returns every lot that owns path at any instant in the half-open
// window [loMs, hiMs). The longest-prefix rule applies per instant: a lot wins
// if some moment of its active interval within the window is not shadowed by a
// strictly longer-claim lot. "default" is included if any instant in the window
// has no owning lot. When recursive is true, ancestors of the winners are
// appended. When includeReclaimed is false, lots reclaimed for the whole window
// are dropped and mid-window reclamation clips a lot's active interval.
func (m *Manager) LotsForPath(p string, recursive bool, loMs, hiMs int64, includeReclaimed bool) ([]string, error) {
	if hiMs <= loMs {
		return nil, wrapf(ErrInvalidLot, "time window hi (%d) must exceed lo (%d)", hiMs, loMs)
	}
	q := normalizePath(p)
	cands, err := m.pathCandidates(q)
	if err != nil {
		return nil, err
	}

	type ival struct {
		lot        string
		claim      int
		start, end int64
	}
	var actives []ival
	for _, c := range cands {
		if !includeReclaimed && c.hasReclaim && c.reclaimedAt <= loMs {
			continue // reclaimed for the entirety of the window
		}
		var start, end int64
		if IsNonExpiring(c.creation, c.expiration, c.deletion) {
			start, end = loMs, hiMs
		} else {
			if !(c.creation < hiMs && c.expiration > loMs) {
				continue // active window does not overlap the query window
			}
			start = max(c.creation, loMs)
			end = min(c.expiration, hiMs)
		}
		if !includeReclaimed && c.hasReclaim && c.reclaimedAt > loMs && c.reclaimedAt < end {
			end = c.reclaimedAt // mid-window reclamation clips the interval
		}
		if end <= start {
			continue
		}
		actives = append(actives, ival{lot: c.lotName, claim: c.claimLen, start: start, end: end})
	}

	winners := []string{}
	for _, c := range actives {
		var shadow [][2]int64
		for _, o := range actives {
			if o.claim <= c.claim {
				continue
			}
			s, e := max(o.start, c.start), min(o.end, c.end)
			if s < e {
				shadow = append(shadow, [2]int64{s, e})
			}
		}
		if !intervalUnionCovers(shadow, c.start, c.end) {
			winners = append(winners, c.lot)
		}
	}

	// Default-lot fallback: some instant in the window has no owning lot.
	var all [][2]int64
	for _, c := range actives {
		all = append(all, [2]int64{c.start, c.end})
	}
	if !intervalUnionCovers(all, loMs, hiMs) {
		winners = append(winners, "default")
	}

	if recursive {
		seen := map[string]bool{}
		for _, w := range winners {
			seen[w] = true
		}
		var additions []string
		for _, w := range winners {
			if w == "default" {
				continue
			}
			parents, err := m.GetParents(w, true, false)
			if err != nil {
				return nil, err
			}
			for _, par := range parents {
				if seen[par] {
					continue
				}
				if !includeReclaimed {
					// Suppress only ancestors reclaimed for the whole window.
					reclaimed, err := m.isReclaimedAt(par, loMs)
					if err != nil {
						return nil, err
					}
					if reclaimed {
						continue
					}
				}
				seen[par] = true
				additions = append(additions, par)
			}
		}
		winners = append(winners, additions...)
	}
	return winners, nil
}

// intervalUnionCovers reports whether the union of the given intervals fully
// covers the half-open target interval [ts, te).
func intervalUnionCovers(intervals [][2]int64, ts, te int64) bool {
	if len(intervals) == 0 {
		return te <= ts
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i][0] < intervals[j][0] })
	cursor := ts
	for _, iv := range intervals {
		if iv[0] > cursor {
			return false
		}
		if iv[1] > cursor {
			cursor = iv[1]
		}
		if cursor >= te {
			return true
		}
	}
	return cursor >= te
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
