//go:build linux && !ppc64le

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

// Per-namespace lot timelines.
//
// Once a namespace is governed by lots whose names are opaque UUIDs, the
// renewal scheduler reasons about a *namespace path*, not a single lot:
// for path P, the lots that ever cover P form a sequence of half-open
// intervals [creation_time, expiration_time). Together they describe
// "which lot is responsible for files at P at any given moment".
//
// This file provides the small pure helpers the scheduler uses:
//
//	lotsForNamespace(P, all)  — filter `all` to the lots whose paths
//	                            include P, sorted by CreationTime asc.
//	nextGap(timeline, now)    — given a sorted timeline, return the first
//	                            point at or after `now` that is NOT
//	                            covered by any lot in the timeline.
//	listAllLotsFull()         — fetch every lot from the lotman DB as
//	                            full Lot structs (FFI-side helper).
//
// All time values are Unix milliseconds. The data plane is intentionally
// pure so it can be unit-tested with synthetic Lot slices.

package lotman

import (
	"math"
	"sort"
)

// lotsForNamespace returns the subset of `all` whose paths[].Path matches
// nsPath exactly (after path normalisation), ordered by CreationTime asc.
// Lots without an MPA, or with no recorded creation time, are skipped:
// they cannot meaningfully participate in a coverage timeline.
//
// nsPath is matched via normaliseLotPath so callers may pass either /foo
// or /foo/ interchangeably.
func lotsForNamespace(nsPath string, all []Lot) []Lot {
	target := normaliseLotPath(nsPath)
	out := make([]Lot, 0, 4)
	for _, l := range all {
		if l.MPA == nil || l.MPA.CreationTime == nil {
			continue
		}
		for _, p := range l.Paths {
			if normaliseLotPath(p.Path) == target {
				out = append(out, l)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].MPA.CreationTime.Value < out[j].MPA.CreationTime.Value
	})
	return out
}

// nextGap walks a CreationTime-sorted `timeline` and returns the first
// point at or after `now` (Unix ms) that no lot in `timeline` covers.
//
// Coverage semantics: a lot covers wall-clock t iff
//
//	creation_time <= t < expiration_time
//
// (half-open right; matches lotman's "lots-past-exp" cutoff exactly).
//
// Returns the first uncovered point at or after `now`. Because lots in
// our model always have a finite expiration_time, a gap is guaranteed to
// exist eventually; the caller compares the returned point against its
// planning horizon to decide whether a successor lot is needed *now*.
//
// Treatment of edge cases:
//   - empty timeline -> returns `now`.
//   - all lots end at or before `now` -> returns `now`.
//   - lots overlap (predecessor.expiration > successor.creation) ->
//     the union of intervals is what matters; the gap starts at the
//     largest expiration that bounds an unbroken run starting at `now`.
func nextGap(timeline []Lot, now int64) int64 {
	cursor := now
	for _, l := range timeline {
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		create := l.MPA.CreationTime.Value
		expire := l.MPA.ExpirationTime.Value
		if expire <= cursor {
			continue
		}
		if create > cursor {
			// Found a hole: cursor sits in a region no lot covers.
			return cursor
		}
		// create <= cursor < expire: lot covers cursor; extend coverage.
		cursor = expire
	}
	return cursor
}

// nextHole walks a CreationTime-sorted `timeline` and returns the first
// uncovered region at or after `cursor`, expressed as the half-open
// interval [holeStart, holeEnd). Coverage semantics match nextGap:
// a lot covers wall-clock t iff creation_time <= t < expiration_time.
//
// holeStart is the first point at or after `cursor` that no lot covers.
// holeEnd is the creation_time of the next lot whose interval *starts*
// after holeStart, or `mathMaxMs` (`int64(math.MaxInt64)`) if no such
// lot exists. Callers can intersect [holeStart, holeEnd) with their own
// scheduling horizon to bound the fill width.
//
// Returns ok=false only when the timeline fully covers `cursor` and
// every subsequent moment up to the last lot's expiration_time without
// a break — but since every Pelican lot has a finite expiration_time,
// in practice ok is always true (the post-last-lot region is itself a
// hole). Defensive callers should still check.
//
// Edge cases:
//   - empty timeline -> ([cursor, mathMaxMs), true)
//   - cursor sits inside a covered run: holeStart = end of that run.
//   - lots overlap: their union is taken; the hole begins at the
//     largest expiration that bounds an unbroken run.
//   - subsequent lots after the hole are honoured: holeEnd is set to
//     the next lot's creation_time, not its expiration_time.
func nextHole(timeline []Lot, cursor int64) (holeStart, holeEnd int64, ok bool) {
	const sentinelEnd = math.MaxInt64
	pos := cursor
	for i := 0; i < len(timeline); i++ {
		l := timeline[i]
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		create := l.MPA.CreationTime.Value
		expire := l.MPA.ExpirationTime.Value
		if expire <= pos {
			// Lot already in the past relative to cursor; ignore.
			continue
		}
		if create > pos {
			// Hole found: [pos, create). The next lot bounds the hole's end.
			return pos, create, true
		}
		// create <= pos < expire: lot covers pos; extend coverage and
		// continue scanning. A hole may still appear after this lot
		// ends if a later lot starts strictly after `expire`.
		pos = expire
	}
	// Fell off the end: the post-last-lot region is one big hole.
	return pos, sentinelEnd, true
}

// listAllLotsFull returns every lot in the lotman DB as a fully-populated
// Lot struct, fetching each one via lotman_get_lot_as_json. Reclaimed
// lots are included so callers can compute reclamation-aware GC eligibility.
// Returns nil, nil on an empty DB.
//
// This is an FFI helper, not a pure function: the rest of timeline.go is
// pure and unit-testable with synthetic slices, while production callers
// reach the real database through this entry point.
func listAllLotsFull() ([]Lot, error) {
	names, err := ListAllLots()
	if err != nil {
		return nil, err
	}
	out := make([]Lot, 0, len(names))
	for _, n := range names {
		l, err := GetLot(n, false)
		if err != nil {
			return nil, err
		}
		if l == nil {
			continue
		}
		out = append(out, *l)
	}
	return out, nil
}
