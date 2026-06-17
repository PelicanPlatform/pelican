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
***************************************************************/

package lotman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// makeLot is a tiny helper for constructing synthetic Lot values whose
// only populated fields are the bits of MPA the timeline helpers care
// about. Path sets a single recursive path entry.
func makeLot(name, path string, create, expire int64) Lot {
	return Lot{
		LotName: name,
		Paths:   []LotPath{{Path: path, Recursive: true}},
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: create},
			ExpirationTime: &Int64FromFloat{Value: expire},
		},
	}
}

func TestLotsForNamespace_FiltersAndSorts(t *testing.T) {
	all := []Lot{
		makeLot("u3", "/foo", 300, 400),
		makeLot("u1", "/foo", 100, 200),
		makeLot("v1", "/bar", 50, 150),
		makeLot("u2", "/foo/", 200, 300), // trailing slash should normalise.
	}
	got := lotsForNamespace("/foo", all)
	if assert.Len(t, got, 3) {
		assert.Equal(t, "u1", got[0].LotName)
		assert.Equal(t, "u2", got[1].LotName)
		assert.Equal(t, "u3", got[2].LotName)
	}
}

func TestLotsForNamespace_SkipsLotsWithoutCreation(t *testing.T) {
	all := []Lot{
		{LotName: "no-mpa", Paths: []LotPath{{Path: "/p"}}},
		{LotName: "no-create", Paths: []LotPath{{Path: "/p"}}, MPA: &MPA{}},
		makeLot("ok", "/p", 1, 2),
	}
	got := lotsForNamespace("/p", all)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "ok", got[0].LotName)
	}
}

func TestNextGap_EmptyTimeline(t *testing.T) {
	assert.Equal(t, int64(42), nextGap(nil, 42))
}

func TestNextGap_AllLotsBeforeNow(t *testing.T) {
	timeline := []Lot{
		makeLot("a", "/p", 1, 2),
		makeLot("b", "/p", 3, 4),
	}
	assert.Equal(t, int64(100), nextGap(timeline, 100))
}

func TestNextGap_CoveredByOne(t *testing.T) {
	timeline := []Lot{makeLot("a", "/p", 0, 1000)}
	assert.Equal(t, int64(1000), nextGap(timeline, 500))
}

func TestNextGap_HoleBetweenAdjacentLots(t *testing.T) {
	timeline := []Lot{
		makeLot("a", "/p", 0, 100),
		makeLot("b", "/p", 200, 300),
	}
	// at t=50, "a" covers; coverage extends to 100; next lot starts at 200 -> hole at 100.
	assert.Equal(t, int64(100), nextGap(timeline, 50))
}

func TestNextGap_OverlappingCoverage(t *testing.T) {
	timeline := []Lot{
		makeLot("a", "/p", 0, 200),
		makeLot("b", "/p", 100, 400),
		makeLot("c", "/p", 350, 500),
	}
	// Union = [0, 500); from now=10 the next gap is at 500.
	assert.Equal(t, int64(500), nextGap(timeline, 10))
}

func TestNextGap_NowInsideHole(t *testing.T) {
	timeline := []Lot{
		makeLot("a", "/p", 0, 100),
		makeLot("b", "/p", 200, 300),
	}
	// now=150 sits in the hole; the gap is at now.
	assert.Equal(t, int64(150), nextGap(timeline, 150))
}
