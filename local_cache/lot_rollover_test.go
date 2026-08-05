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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// Renewal retires a lot by minting a fresh-UUID successor covering the same
// path, with back-to-back windows, rather than extending the old lot. So at any
// moment a namespace has several generations side by side. These names are
// chosen so the *older* one sorts first, which is what the old
// lexicographically-smallest tie-break would have picked.
const (
	oldGeneration = "aaaa-old-generation"
	newGeneration = "zzzz-new-generation"
)

// TestResolvePrefersTheLiveGeneration covers path resolution across a rollover.
// Ties used to break on the lowest lot name, so an expired generation would win
// and stay pinned for the whole retention window — newly cached objects were
// attributed to a lot the core considers dead, whose bucket the eviction planner
// then treats as free to delete.
func TestResolvePrefersTheLiveGeneration(t *testing.T) {
	now := time.Now().UnixMilli()
	hour := int64(3600_000)

	li := newLotIndex()
	li.setEntries([]lotPathEntry{
		{
			lotName: oldGeneration, path: "/atlas", recursive: true,
			creationMs: now - 2*hour, expirationMs: now - hour, deletionMs: now + 24*hour,
		},
		{
			lotName: newGeneration, path: "/atlas", recursive: true,
			creationMs: now - hour, expirationMs: now + 24*hour, deletionMs: now + 48*hour,
		},
	})

	require.Equal(t, newGeneration, li.Resolve("/atlas/data/x"),
		"objects must land in the generation that is live now, not the one that sorts first")

	// And the index can still answer historically.
	require.Equal(t, oldGeneration, li.ResolveAt("/atlas/data/x", now-90*60*1000),
		"resolution at an earlier instant must name the generation live then")
}

// TestResolveIgnoresFullyRetiredGenerations checks that when nothing live covers
// a path, resolution falls through to the default lot rather than naming a dead
// generation.
func TestResolveIgnoresFullyRetiredGenerations(t *testing.T) {
	now := time.Now().UnixMilli()
	hour := int64(3600_000)

	li := newLotIndex()
	li.setEntries([]lotPathEntry{{
		lotName: oldGeneration, path: "/atlas", recursive: true,
		creationMs: now - 2*hour, expirationMs: now - hour, deletionMs: now + 24*hour,
	}})

	require.Equal(t, DefaultLotName, li.Resolve("/atlas/data/x"))
}

// TestNonExpiringLotsAlwaysResolve pins the all-zero sentinel, which the
// admin-configured and auto-created lots use.
func TestNonExpiringLotsAlwaysResolve(t *testing.T) {
	li := newLotIndex()
	li.setEntries([]lotPathEntry{
		{lotName: "permanent", path: "/atlas", recursive: true},
	})
	require.Equal(t, "permanent", li.Resolve("/atlas/data/x"))
}

// TestPriorityBucketsSparesRetiredLotStillCoveredByASuccessor is the data-loss
// case. A retired lot's bucket holds ordinary cached objects of a namespace that
// is still live — renewal only replaced the reservation, it did not orphan the
// data. Selecting it as a past-expiration target meant tier-1 drained it
// wholesale, deleting the pre-rollover half of a perfectly healthy namespace.
func TestPriorityBucketsSparesRetiredLotStillCoveredByASuccessor(t *testing.T) {
	m := newCoreTestManager(t)
	now := time.Now().UnixMilli()
	hour := int64(3600_000)

	mustAdd := func(s core.LotSpec) {
		t.Helper()
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1}})
	// The retired generation: expired an hour ago, deletion still ahead.
	mustAdd(core.LotSpec{LotName: oldGeneration, Owner: "fed", Parents: []string{"root"},
		Paths: []core.PathSpec{{Path: "/atlas", Recursive: true}},
		MPA: core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1,
			CreationTime: now - 2*hour, ExpirationTime: now - hour, DeletionTime: now + 24*hour}})
	// Its live successor on the same path.
	mustAdd(core.LotSpec{LotName: newGeneration, Owner: "fed", Parents: []string{"root"},
		Paths: []core.PathSpec{{Path: "/atlas", Recursive: true}},
		MPA: core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1,
			CreationTime: now - hour, ExpirationTime: now + 24*hour, DeletionTime: now + 48*hour}})

	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	require.NoError(t, err)
	defer cdb.Close()

	const oldNS, newNS NamespaceID = 50, 51
	li := newLotIndex()
	require.NoError(t, li.rebuildFromManager(m))

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		lotIndex:     li,
		namespaceMap: map[string]NamespaceID{oldGeneration: oldNS, newGeneration: newNS, "root": 52},
	}

	// The retired generation still holds the namespace's pre-rollover objects.
	mustSeed(t, cdb, 3, oldNS, 4000)

	for _, target := range pc.priorityBuckets(3) {
		if target.bucket == oldNS {
			require.GreaterOrEqual(t, target.maxBytes, int64(0),
				"a retired lot whose path a live successor still covers must not be drained wholesale")
		}
	}
}
