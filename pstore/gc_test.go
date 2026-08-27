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

package pstore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/local_cache"
)

// The shape of the reclamation queue's boundary, pinned at compile time.
//
// A `pg:i:` entry means either "this version is garbage" or "a write is in
// flight"; deleting the second kind destroys a live upload.  What keeps the two
// apart is that reading the queue yields a queuedInstance, which no delete and
// no index mutation accepts, and that the sole route from one back to an
// instance hash is claim, which runs the interlock.
//
// These assertions fail to *compile* if that boundary is dismantled: if
// collectGarbage goes back to handing out bare hashes, if reclaimInstance starts
// accepting one, or if claim's signature changes so that the check can be
// skipped.  A reviewer who has to delete a line here is being told exactly what
// they are giving up.
var (
	_ func(*Store) ([]queuedInstance, []string, bool, error)                         = (*Store).collectGarbage
	_ func(*Store, queuedInstance) (reclaimOutcome, int64, error)                    = (*Store).reclaimInstance
	_ func(queuedInstance, *Store) (local_cache.InstanceHash, reclaimOutcome, error) = queuedInstance.claim
	_ func(queuedInstance, local_cache.InstanceHash) int                             = queuedInstance.compare
	_ func(string) queuedInstance                                                    = newQueuedInstance
)

// TestReclamationQueueEntriesCannotBypassTheInterlock enforces what the type
// system alone cannot, because everything here is one package.
//
// Within a package an unexported field is still reachable, so queuedInstance
// stops an *accident* -- its hash is a plain string, which no delete accepts --
// but not a determined bypass.  This closes that by reading the package's own
// source and insisting on three properties:
//
//  1. only a method of queuedInstance may touch the raw hash;
//  2. only claim, which performs the pin check and the re-read, may hand one
//     back out;
//  3. only newQueuedInstance may build the type, so there is one place a hash
//     enters it.
//
// Together those mean the single path from the reclamation queue to a deletable
// hash runs through claim.  A change that opens a second path fails here with
// the reason rather than silently shipping.
func TestReclamationQueueEntriesCannotBypassTheInterlock(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		// Tests may reach for the field freely; it is the shipping code that
		// has to be kept honest.
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	pkg := pkgs["pstore"]
	require.NotNil(t, pkg, "the pstore package must parse")

	// Sanity: the rules below are vacuous if the field ever gets renamed, so
	// prove the scan actually found the accessor it is meant to be policing.
	sawClaim := false

	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			owner, onQueuedInstance := "", false
			if isFunc {
				owner = fn.Name.Name
				onQueuedInstance = receiverTypeName(fn) == "queuedInstance"
			}

			if onQueuedInstance && owner == "claim" {
				sawClaim = true
			}

			// (2) A method of queuedInstance other than claim may not return
			// anything the hash can be recovered from.  A String() method would
			// be exactly as dangerous as an exported field.
			if onQueuedInstance && owner != "claim" && fn.Type.Results != nil {
				for _, res := range fn.Type.Results.List {
					name := typeExprName(res.Type)
					assert.NotContains(t, []string{"string", "local_cache.InstanceHash"}, name,
						"queuedInstance.%s returns %s: only claim, which runs the pin check "+
							"and the queue re-read, may yield the hash of a queued entry",
						owner, name)
				}
			}

			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.SelectorExpr:
					// (1) Reading the raw hash is the dangerous act; confine it
					// to the type's own methods, where the reasoning lives.
					if node.Sel.Name == "unsafeHash" {
						assert.True(t, onQueuedInstance,
							"%s reads queuedInstance.unsafeHash: a queue entry may only be "+
								"turned into an instance hash by queuedInstance.claim, which "+
								"performs the pin check and the queue re-read that tell a dead "+
								"version from a write in flight",
							describeDecl(owner, isFunc))
					}
				case *ast.CompositeLit:
					// (3) One constructor, so there is one place a hash becomes
					// a queued entry.
					if typeExprName(node.Type) == "queuedInstance" {
						assert.Equal(t, "newQueuedInstance", owner,
							"%s builds a queuedInstance literal: construct it through "+
								"newQueuedInstance so the queue has a single entry point",
							describeDecl(owner, isFunc))
					}
				}
				return true
			})
		}
	}

	assert.True(t, sawClaim,
		"queuedInstance.claim was not found; the rules above police a name that no longer exists")
}

// receiverTypeName reports the type a method is declared on, or "" for a
// plain function.
func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	return typeExprName(fn.Recv.List[0].Type)
}

// typeExprName renders the identifier, qualified identifier, or pointer target
// a type expression names.  Anything else reports "", which no rule matches.
func typeExprName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeExprName(t.X)
	case *ast.SelectorExpr:
		return typeExprName(t.X) + "." + t.Sel.Name
	}
	return ""
}

// describeDecl names a declaration for a failure message.
func describeDecl(owner string, isFunc bool) string {
	if !isFunc {
		return "a package-level declaration"
	}
	return owner
}

// TestJanitorNeverReclaimsAWriteInFlight is the runtime half: a full sweep run
// at the worst possible moment must leave a live upload alone.
//
// A write tombstones its own version on the reclamation queue before it
// materializes anything, so between beginMaterialize and the commit the entry is
// byte-for-byte what a superseded version looks like.  The pin the writer holds
// is what distinguishes them, and this steps through Close by hand so the sweep
// lands exactly inside that window.
func TestJanitorNeverReclaimsAWriteInFlight(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(8<<10, 17)
	w, err := s.Create("/in-flight")
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)

	require.NoError(t, w.beginMaterialize())
	meta, err := w.materialize()
	require.NoError(t, err)

	// The tombstone is indistinguishable from a work item, which is the whole
	// difficulty.
	queued, _, _, err := s.collectGarbage()
	require.NoError(t, err)
	require.Equal(t, []queuedInstance{newQueuedInstance(string(w.instanceHash))}, queued,
		"a write in flight sits on the queue looking exactly like garbage")

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Zero(t, stats.InstancesFreed, "a sweep must never reclaim a write in flight")
	assert.Zero(t, stats.BytesFreed)
	assert.Equal(t, 1, stats.InstancesPinned, "it is deferred, not dropped")

	stored, err := s.db.GetMetadata(w.instanceHash)
	require.NoError(t, err)
	require.NotNil(t, stored, "the half-built version survived the sweep intact")

	// Repeated passes must not wear it down either: the entry stays queued, so
	// there is no count of attempts after which it is reclaimed anyway.
	for range 3 {
		_, err = s.RunGC(t.Context())
		require.NoError(t, err)
	}
	stillQueued, err := s.instanceQueued(w.instanceHash)
	require.NoError(t, err)
	assert.True(t, stillQueued, "the tombstone is the writer's to clear, not the janitor's")

	finishInterruptedWrite(t, w, meta)

	// The commit withdrew the entry, so the queue is empty and the object reads
	// back exactly as written.
	drainQueue(t, s)
	assertQueueEmpty(t, s)
	got, err := s.ReadAll("/in-flight")
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

// TestReclaimRefusesAWithdrawnQueueEntry covers the second half of the
// interlock, the one a pin check alone would miss.
//
// The janitor works from a snapshot.  A write that commits after the batch is
// taken has both cleared its queue entry and released its pin, so an entry read
// a moment earlier now looks like unpinned garbage.  Re-reading the entry is
// what catches it.
func TestReclaimRefusesAWithdrawnQueueEntry(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(8<<10, 19)
	w, err := s.Create("/withdrawn")
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)

	require.NoError(t, w.beginMaterialize())
	meta, err := w.materialize()
	require.NoError(t, err)

	// The batch is taken while the write is still in flight...
	batch, _, _, err := s.collectGarbage()
	require.NoError(t, err)
	require.Len(t, batch, 1)

	// ...and the write commits before the janitor gets to it.
	finishInterruptedWrite(t, w, meta)

	outcome, freed, err := s.reclaimInstance(batch[0])
	require.NoError(t, err)
	assert.Equal(t, reclaimWithdrawn, outcome,
		"an entry cleared by its own commit is not garbage, pin or no pin")
	assert.Zero(t, freed)

	got, err := s.ReadAll("/withdrawn")
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

// TestReclaimFreesASupersededVersion is the positive control: the interlock
// refuses live writes without also refusing the work it exists to do.
func TestReclaimFreesASupersededVersion(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", randomBytes(8<<10, 23))
	first, err := s.Stat("/obj")
	require.NoError(t, err)
	superseded := instanceHashFor(s.db, first.Generation)

	writeObject(t, s, "/obj", randomBytes(8<<10, 29))

	batch, _, _, err := s.collectGarbage()
	require.NoError(t, err)
	require.Equal(t, []queuedInstance{newQueuedInstance(string(superseded))}, batch)

	outcome, freed, err := s.reclaimInstance(batch[0])
	require.NoError(t, err)
	assert.Equal(t, reclaimFreed, outcome)
	assert.Positive(t, freed, "the freed bytes are the ones credited back to capacity")

	stored, err := s.db.GetMetadata(superseded)
	require.NoError(t, err)
	assert.Nil(t, stored, "the superseded version is gone")
	assertQueueEmpty(t, s)
}

// finishInterruptedWrite completes a write that was stepped through
// beginMaterialize and materialize by hand, performing the rest of what Close
// would have done.
func finishInterruptedWrite(t *testing.T, w *WriteHandle, meta *local_cache.CacheMetadata) {
	t.Helper()

	require.NoError(t, w.install(&Dirent{
		Type:       EntryFile,
		Generation: w.generation,
		Size:       w.written.Load(),
		MTimeNanos: time.Now().UnixNano(),
		Mode:       uint32(defaultFileMode),
	}))
	w.endMaterialize()

	if meta != nil {
		w.store.capacity.settle(w.reserved, meta.PerDirectoryBytes())
	} else {
		w.store.capacity.settle(w.reserved, nil)
	}
	w.reserved = 0
	w.done = true
}
