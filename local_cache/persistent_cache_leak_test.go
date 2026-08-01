//go:build !windows

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
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_utils"
)

// TestPersistentCacheFailedInitDrainsErrgroup asserts that a failed
// NewPersistentCache leaves nothing running in the caller's errgroup.
//
// NewPersistentCache launches background workers (the storage manager's TTL
// eviction loops) partway through construction, before setup steps that can
// still fail — federation discovery, client init, transfer-engine creation.
// Those workers are launched on the caller's errgroup and only ever exit when
// something calls Stop() on them; cancelling the context does not reach them.
//
// This matters because callers own that errgroup and eventually block on
// egrp.Wait(). If a construction failure leaves workers behind, Wait() never
// returns, so a caller that correctly handles the error still hangs at
// shutdown: the process cannot exit, and a test binary runs to its timeout
// instead of reporting the failure.
func TestPersistentCacheFailedInitDrainsErrgroup(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	// No federation is configured, so the federation lookup partway through
	// NewPersistentCache fails.  Everything before it — the database and the
	// storage manager, including its background workers — has already been
	// built by then.
	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.Error(t, err, "expected construction to fail without a configured federation")
	require.Nil(t, pc)
	// Pin where it failed. The point is that construction gets *past* the
	// storage manager before giving up; if it ever started failing earlier the
	// errgroup would drain trivially and this test would pass while covering
	// nothing.
	require.ErrorContains(t, err, "failed to get federation info")

	// Cancelling the context is the only shutdown lever the caller has left:
	// the failure returned no handle to close.
	cancel()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_ = egrp.Wait()
	}()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer waitCancel()
	select {
	case <-drained:
	case <-waitCtx.Done():
		t.Fatal("errgroup did not drain after context cancellation: NewPersistentCache " +
			"left background workers running when it returned an error")
	}
}

// TestStorageManagerCloseIsSafeWithoutEvictionLoops asserts that closing a
// storage manager returns even when its TTL eviction loops were never started,
// and that closing twice is safe.
//
// Stopping a ttlcache hands the eviction loop a value over an unbuffered
// channel and waits for it to be received, so it blocks forever with no loop
// running. A read-only manager -- what the offline introspection subcommands
// build -- never starts those loops, so an unguarded Close deadlocks on exit
// after the command has already done its work and printed its output.
func TestStorageManagerCloseIsSafeWithoutEvictionLoops(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	tmpDir := t.TempDir()
	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)

	// Build a writable manager first so the disk mappings the read-only
	// variant loads actually exist.
	writable, err := NewStorageManager(db, []string{tmpDir}, InlineThreshold, egrp)
	require.NoError(t, err)
	// First close stops the eviction loops; the goroutine below closes it a
	// second time.
	writable.Close()

	readOnly, err := NewStorageManagerReadOnly(tmpDir, db)
	require.NoError(t, err)

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		readOnly.Close()
		// A second Close must be safe too: the eviction loops are gone either
		// way, and a caller that closes defensively should not hang.
		readOnly.Close()
		// And on a manager whose loops *were* started: the first Close stopped
		// them, so the second finds no reader for its stop signal. This is the
		// case the claim on Close is really about -- the read-only pair above
		// never had the loops running, so both of its calls are declined by the
		// same condition.
		writable.Close()
	}()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	select {
	case <-closed:
	case <-waitCtx.Done():
		t.Fatal("Close blocked on a storage manager whose eviction loops were never started")
	}

	require.NoError(t, db.Close())
	cancel()
	require.NoError(t, egrp.Wait())
}
