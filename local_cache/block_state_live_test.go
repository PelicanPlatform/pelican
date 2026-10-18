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
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeldBlockStateSurvivesExpiry checks that a block state somebody still
// holds is handed back when its cache entry expires and is reloaded, so that
// blocks written through the reloaded state are visible to the holder.  An
// explicit invalidation still starts afresh.
func TestHeldBlockStateSurvivesExpiry(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	held, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)

	// What the TTL does to an idle entry.
	env.storage.blockStates.Delete(env.hash)

	// A writer arriving now gets the state from a fresh load.
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:BlockDataSize])
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	reloaded, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.Same(t, held, reloaded, "a held state must not be replaced by expiry")
	assert.True(t, held.Contains(0), "the holder must see what was written after the expiry")

	env.storage.InvalidateSharedBlockState(env.hash)
	fresh, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.NotSame(t, held, fresh, "invalidation starts a new state")
	assert.True(t, fresh.Contains(0), "the new state is loaded from the database")
}

// TestInvalidationDuringALoadIsNotUndone checks that a block-state load
// that reads the database before an object is deleted, and would insert
// its result after, does not bring the deleted object's blocks back: the
// load starts over, and the state it inserts is the deleted object's empty
// one.
func TestInvalidationDuringALoadIsNotUndone(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:BlockDataSize])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	// Nobody holds a state now, so the next lookup reads the database.
	env.storage.InvalidateSharedBlockState(env.hash)

	attempts := 0
	env.storage.blockStates.beforeInsert = func(h InstanceHash) {
		attempts++
		if attempts == 1 {
			// The load has read block 0 as present; the object goes now.
			require.NoError(t, env.storage.Delete(h))
		}
	}
	got, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "the interrupted load must start over")
	assert.False(t, got.Contains(0), "a deleted object's block must not come back")
	again, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.Same(t, got, again)
}

// TestInvalidationDuringALoadOfAHeldStateIsNotUndone is the same race on
// the path that hands back a state still held elsewhere: a load that found
// the held state before the object was deleted must not reinstate it.
func TestInvalidationDuringALoadOfAHeldStateIsNotUndone(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	held, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:BlockDataSize])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	require.True(t, held.Contains(0))
	// What the TTL does to an idle entry; the holder keeps it live.
	env.storage.blockStates.Delete(env.hash)

	attempts := 0
	env.storage.blockStates.beforeInsert = func(h InstanceHash) {
		attempts++
		if attempts == 1 {
			require.NoError(t, env.storage.Delete(h))
		}
	}
	got, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "the interrupted load must start over")
	assert.NotSame(t, held, got, "a state invalidated during the load must not be reinstated")
	assert.False(t, got.Contains(0), "a deleted object's block must not come back")
	runtime.KeepAlive(held)
}
