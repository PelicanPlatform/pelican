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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestNewTransferEngineWorkerCount verifies that the worker count is taken from
// Client.WorkerCount by default and can be overridden explicitly (as the cache
// does with Cache.WorkerCount).
func TestNewTransferEngineWorkerCount(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{
		param.Client_WorkerCount: 3,
	})

	t.Run("default uses Client.WorkerCount", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		te, err := NewTransferEngine(ctx)
		require.NoError(t, err)
		defer func() { _ = te.Shutdown() }()
		assert.Equal(t, 3, te.workersActive)
	})

	t.Run("explicit worker count overrides the client default", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		te, err := NewTransferEngineWithWorkers(ctx, 100)
		require.NoError(t, err)
		defer func() { _ = te.Shutdown() }()
		assert.Equal(t, 100, te.workersActive)
	})

	t.Run("non-positive worker count is rejected", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := NewTransferEngineWithWorkers(ctx, 0)
		require.Error(t, err)
	})
}
