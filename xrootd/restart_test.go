//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package xrootd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/daemon"
)

// TestStoreRestartInfo tests that restart info is stored correctly
func TestStoreRestartInfo(t *testing.T) {
	restartInfos = nil
	t.Cleanup(func() { restartInfos = nil })

	var launchers []daemon.Launcher
	egrp := &errgroup.Group{}
	callback := func(port int) {}

	StoreRestartInfo(context.Background(), launchers, nil, egrp, callback, true, false, true, nil)
	StoreRestartInfo(context.Background(), launchers, nil, egrp, callback, false, true, false, nil)

	require.Len(t, restartInfos, 2)

	var cacheInfo, originInfo *restartInfo
	for idx := range restartInfos {
		if restartInfos[idx].isCache {
			cacheInfo = &restartInfos[idx]
		} else {
			originInfo = &restartInfos[idx]
		}
	}

	require.NotNil(t, cacheInfo)
	require.NotNil(t, originInfo)

	assert.True(t, cacheInfo.isCache)
	assert.False(t, cacheInfo.useCMSD)
	assert.True(t, cacheInfo.privileged)

	assert.False(t, originInfo.isCache)
	assert.True(t, originInfo.useCMSD)
	assert.False(t, originInfo.privileged)
	assert.NotNil(t, originInfo.egrp)
	assert.NotNil(t, originInfo.callback)
}

func TestStoreRestartInfoReplacesByRole(t *testing.T) {
	restartInfos = nil
	t.Cleanup(func() { restartInfos = nil })

	var launchers []daemon.Launcher
	egrp := &errgroup.Group{}

	StoreRestartInfo(context.Background(), launchers, nil, egrp, func(int) {}, true, false, false, nil)
	require.Len(t, restartInfos, 1)

	StoreRestartInfo(context.Background(), launchers, nil, egrp, func(int) {}, true, true, true, nil)

	require.Len(t, restartInfos, 1)
	assert.True(t, restartInfos[0].useCMSD)
	assert.True(t, restartInfos[0].privileged)
}

// TestRestartXrootd_NoProcesses tests restart with no running processes
func TestRestartXrootd_NoProcesses(t *testing.T) {
	// This is a minimal test that just checks the restart flow doesn't panic
	// when there are no processes to kill
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var launchers []daemon.Launcher
	egrp := &errgroup.Group{}
	callback := func(int) {}
	StoreRestartInfo(context.Background(), launchers, []int{999999, 999998}, egrp, callback, false, false, false, nil)

	// Try to restart with empty PID list - should fail since there's no xrootd config
	_, err := RestartXrootd(ctx, []int{})

	// We expect this to fail because there's no config set up
	// The important thing is it doesn't panic
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to reconfigure XRootD")
}
