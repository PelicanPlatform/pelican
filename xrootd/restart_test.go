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

package xrootd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/daemon"
)

// TestStoreRestartInfo tests that restart info is stored correctly
func TestStoreRestartInfo(t *testing.T) {
	restartInfos = nil
	t.Cleanup(func() { restartInfos = nil })

	launch := func(ls []daemon.Launcher) ([]int, error) { return nil, nil }

	StoreRestartInfo(nil, launch, nil, true, false, true)
	StoreRestartInfo(nil, launch, nil, false, true, false)

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

	assert.NotNil(t, cacheInfo.launch)
	assert.True(t, cacheInfo.isCache)
	assert.False(t, cacheInfo.useCMSD)
	assert.True(t, cacheInfo.privileged)

	assert.NotNil(t, originInfo.launch)
	assert.False(t, originInfo.isCache)
	assert.True(t, originInfo.useCMSD)
	assert.False(t, originInfo.privileged)
}

func TestStoreRestartInfoReplacesByRole(t *testing.T) {
	restartInfos = nil
	t.Cleanup(func() { restartInfos = nil })

	launch := func(ls []daemon.Launcher) ([]int, error) { return nil, nil }

	StoreRestartInfo(nil, launch, nil, true, false, false)
	require.Len(t, restartInfos, 1)

	StoreRestartInfo(nil, launch, nil, true, true, true)

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

	launch := func(ls []daemon.Launcher) ([]int, error) { return nil, nil }
	StoreRestartInfo([]int{999999, 999998}, launch, nil, false, false, false)

	// Try to restart with empty PID list - should fail since there's no xrootd config
	_, err := RestartXrootd(ctx, ctx, []int{})

	// We expect this to fail because there's no config set up
	// The important thing is it doesn't panic
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to reconfigure XRootD")
}

// TestRestartXrootd_PreRestartHookCalled verifies global pre-restart is called once
func TestRestartXrootd_PreRestartHookCalled(t *testing.T) {
	t.Cleanup(ResetRestartState)

	// Stub out ConfigXrootd and ConfigureLaunchers; the test doesn't need real config
	configXrootdFn = func(_ context.Context, _ bool) (string, error) { return "/fake/xrootd.cfg", nil }
	configureLaunchersFn = func(_ bool, _ string, _ bool, _ bool) ([]daemon.Launcher, error) {
		return nil, nil
	}

	hookCalls := 0
	preRestartFn = func(_ context.Context, _ []restartInfo) error {
		hookCalls++
		return nil
	}
	postRestartFn = func(_ context.Context, _ []restartInfo) error { return nil }

	// Return an arbitrary non-zero PID to emulate success.
	launch := func(ls []daemon.Launcher) ([]int, error) { return []int{12345}, nil }
	StoreRestartInfo([]int{999999}, launch, nil, false, false, false) // origin
	StoreRestartInfo([]int{999998}, launch, nil, true, false, false)  // cache

	ctx := context.Background()
	_, err := RestartXrootd(ctx, ctx, []int{999999, 999998})
	require.NoError(t, err)
	assert.Equal(t, 1, hookCalls, "global pre-restart hook should be called exactly once")
}

// TestRestartXrootd_PostRestartHookCalled verifies global post-restart is called once
func TestRestartXrootd_PostRestartHookCalled(t *testing.T) {
	t.Cleanup(ResetRestartState)

	// Stub out ConfigXrootd and ConfigureLaunchers; the test doesn't need real config
	configXrootdFn = func(_ context.Context, _ bool) (string, error) { return "/fake/xrootd.cfg", nil }
	configureLaunchersFn = func(_ bool, _ string, _ bool, _ bool) ([]daemon.Launcher, error) {
		return nil, nil
	}

	postCalls := 0
	preRestartFn = func(_ context.Context, _ []restartInfo) error { return nil }
	postRestartFn = func(_ context.Context, _ []restartInfo) error {
		postCalls++
		return nil
	}

	// Return an arbitrary non-zero PID to emulate success.
	launch := func(ls []daemon.Launcher) ([]int, error) { return []int{12345}, nil }
	StoreRestartInfo([]int{999999}, launch, nil, false, false, false) // origin
	StoreRestartInfo([]int{999998}, launch, nil, true, false, false)  // cache

	ctx := context.Background()
	_, err := RestartXrootd(ctx, ctx, []int{999999, 999998})
	require.NoError(t, err)
	assert.Equal(t, 1, postCalls, "global post-restart hook should be called exactly once")
}

func TestRestartXrootd_HooksNotCalledWithoutRestartInfos(t *testing.T) {
	t.Cleanup(ResetRestartState)

	preCalls := 0
	postCalls := 0
	preRestartFn = func(_ context.Context, _ []restartInfo) error {
		preCalls++
		return nil
	}
	postRestartFn = func(_ context.Context, _ []restartInfo) error {
		postCalls++
		return nil
	}

	_, err := RestartXrootd(context.Background(), context.Background(), []int{999999})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restart requested before storing launcher information")
	assert.Equal(t, 0, preCalls, "pre-restart hook should not be called without tracked restart info")
	assert.Equal(t, 0, postCalls, "post-restart hook should not be called without tracked restart info")
}

// TestRestartXrootd_LaunchCtxOutlivesRestartCtx verifies
// that the context used to start the new daemon
// is the server-lifetime context captured in the launch closure,
// not the short-lived context passed to RestartXrootd.
func TestRestartXrootd_LaunchCtxOutlivesRestartCtx(t *testing.T) {
	t.Cleanup(ResetRestartState)

	// Stub out ConfigXrootd and ConfigureLaunchers; the test doesn't need real config
	configXrootdFn = func(_ context.Context, _ bool) (string, error) { return "/fake/xrootd.cfg", nil }
	configureLaunchersFn = func(_ bool, _ string, _ bool, _ bool) ([]daemon.Launcher, error) {
		return nil, nil
	}

	// serverCtx represents the long-lived server-lifetime context
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	// launchCtxWasAlive is set inside the closure
	// to record whether the server context is still alive when launch is called
	launchCtxWasAlive := false
	launch := func(ls []daemon.Launcher) ([]int, error) {
		launchCtxWasAlive = serverCtx.Err() == nil
		// Return an arbitrary non-zero PID to emulate success
		return []int{12345}, nil
	}

	StoreRestartInfo([]int{999999}, launch, nil, false, false, false)

	// Simulate handleXrootdLoggingChange: use a short-lived context
	// that is already cancelled
	// by the time RestartXrootd's work reaches the launch step
	shortCtx, shortCancel := context.WithCancel(context.Background())
	shortCancel()

	_, err := RestartXrootd(shortCtx, serverCtx, []int{999999})
	require.NoError(t, err)

	// The server's launch context must still be alive
	assert.True(t, launchCtxWasAlive, "the launch closure used a context that was already cancelled")
}

func TestRestartXrootd_PreRestartCalledOnceForMultipleRoles(t *testing.T) {
	t.Cleanup(ResetRestartState)
	configXrootdFn = func(_ context.Context, _ bool) (string, error) { return "/fake/xrootd.cfg", nil }
	configureLaunchersFn = func(_ bool, _ string, _ bool, _ bool) ([]daemon.Launcher, error) { return nil, nil }

	preCalls := 0
	preRestartFn = func(_ context.Context, infos []restartInfo) error {
		preCalls++
		assert.Len(t, infos, 2)
		return nil
	}
	postRestartFn = func(_ context.Context, _ []restartInfo) error { return nil }

	launch := func(ls []daemon.Launcher) ([]int, error) { return []int{12345}, nil }
	StoreRestartInfo([]int{999999}, launch, nil, false, false, false)
	StoreRestartInfo([]int{999998}, launch, nil, true, false, false)

	_, err := RestartXrootd(context.Background(), context.Background(), []int{999999, 999998})
	require.NoError(t, err)
	assert.Equal(t, 1, preCalls)
}

func TestRestartXrootd_PostRestartErrorPropagates(t *testing.T) {
	t.Cleanup(ResetRestartState)
	configXrootdFn = func(_ context.Context, _ bool) (string, error) { return "/fake/xrootd.cfg", nil }
	configureLaunchersFn = func(_ bool, _ string, _ bool, _ bool) ([]daemon.Launcher, error) { return nil, nil }
	preRestartFn = func(_ context.Context, _ []restartInfo) error { return nil }
	postRestartFn = func(_ context.Context, _ []restartInfo) error { return errors.New("post failed") }

	launch := func(ls []daemon.Launcher) ([]int, error) { return []int{12345}, nil }
	StoreRestartInfo([]int{999999}, launch, nil, false, false, false)

	_, err := RestartXrootd(context.Background(), context.Background(), []int{999999})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post failed")
}
