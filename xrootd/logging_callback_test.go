//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
)

type mockLauncher struct{}

func (m *mockLauncher) Name() string                                             { return "mock" }
func (m *mockLauncher) Launch(ctx context.Context) (context.Context, int, error) { return ctx, 0, nil }
func (m *mockLauncher) KillFunc() func(pid int, sig int) error {
	return func(pid int, sig int) error { return nil }
}

func TestXrootdLoggingCallbackRestartsAndUpdatesPids(t *testing.T) {
	param.ClearCallbacks()
	ClearXrootdDaemons()
	restartInfos = []restartInfo{
		{launchers: []daemon.Launcher{&mockLauncher{}}, isCache: true, pids: []int{10}},
		{launchers: []daemon.Launcher{&mockLauncher{}}, isCache: false, pids: []int{20}},
	}
	t.Cleanup(func() { restartInfos = nil })

	restartCalled := make(chan []int, 1)
	restartXrootdFn = func(ctx context.Context, oldPids []int) ([]int, error) {
		if oldPids == nil {
			oldPids = collectTrackedPIDs(restartInfos)
		}
		restartCalled <- append([]int(nil), oldPids...)
		return []int{111, 222}, nil
	}
	t.Cleanup(func() { restartXrootdFn = RestartXrootd })

	require.NoError(t, param.Set("Logging.Origin.Cms", "info"))
	require.NoError(t, param.Set("Logging.Cache.Pfc", "info"))

	RegisterXrootdLoggingCallback()

	require.NoError(t, param.Set("Logging.Cache.Pfc", "debug"))

	var seenOld []int
	require.Eventually(t, func() bool {
		select {
		case seenOld = <-restartCalled:
			return true
		default:
			return false
		}
	}, time.Second, 25*time.Millisecond)

	assert.ElementsMatch(t, []int{10, 20}, seenOld)
}

func TestXrootdLoggingCallbackIgnoresNonXrootdLogging(t *testing.T) {
	param.ClearCallbacks()
	ClearXrootdDaemons()
	restartInfos = []restartInfo{{launchers: []daemon.Launcher{&mockLauncher{}}, isCache: false, pids: []int{30}}}
	t.Cleanup(func() { restartInfos = nil })

	restartCalled := make(chan struct{}, 1)
	restartXrootdFn = func(ctx context.Context, oldPids []int) ([]int, error) {
		restartCalled <- struct{}{}
		return []int{333}, nil
	}
	t.Cleanup(func() { restartXrootdFn = RestartXrootd })

	require.NoError(t, param.Set("Logging.Level", "info"))
	RegisterXrootdLoggingCallback()

	require.NoError(t, param.Set("Logging.Level", "debug"))

	time.Sleep(200 * time.Millisecond)
	select {
	case <-restartCalled:
		t.Fatalf("unexpected restart for non-xrootd logging change")
	default:
	}
}
