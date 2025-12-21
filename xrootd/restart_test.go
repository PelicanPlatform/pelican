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

// TestRestartConcurrentProtection tests that only one restart can happen at a time
func TestRestartConcurrentProtection(t *testing.T) {
	// Store dummy restart info
	var launchers []daemon.Launcher
	egrp := &errgroup.Group{}
	callback := func(int) {}
	StoreRestartInfo(launchers, egrp, callback, false, false, false)

	// Try to start two restarts concurrently
	done := make(chan struct{})
	var firstSuccess, secondSuccess bool

	go func() {
		firstSuccess = restartMutex.TryLock()
		if firstSuccess {
			// Simulate a long restart
			time.Sleep(100 * time.Millisecond)
			restartMutex.Unlock()
		}
		done <- struct{}{}
	}()

	// Give first goroutine time to acquire lock
	time.Sleep(10 * time.Millisecond)

	go func() {
		secondSuccess = restartMutex.TryLock()
		if secondSuccess {
			restartMutex.Unlock()
		}
		done <- struct{}{}
	}()

	// Wait for both goroutines
	<-done
	<-done

	// One should succeed, one should fail
	assert.True(t, firstSuccess != secondSuccess, "One restart should succeed and one should fail")
}

// TestStoreRestartInfo tests that restart info is stored correctly
func TestStoreRestartInfo(t *testing.T) {
	var launchers []daemon.Launcher
	egrp := &errgroup.Group{}
	callback := func(port int) {}

	StoreRestartInfo(launchers, egrp, callback, true, false, true)

	assert.Equal(t, true, isCache)
	assert.Equal(t, false, useCMSD)
	assert.Equal(t, true, privileged)
	assert.NotNil(t, currentEgrp)
	assert.NotNil(t, currentCallback)
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
	StoreRestartInfo(launchers, egrp, callback, false, false, false)

	// Try to restart with empty PID list - should fail since there's no xrootd config
	_, err := RestartXrootd(ctx, []int{})

	// We expect this to fail because there's no config set up
	// The important thing is it doesn't panic
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to reconfigure XRootD")
}
