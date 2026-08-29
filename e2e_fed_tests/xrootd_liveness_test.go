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

package fed_tests

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// livenessConfig shortens the hidden liveness knobs so the monitor reacts within the
// lifetime of a unit test instead of the ten minutes it allows in production.
const livenessConfig = `
Xrootd:
  LivenessCheckInterval: 1s
  LivenessCheckTimeout: 2s
  LivenessMaxUnresponsiveTime: 3s
`

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil || process == nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// TestXRootDLivenessKillsHungProcess wedges XRootD with SIGSTOP -- the one way to stall it
// indefinitely -- and verifies Pelican notices and shuts the daemon down.  A stopped process
// still completes TCP handshakes out of the kernel's listen backlog, so this also guards
// against the check regressing to a bare connect().
func TestXRootDLivenessKillsHungProcess(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	ft := fed_test_utils.NewFedTest(t, bothPubNamespaces+livenessConfig)
	// Killing XRootD takes the rest of the server down with it; that is the point of
	// the test, not a teardown failure.
	ft.AllowServerFailure()

	pids := ft.Pids
	require.NotEmpty(t, pids, "no XRootD PIDs were tracked by the federation")

	for _, pid := range pids {
		require.NoError(t, syscall.Kill(pid, syscall.SIGSTOP), "failed to stop PID %d", pid)
	}
	t.Cleanup(func() {
		// Revive anything Pelican did not manage to kill so the process table is
		// left clean even when the assertion below fails.
		for _, pid := range pids {
			if processExists(pid) {
				_ = syscall.Kill(pid, syscall.SIGCONT)
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})

	require.Eventually(t, func() bool {
		for _, pid := range pids {
			if processExists(pid) {
				return false
			}
		}
		return true
	}, 60*time.Second, 250*time.Millisecond, "Pelican did not shut down the wedged XRootD processes %v", pids)
}
