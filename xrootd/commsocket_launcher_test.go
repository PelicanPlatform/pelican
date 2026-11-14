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
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// fdIsOpen reports whether a descriptor is still valid in this process.
func fdIsOpen(fd int) bool {
	if fd < 0 {
		return false
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
	return errno == 0
}

// TestConfigureLaunchersKeepsXrootdControlFds covers the interaction between
// CMSD and the control socketpair registry.
//
// Pelican keeps both ends of the xrootd launcher's socketpair for the process
// lifetime: fds[0] carries CA/cert updates (sendChildFD) and fds[1] relays kill
// signals under DropPrivileges (KillFunc); the child inherits its own copy of
// fds[1]. Registering a launcher's pair replaces -- and closes -- whatever was
// registered before, which is right when a launcher is genuinely being
// replaced, but the cmsd launcher is an *additional* daemon in the same
// process. With Origin.EnableCmsd defaulting on, building it used to close the
// xrootd launcher's still-live descriptors before its child had even started,
// so the fd baked into the child's environment was closed (or, once the parent
// opened anything else, recycled to point at an unrelated file) and KillFunc
// later wrote a kill frame into whatever now owned that number.
func TestConfigureLaunchersKeepsXrootdControlFds(t *testing.T) {
	for _, tc := range []struct {
		name        string
		enableCache bool
	}{
		{"origin", false},
		{"cache", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			t.Cleanup(func() {
				closePairFds(g_origin_fds)
				closePairFds(g_cache_fds)
				g_origin_fds = [2]int{-1, -1}
				g_cache_fds = [2]int{-1, -1}
				server_utils.ResetTestState()
			})

			runDir := t.TempDir()
			if tc.enableCache {
				require.NoError(t, param.Cache_RunLocation.Set(runDir))
			} else {
				require.NoError(t, param.Origin_RunLocation.Set(runDir))
			}

			launchers, err := ConfigureLaunchers(false, "/dev/null", true /* useCMSD */, tc.enableCache)
			require.NoError(t, err)
			require.Len(t, launchers, 2, "expected an xrootd and a cmsd launcher")

			xrootdLauncher, ok := launchers[0].(UnprivilegedXrootdLauncher)
			require.True(t, ok, "first launcher should be the unprivileged xrootd launcher")
			cmsdLauncher, ok := launchers[1].(UnprivilegedXrootdLauncher)
			require.True(t, ok, "second launcher should be the unprivileged cmsd launcher")
			t.Cleanup(func() {
				closePairFds(cmsdLauncher.fds)
			})

			// The xrootd launcher still owns both of its descriptors.
			require.True(t, fdIsOpen(xrootdLauncher.fds[0]),
				"xrootd control fd[0] was closed while the launcher still holds it")
			require.True(t, fdIsOpen(xrootdLauncher.fds[1]),
				"xrootd control fd[1] was closed while the launcher still holds it")

			// And it -- not cmsd -- is what the process-wide control channel
			// points at, so sendChildFD and KillFunc reach the right child.
			registered := g_origin_fds
			if tc.enableCache {
				registered = g_cache_fds
			}
			require.Equal(t, xrootdLauncher.fds, registered,
				"the registered control pair must be the xrootd launcher's, not cmsd's")
		})
	}
}
