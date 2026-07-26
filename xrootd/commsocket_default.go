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
	"os"
	"syscall"
)

var (
	g_origin_fds [2]int
	g_cache_fds  [2]int
)

func init() {
	g_origin_fds = [2]int{-1, -1}
	g_cache_fds = [2]int{-1, -1}
}

// closePairFds closes both still-open ends of a parent-held socketpair.
// The parent keeps fds[0] (the control end used by sendChildFD) and
// fds[1] (the signal end, a copy of which was handed to the child via
// ExtraFiles). Neither is closed anywhere on the normal shutdown path,
// so when a new xrootd is launched into the same process — most visibly
// in back-to-back federation unit tests — the previous pair is orphaned
// and leaks two descriptors. On macOS (kqueue) these accumulate until
// the 256 open-file limit is hit and sockets start failing with
// "invalid argument". Closing the prior pair before overwriting the
// global keeps the descriptor count flat across relaunches. The old
// child process is already gone by the time a replacement is set, so
// closing is safe; a -1 sentinel closes nothing.
func closePairFds(fds [2]int) {
	if fds[0] != -1 {
		_ = syscall.Close(fds[0])
	}
	if fds[1] != -1 && fds[1] != fds[0] {
		_ = syscall.Close(fds[1])
	}
}

// Set the global copy of the origin's communication FDs
// To be used later for sending updated CAs and host certificates.
func setOriginFds(fds [2]int) {
	closePairFds(g_origin_fds)
	g_origin_fds = fds
}

// Set the global copy of the cache's communication FDs
// To be used later for sending updated CAs and host certificates.
func setCacheFds(fds [2]int) {
	closePairFds(g_cache_fds)
	g_cache_fds = fds
}

// Send a provided file descriptor to a child xrootd process.
// If the `origin` is true, it'll send the FD to origin;
// otherwise, it'll send it to cache.
// If the origin/cache FD is not set, it'll return nil.
func sendChildFD(origin bool, cmd int, fp *os.File) error {
	rights := syscall.UnixRights(int(fp.Fd()))
	if origin {
		if g_origin_fds[0] == -1 {
			return nil
		}
		return syscall.Sendmsg(g_origin_fds[0], []byte{byte(cmd)}, rights, nil, 0)
	}
	if g_cache_fds[0] == -1 {
		return nil
	}
	return syscall.Sendmsg(g_cache_fds[0], []byte{byte(cmd)}, rights, nil, 0)
}

// Close the child socket. Closes both parent-held ends of the pair and
// resets the global to the -1 sentinel so a later setOriginFds/setCacheFds
// does not attempt to close an already-closed descriptor.
func closeChildSocket(origin bool) error {
	if origin {
		err := syscall.Close(g_origin_fds[0])
		if g_origin_fds[1] != -1 && g_origin_fds[1] != g_origin_fds[0] {
			_ = syscall.Close(g_origin_fds[1])
		}
		g_origin_fds = [2]int{-1, -1}
		return err
	}
	err := syscall.Close(g_cache_fds[0])
	if g_cache_fds[1] != -1 && g_cache_fds[1] != g_cache_fds[0] {
		_ = syscall.Close(g_cache_fds[1])
	}
	g_cache_fds = [2]int{-1, -1}
	return err
}
