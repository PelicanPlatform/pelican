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

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/server_structs"
)

// StoreRestartInfo stores the information needed for restarting XRootD
// Windows stub - restart not implemented on Windows
func StoreRestartInfo(launchers []daemon.Launcher, egrp *errgroup.Group, callback func(int), cache bool, cmsd bool, priv bool) {
	// No-op on Windows
}

// RestartXrootd gracefully restarts the XRootD server processes
// Windows stub - restart not implemented on Windows
func RestartXrootd(ctx context.Context, oldPids []int) (newPids []int, err error) {
	return nil, errors.New("XRootD restart is not supported on Windows")
}

// RestartServer is a helper function that restarts XRootD and updates the server's PIDs
// Windows stub - restart not implemented on Windows
func RestartServer(ctx context.Context, server server_structs.XRootDServer) error {
	return errors.New("XRootD restart is not supported on Windows")
}
