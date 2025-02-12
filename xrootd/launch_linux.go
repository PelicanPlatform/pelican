//go:build linux

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
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
)

func doWait(pid int) error {
	for {
		var wstatus syscall.WaitStatus
		wpid, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			return err
		}
		if wpid != pid {
			return errors.New("Internal failure when waiting for command completion")
		}
		log.Debugln("Pid", pid, "exited with status", int(wstatus))
		if wstatus.Exited() {
			if estatus := wstatus.ExitStatus(); estatus != 0 {
				return errors.Errorf("Daemon exited with status %d", estatus)
			}
			return nil
		} else if wstatus.Continued() || wstatus.Stopped() {
			continue
		} else if wstatus.Signaled() {
			return errors.Errorf("Daemon exited with signal %s", wstatus.Signal().String())
		}
		return errors.Errorf("Daemon exited in unknown status %d", wstatus)
	}
}

func findDaemon(daemonName string) (string, error) {
	path_env := os.Getenv("PATH")
	paths := append(strings.Split(path_env, ":"), "/usr/bin", "/bin")
	for _, directory := range paths {
		testPath := filepath.Join(directory, daemonName)
		if syscall.Access(testPath, 1) == nil {
			return testPath, nil
		}
	}
	return "", errors.Errorf("No executable by name of %s found", daemonName)
}

func (plauncher PrivilegedXrootdLauncher) Launch(ctx context.Context) (context.Context, int, error) {
	readStdout, writeStdout, err := os.Pipe()
	if err != nil {
		return ctx, -1, errors.Wrapf(err, "Unable to create stdout pipe for %s", plauncher.Name())
	}
	readStderr, writeStderr, err := os.Pipe()
	if err != nil {
		return ctx, -1, errors.Wrapf(err, "Unable to create stderr pipe for %s", plauncher.Name())
	}

	xrootdRun := param.Origin_RunLocation.GetString()
	pidFile := filepath.Join(xrootdRun, "xrootd.pid")

	executable, err := findDaemon(plauncher.Name())
	if err != nil {
		return ctx, -1, err
	}
	launcher := cap.NewLauncher(executable, []string{plauncher.Name(), "-f", "-s", pidFile, "-c", plauncher.configPath}, nil)
	launcher.Callback(func(attrs *syscall.ProcAttr, _ interface{}) error {
		attrs.Files[1] = writeStdout.Fd()
		attrs.Files[2] = writeStderr.Fd()
		return nil
	})
	iab := cap.NewIAB()
	// Set bounding capabilities: even if xrootd execs a setuid binary, it should never
	// be able to get anything but SETUID and SETGID
	bound_caps, err := cap.FromText("all=eip")
	if err != nil {
		return ctx, -1, err
	}
	if err = bound_caps.SetFlag(cap.Inheritable, false, cap.SETUID, cap.SETGID); err != nil {
		return ctx, -1, err
	}
	if err = iab.Fill(cap.Bound, bound_caps, cap.Inheritable); err != nil {
		return ctx, -1, err
	}

	// Raising the ambient capabilities will also set the inheritable caps
	amb_caps := cap.NewSet()
	if err = amb_caps.SetFlag(cap.Inheritable, true, cap.SETUID, cap.SETGID); err != nil {
		return ctx, -1, err
	}
	if err = iab.Fill(cap.Inh, amb_caps, cap.Inheritable); err != nil {
		return ctx, -1, err
	}
	if err = iab.Fill(cap.Amb, amb_caps, cap.Inheritable); err != nil {
		return ctx, -1, err
	}
	launcher.SetIAB(iab)

	gid, err := config.GetDaemonGID()
	if err != nil {
		return ctx, -1, errors.Wrap(err, "Unable to determine xrootd daemon GID")
	}
	launcher.SetGroups(gid, nil)
	uid, err := config.GetDaemonUID()
	if err != nil {
		return ctx, -1, errors.Wrap(err, "Unable to determine xrootd daemon UID")
	}
	launcher.SetUID(uid)

	pid, err := launcher.Launch(nil)
	if err != nil {
		return ctx, -1, err
	}

	writeStdout.Close()
	writeStderr.Close()
	go daemon.ForwardCommandToLogger(ctx, plauncher.Name(), readStdout, readStderr)

	ctx_result, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(doWait(pid))
	}()
	return ctx_result, pid, nil
}
