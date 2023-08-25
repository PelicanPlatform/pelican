//go:build linux

package xrootd

import (
	"context"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"kernel.org/pub/linux/libs/security/libcap/cap"
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
		if wstatus.Exited() {
			if estatus := wstatus.ExitStatus(); estatus != 0 {
				return errors.Errorf("Daemon exited with status %d", estatus)
			}
			return nil
		} else if wstatus.Continued() || wstatus.Stopped() {
			continue
		} else if wstatus.Signaled() {
			return errors.Errorf("Daemon exited with signal %s", wstatus.Signal().String())
		} else {
			return errors.Errorf("Daemon exited in unknown status %d", wstatus)
		}
	}
}

func (PrivilegedXrootdLauncher) Launch(ctx context.Context, daemonName string, configPath string) (context.Context, int, error) {
	readStdout, writeStdout, err := os.Pipe()
	if err != nil {
		return ctx, -1, errors.Wrapf(err, "Unable to create stdout pipe for %s", daemonName)
	}
	readStderr, writeStderr, err := os.Pipe()
	if err != nil {
		return ctx, -1, errors.Wrapf(err, "Unable to create stderr pipe for %s", daemonName)
	}

	launcher := cap.NewLauncher(daemonName, []string{"-f", "-c", configPath}, nil)
	launcher.Callback(func(attrs *syscall.ProcAttr, _ interface{}) error {
		err := syscall.Dup3(int(writeStdout.Fd()), 1, 0)
		if err != nil {
			return err
		}
		err = syscall.Dup3(int(writeStderr.Fd()), 2, 0)
		if err != nil {
			return err
		}
		return nil
	})
	iab := cap.NewIAB()
	// Set bounding capabilities: even if xrootd execs a setuid binary, it should never
	// be able to get anything but SETUID and SETGID
	bound_caps, err := cap.FromText("all=eip")
	if err != nil {
		return ctx, -1, err
	}
	bound_caps.SetFlag(cap.Effective, false, cap.SETUID, cap.SETGID)
	bound_caps.SetFlag(cap.Inheritable, false, cap.SETUID, cap.SETGID)
	bound_caps.SetFlag(cap.Permitted, false, cap.SETUID, cap.SETGID)
	iab.Fill(cap.Bound, bound_caps, cap.Effective)
	iab.Fill(cap.Bound, bound_caps, cap.Inheritable)
	iab.Fill(cap.Bound, bound_caps, cap.Permitted)

	pid, err := launcher.Launch(nil)
	if err != nil {
		return ctx, -1, err
	}

	go forwardCommandToLogger(ctx, daemonName, readStdout, readStderr)

	ctx_result, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(doWait(pid))
	}()
	return ctx_result, pid, nil
}
