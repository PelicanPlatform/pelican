//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"bufio"
	"context"
	_ "embed"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type (
	XrootdLauncher interface {
		Launch(ctx context.Context, daemonName string, configPath string) (context.Context, int, error)
	}

	PrivilegedXrootdLauncher struct{}

	UnprivilegedXrootdLauncher struct{}
)

func forwardCommandToLogger(ctx context.Context, daemonName string, cmdStdout io.ReadCloser, cmdStderr io.ReadCloser) {
	cmd_logger := log.WithFields(log.Fields{"daemon": daemonName})
	stdout_scanner := bufio.NewScanner(cmdStdout)
	stdout_lines := make(chan string, 10)

	stderr_scanner := bufio.NewScanner(cmdStderr)
	stderr_lines := make(chan string, 10)
	go func() {
		defer close(stdout_lines)
		for stdout_scanner.Scan() {
			stdout_lines <- stdout_scanner.Text()
		}
	}()
	go func() {
		defer close(stderr_lines)
		for stderr_scanner.Scan() {
			stderr_lines <- stderr_scanner.Text()
		}
	}()
	for {
		select {
		case stdout_line, ok := <-stdout_lines:
			if ok {
				cmd_logger.Info(stdout_line)
			} else {
				stdout_lines = nil
			}
		case stderr_line, ok := <-stderr_lines:
			if ok {
				cmd_logger.Info(stderr_line)
			} else {
				stderr_lines = nil
			}
		}
		if stdout_lines == nil && stderr_lines == nil {
			break
		}
	}
	<-ctx.Done()
}

func (UnprivilegedXrootdLauncher) Launch(ctx context.Context, daemonName string, configPath string) (context.Context, int, error) {
	xrootdRun := viper.GetString("XrootdRun")
	pidFile := filepath.Join(xrootdRun, "xrootd.pid")

	cmd := exec.CommandContext(ctx, daemonName, "-f", "-s", pidFile, "-c", configPath)
	if cmd.Err != nil {
		return ctx, -1, cmd.Err
	}
	cmdStdout, err := cmd.StdoutPipe()
	if err != nil {
		return ctx, -1, err
	}
	cmdStderr, err := cmd.StderrPipe()
	if err != nil {
		return ctx, -1, err
	}

	if config.IsRootExecution() {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		uid, err := config.GetDaemonUID()
		if err != nil {
			return ctx, -1, err
		}
		gid, err := config.GetDaemonGID()
		if err != nil {
			return ctx, -1, err
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}

	if err := cmd.Start(); err != nil {
		return ctx, -1, err
	}
	go forwardCommandToLogger(ctx, daemonName, cmdStdout, cmdStderr)

	ctx_result, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(cmd.Wait())
	}()
	return ctx_result, cmd.Process.Pid, nil
}

func LaunchXrootd(privileged bool, configPath string) (err error) {
	var launcher XrootdLauncher
	if privileged {
		launcher = PrivilegedXrootdLauncher{}
	} else {
		launcher = UnprivilegedXrootdLauncher{}
	}
	ctx := context.Background()

	xrootdCtx, xrootdPid, err := launcher.Launch(ctx, "xrootd", configPath)
	if err != nil {
		return errors.Wrap(err, "Failed to launch xrootd daemon")
	}
	log.Info("Successfully launched xrootd")
	if err := metrics.SetComponentHealthStatus("xrootd", "ok", ""); err != nil {
		return err
	}

	cmsdCtx, cmsdPid, err := launcher.Launch(ctx, "cmsd", configPath)
	if err != nil {
		return errors.Wrap(err, "Failed to launch cmsd daemon")
	}
	log.Info("Successfully launched cmsd")
	if err := metrics.SetComponentHealthStatus("cmsd", "ok", ""); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	var xrootdExpiry time.Time
	var cmsdExpiry time.Time
	for {
		timer := time.NewTimer(time.Second)
		select {
		case sig := <-sigs:
			if sys_sig, ok := sig.(syscall.Signal); ok {
				log.Warnf("Forwarding signal %v to xrootd daemons\n", sys_sig)
				if err = syscall.Kill(xrootdPid, sys_sig); err != nil {
					return errors.Wrap(err, "Failed to forward signal to xrootd process")
				}
				if err = syscall.Kill(cmsdPid, sys_sig); err != nil {
					return errors.Wrap(err, "Failed to forward signal to cmsd process")
				}
			} else {
				panic(errors.New("Unable to convert signal to syscall.Signal"))
			}
			xrootdExpiry = time.Now().Add(10 * time.Second)
			cmsdExpiry = time.Now().Add(10 * time.Second)
		case <-xrootdCtx.Done():
			if waitResult := context.Cause(xrootdCtx); waitResult != nil {
				if !xrootdExpiry.IsZero() {
					return nil
				}
				if err = metrics.SetComponentHealthStatus("xrootd", "critical",
					"xrootd process failed unexpectedly"); err != nil {
					return err
				}
				return errors.Wrap(waitResult, "xrootd process failed unexpectedly")
			}
			log.Debugln("Xrootd daemon has shut down successfully")
			return nil
		case <-cmsdCtx.Done():
			if waitResult := context.Cause(cmsdCtx); waitResult != context.Canceled {
				if !cmsdExpiry.IsZero() {
					return nil
				}
				if err = metrics.SetComponentHealthStatus("cmsd", "critical",
					"cmsd process failed unexpectedly"); err != nil {
					return nil
				}
				return errors.Wrap(waitResult, "cmsd process failed unexpectedly")
			}
			log.Debugln("Cmsd daemon has shut down successfully")
			return nil
		case <-timer.C:
			if !xrootdExpiry.IsZero() && time.Now().After(xrootdExpiry) {
				if err = syscall.Kill(xrootdPid, syscall.SIGKILL); err != nil {
					return errors.Wrap(err, "Failed to SIGKILL the xrootd process")
				}
			}
			if !cmsdExpiry.IsZero() && time.Now().After(cmsdExpiry) {
				if err = syscall.Kill(cmsdPid, syscall.SIGKILL); err != nil {
					return errors.Wrap(err, "Failed to SIGKILL the cmsd process")
				}
			}
		}
	}
}
