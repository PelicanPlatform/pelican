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

package daemon

import (
	"bufio"
	"context"
	_ "embed"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	launchInfo struct {
		ctx    context.Context
		expiry time.Time
		pid    int
	}
)

func ForwardCommandToLogger(ctx context.Context, daemonName string, cmdStdout io.ReadCloser, cmdStderr io.ReadCloser) {
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

func (launcher DaemonLauncher) Name() string {
	return launcher.DaemonName
}

func (launcher DaemonLauncher) Launch(ctx context.Context) (context.Context, int, error) {

	cmd := exec.CommandContext(ctx, launcher.Args[0], launcher.Args[1:]...)
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

	if launcher.Uid != -1 && launcher.Gid != -1 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(launcher.Uid), Gid: uint32(launcher.Gid)}
		log.Infof("Will launch daemon with UID %v and GID %v", launcher.Uid, launcher.Gid)
	} else if launcher.Uid != -1 || launcher.Gid != -1 {
		return ctx, -1, errors.New("If either uid or gid is specified for daemon, both must be specified")
	}

	if err := cmd.Start(); err != nil {
		return ctx, -1, err
	}
	go ForwardCommandToLogger(ctx, launcher.Name(), cmdStdout, cmdStderr)

	ctx_result, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(cmd.Wait())
	}()
	return ctx_result, cmd.Process.Pid, nil
}

func LaunchDaemons(launchers []Launcher) (err error) {
	ctx := context.Background()

	daemons := make([]launchInfo, len(launchers))
	for idx, daemon := range launchers {
		ctx, pid, err := daemon.Launch(ctx)
		if err != nil {
			err = errors.Wrapf(err, "Failed to launch %s daemon", daemon.Name())
			if err := metrics.SetComponentHealthStatus(daemon.Name(), "critical", err.Error()); err != nil {
				return err
			}
			return err
		}
		daemons[idx].ctx = ctx
		daemons[idx].pid = pid
		log.Infoln("Successfully launched", daemon.Name())
		if err := metrics.SetComponentHealthStatus(daemon.Name(), "ok", ""); err != nil {
			return err
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	cases := make([]reflect.SelectCase, len(daemons)+2)
	for idx, daemon := range daemons {
		cases[idx].Dir = reflect.SelectRecv
		cases[idx].Chan = reflect.ValueOf(daemon.ctx.Done())
	}
	cases[len(daemons)].Dir = reflect.SelectRecv
	cases[len(daemons)].Chan = reflect.ValueOf(sigs)
	cases[len(daemons)+1].Dir = reflect.SelectRecv

	for {
		timer := time.NewTimer(time.Second)
		cases[len(daemons)+1].Chan = reflect.ValueOf(timer.C)

		chosen, recv, _ := reflect.Select(cases)
		if chosen == len(daemons) {
			sys_sig, ok := recv.Interface().(syscall.Signal)
			if !ok {
				panic(errors.New("Unable to convert signal to syscall.Signal"))
			}
			log.Warnf("Forwarding signal %v to daemons\n", sys_sig)
			var lastErr error
			for idx, daemon := range daemons {
				if err = syscall.Kill(daemon.pid, sys_sig); err != nil {
					lastErr = errors.Wrapf(err, "Failed to forward signal to %s process", launchers[idx].Name())
				}
				daemon.expiry = time.Now().Add(10 * time.Second)
			}
			if lastErr != nil {
				return lastErr
			}
		} else if chosen < len(daemons) {
			if waitResult := context.Cause(daemons[chosen].ctx); waitResult != nil {
				if !daemons[chosen].expiry.IsZero() {
					return nil
				}
				if err = metrics.SetComponentHealthStatus(launchers[chosen].Name(), "critical",
					"process failed unexpectedly"); err != nil {
					return err
				}
				return errors.Wrapf(waitResult, "%s process failed unexpectedly", launchers[chosen].Name())
			}
			log.Debugln("Daemons have been shut down successfully")
			return nil
		} else {
			for idx, daemon := range daemons {
				if !daemon.expiry.IsZero() && time.Now().After(daemon.expiry) {
					if err = syscall.Kill(daemon.pid, syscall.SIGKILL); err != nil {
						return errors.Wrapf(err, "Failed to SIGKILL the %s process", launchers[idx].Name())
					}
				}
			}
		}
	}
}
