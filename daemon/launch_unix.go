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
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
)

type (
	launchInfo struct {
		ctx    context.Context
		expiry time.Time
		pid    int
		name   string
	}
)

func checkPIDExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		// On Unix, FindProcess always succeeds and returns a Process for the given pid, regardless of whether the process exists.
		return false
	}

	// Sending signal 0 to a process is a way to check if the process exists.
	// An error indicates that the process does not exist or you do not have permission to signal it.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

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
		log.Infof("Will launch daemon %q with UID %v and GID %v", launcher.DaemonName, launcher.Uid, launcher.Gid)
	} else if launcher.Uid != -1 || launcher.Gid != -1 {
		return ctx, -1, errors.New("If either uid or gid is specified for daemon, both must be specified")
	}

	if len(launcher.ExtraEnv) > 0 {
		// Merge the "extra env" options into the existing OS environment
		existingEnv := os.Environ()
		newEnv := make([]string, 0)
		for _, defEnvStr := range existingEnv {
			useEnv := true
			for _, newEnvStr := range launcher.ExtraEnv {
				if eqPos := strings.IndexByte(newEnvStr, '='); eqPos == -1 {
					return ctx, -1, errors.Errorf("Environment override string %s lacking '=' character", newEnvStr)
				} else {
					envPrefix := newEnvStr[:eqPos]
					if strings.HasPrefix(defEnvStr, envPrefix) {
						useEnv = false
						break
					}
				}
			}
			if useEnv {
				newEnv = append(newEnv, defEnvStr)
			}
		}
		cmd.Env = append(newEnv, launcher.ExtraEnv...)
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

func LaunchDaemons(ctx context.Context, launchers []Launcher, egrp *errgroup.Group) (pids []int, err error) {

	daemons := make([]launchInfo, len(launchers))
	pids = make([]int, len(launchers))
	for idx, daemon := range launchers {
		var newCtx context.Context
		var pid int
		// daemon.Name() is changed to xrootd.origin / xrootd.cache || cmsd.origin, but we only want to have xrootd/cmsd
		metricName := strings.SplitN(daemon.Name(), ".", 2)[0]
		newCtx, pid, err = daemon.Launch(ctx)
		if err != nil {
			err = errors.Wrapf(err, "Failed to launch %s daemon", daemon.Name())
			metrics.SetComponentHealthStatus(metrics.HealthStatusComponent(metricName), metrics.StatusCritical, err.Error())
			return
		}
		daemons[idx].ctx = newCtx
		daemons[idx].pid = pid
		daemons[idx].name = daemon.Name()
		pids[idx] = pid
		log.Infoln("Successfully launched", daemon.Name())
		metrics.SetComponentHealthStatus(metrics.HealthStatusComponent(metricName), metrics.StatusOK, "")
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

	egrp.Go(func() error {
		for {
			timer := time.NewTimer(time.Second)
			cases[len(daemons)+1].Chan = reflect.ValueOf(timer.C)

			chosen, recv, _ := reflect.Select(cases)
			// <-sigs received system call to terminate
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
					log.Infof("Daemon %q with pid %d was killed", daemon.name, daemon.pid)
				}
				if lastErr != nil {
					log.Errorln("Last error when killing launched daemons:", lastErr)
					return lastErr
				}
				// <-ctx.Done() from daemons. Either parent ctx is cancelled or there's error in running the daemon
			} else if chosen < len(daemons) {
				// Kill the daemon if it's still alive
				exists := checkPIDExists(daemons[chosen].pid)
				if exists {
					if err = syscall.Kill(daemons[chosen].pid, syscall.SIGTERM); err != nil {
						err = errors.Wrapf(err, "Failed to kill %s with pid %d", daemons[chosen].name, daemons[chosen].pid)
						log.Errorln(err)
						return err
					}
					daemons[chosen].expiry = time.Now().Add(10 * time.Second)
					log.Infof("Daemon %q with pid %d was killed", daemons[chosen].name, daemons[chosen].pid)
				}
				if waitResult := context.Cause(daemons[chosen].ctx); waitResult != nil {
					if !daemons[chosen].expiry.IsZero() {
						return nil
					} else if errors.Is(waitResult, context.Canceled) {
						return nil
					}
					metricName := strings.SplitN(launchers[chosen].Name(), ".", 2)[0]
					metrics.SetComponentHealthStatus(metrics.HealthStatusComponent(metricName), metrics.StatusCritical,
						launchers[chosen].Name()+" process failed unexpectedly")
					err = errors.Wrapf(waitResult, "%s process failed unexpectedly", launchers[chosen].Name())
					log.Errorln(err)
					return err
				}
				log.Debugln("Daemons have been shut down successfully")
				return nil
			} else { // <-timer.C
				for idx, daemon := range daemons {
					// Daemon is expired, clean up
					if !daemon.expiry.IsZero() && time.Now().After(daemon.expiry) {
						if err = syscall.Kill(daemon.pid, syscall.SIGKILL); err != nil {
							err = errors.Wrapf(err, "Failed to SIGKILL the %s process", launchers[idx].Name())
							log.Errorln(err)
							return err
						}
					}
				}
			}
		}
	})

	return
}
