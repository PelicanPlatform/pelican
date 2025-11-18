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
	_ "embed"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/p11proxy"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (
	PrivilegedXrootdLauncher struct {
		daemonName string
		configPath string
		fds        [2]int
		runDir     string
	}

	UnprivilegedXrootdLauncher struct {
		daemon.DaemonLauncher
		isCache bool
		fds     [2]int
	}
)

func (launcher PrivilegedXrootdLauncher) Name() string {
	return launcher.daemonName
}

func (launcher PrivilegedXrootdLauncher) KillFunc() func(pid int, sig int) error {
	if param.Server_DropPrivileges.GetBool() {
		return func(pid int, sig int) error {
			buff := make([]byte, 5)
			buff[0] = 0x03
			binary.BigEndian.PutUint32(buff[1:], uint32(sig))
			if err := syscall.Sendmsg(launcher.fds[1], buff, nil, nil, 0); err != nil {
				return errors.Wrap(err, "failed to signal xrootd process")
			}
			return nil
		}
	} else {
		return func(pid int, sig int) error {
			return syscall.Kill(pid, syscall.Signal(sig))
		}
	}
}

func (launcher UnprivilegedXrootdLauncher) KillFunc() func(pid int, sig int) error {
	if param.Server_DropPrivileges.GetBool() {
		return func(pid int, sig int) error {
			buff := make([]byte, 5)
			buff[0] = 0x03
			binary.BigEndian.PutUint32(buff[1:], uint32(sig))
			if err := syscall.Sendmsg(launcher.fds[1], buff, nil, nil, 0); err != nil {
				return errors.Wrap(err, "failed to signal xrootd process")
			}
			return nil
		}
	} else {
		return func(pid int, sig int) error {
			return syscall.Kill(pid, syscall.Signal(sig))
		}
	}
}

func makeUnprivilegedXrootdLauncher(daemonName string, xrootdRun string, configPath string, isCache bool) (result UnprivilegedXrootdLauncher, err error) {
	result.DaemonName = daemonName + ".origin"
	if isCache {
		result.DaemonName = daemonName + ".cache"
	}
	result.Uid = -1
	result.Gid = -1
	result.isCache = isCache
	result.fds, err = syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	if isCache {
		setCacheFds(result.fds)
	} else {
		setOriginFds(result.fds)
	}

	result.RunDir = xrootdRun
	pidFile := filepath.Join(xrootdRun, "xrootd.pid")
	result.Args = []string{daemonName, "-s", pidFile, "-c", configPath}

	if config.IsRootExecution() {
		result.Uid, err = config.GetDaemonUID()
		if err != nil {
			return
		}
		result.Gid, err = config.GetDaemonGID()
		if err != nil {
			return
		}
	}

	pkcs11Info := p11proxy.CurrentInfo()
	pkcs11Active := param.Server_EnablePKCS11.GetBool() && pkcs11Info.Enabled
	certPath := runtimeTLSCertPath(isCache)
	caBundlePath := filepath.Join(xrootdRun, "ca-bundle.crt")
	if param.Server_DropPrivileges.GetBool() {
		caBundlePath = filepath.Join(xrootdRun, "pelican", "ca-bundle.crt")
	}

	if isCache {
		result.Args = append(result.Args, "-n", "cache")

		result.ExtraEnv = []string{
			"XRD_PELICANBROKERSOCKET=" + filepath.Join(xrootdRun, "cache-reversal.sock"),
			"XRD_PLUGINCONFDIR=" + filepath.Join(xrootdRun, "cache-client.plugins.d"),
			"X509_CERT_FILE=" + caBundlePath,
			"XRD_PELICANCLIENTCERTFILE=" + certPath,
		}
		if pkcs11Active {
			result.ExtraEnv = append(result.ExtraEnv, "XRD_PELICANCLIENTKEYFILE=")
		} else {
			result.ExtraEnv = append(result.ExtraEnv, "XRD_PELICANCLIENTKEYFILE="+certPath)
		}
		if confDir := os.Getenv("XRD_PLUGINCONFDIR"); confDir != "" {
			result.ExtraEnv = append(result.ExtraEnv, "XRD_PLUGINCONFDIR="+confDir)
		}
		result.ExtraEnv = append(result.ExtraEnv, "XRD_PELICANFEDERATIONMETADATATIMEOUT="+param.Cache_DefaultCacheTimeout.GetDuration().String())
		result.ExtraEnv = append(result.ExtraEnv, "XRD_PELICANDEFAULTHEADERTIMEOUT="+param.Cache_DefaultCacheTimeout.GetDuration().String())

		// Enable client-side curl statistics if configured
		if statsPath := param.Cache_ClientStatisticsLocation.GetString(); statsPath != "" {
			result.ExtraEnv = append(result.ExtraEnv, "XRD_CURLSTATISTICSLOCATION="+statsPath)
		}

		// If the cache is running in "site-local" mode, configure xrdcl-pelican to
		// query the Director for other Caches, not Origins.
		if param.Cache_EnableSiteLocalMode.GetBool() {
			result.ExtraEnv = append(result.ExtraEnv, "XRD_PELICANDIRECTORYQUERYMODE=cache")
		}

		// Pass through the advanced Pelican cache control features; meant for unit tests of xrdcl-pelican
		// Purposely allowing these to override the ones from the Pelican config file
		for _, envVar := range os.Environ() {
			if strings.HasPrefix(envVar, "XRD_PELICAN") {
				result.ExtraEnv = append(result.ExtraEnv, envVar)
			}
		}
	} else {
		result.Args = append(result.Args, "-n", "origin")
	}
	if param.Server_DropPrivileges.GetBool() {
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_CA_FILE="+caBundlePath)
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_CERT_FILE="+certPath)
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_INFO_FD="+strconv.Itoa(result.fds[1]))

		basePath := filepath.Join(param.Cache_NamespaceLocation.GetString(), server_utils.MonitoringBaseNs, "selfTest")
		testFileLocation := filepath.Join(basePath, "self-test-cache-server.txt")
		testFileCinfoLocation := filepath.Join(basePath, "self-test-cache-server.txt.cinfo")
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE="+testFileLocation)
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE_CINFO="+testFileCinfoLocation)

		xrootdRun := param.Origin_RunLocation.GetString()
		authFileName := "authfile-origin-generated"
		scitokensCfgFileName := "scitokens-origin-generated.cfg"
		if isCache {
			xrootdRun = param.Cache_RunLocation.GetString()
			authFileName = "authfile-cache-generated"
			scitokensCfgFileName = "scitokens-cache-generated.cfg"
		}
		authPath := filepath.Join(xrootdRun, authFileName)
		configPath := filepath.Join(xrootdRun, scitokensCfgFileName)
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_AUTHFILE_GENERATED="+authPath)
		result.ExtraEnv = append(result.ExtraEnv, "XRDHTTP_PELICAN_SCITOKENS_GENERATED="+configPath)
	}
	if pkcs11Active {
		if pkcs11Info.ServerAddress != "" {
			result.ExtraEnv = append(result.ExtraEnv, "P11_KIT_SERVER_ADDRESS="+pkcs11Info.ServerAddress)
		}
		if pkcs11Info.OpenSSLConfPath != "" {
			result.ExtraEnv = append(result.ExtraEnv, "OPENSSL_CONF="+pkcs11Info.OpenSSLConfPath)
		}
	}
	return
}

func ConfigureLaunchers(privileged bool, configPath string, useCMSD bool, enableCache bool) (launchers []daemon.Launcher, err error) {
	xrootdRun := param.Origin_RunLocation.GetString()
	if enableCache {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	if privileged {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create socket pair for xrootd")
		}
		launchers = append(launchers, PrivilegedXrootdLauncher{"xrootd", configPath, fds, xrootdRun})
		if enableCache {
			setCacheFds(fds)
		} else {
			setOriginFds(fds)
		}
		if useCMSD {
			cmsdFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create socket pair for xrootd")
			}
			launchers = append(launchers, PrivilegedXrootdLauncher{"cmsd", configPath, cmsdFds, xrootdRun})
		}
	} else {
		var result UnprivilegedXrootdLauncher
		result, err = makeUnprivilegedXrootdLauncher("xrootd", xrootdRun, configPath, enableCache)
		if err != nil {
			return
		}
		launchers = append(launchers, result)
		if useCMSD {
			result, err = makeUnprivilegedXrootdLauncher("cmsd", xrootdRun, configPath, false)
			if err != nil {
				return
			}
			launchers = append(launchers, result)
		}
	}
	return
}

func LaunchDaemons(ctx context.Context, launchers []daemon.Launcher, egrp *errgroup.Group, portStartCallback func(int)) (pids []int, err error) {
	startupChan := make(chan int)
	readyChan := make(chan bool)
	defer close(readyChan)
	re := regexp.MustCompile(`^------ xrootd [A-Za-z0-9]+@[A-Za-z0-9.\-]+:([0-9]+) initialization complete.*`)
	config.AddFilter(&config.RegexpFilter{
		Name:   "xrootd_startup",
		Regexp: re,
		Levels: []log.Level{log.InfoLevel},
		Fire: func(e *log.Entry) error {
			portStrs := re.FindStringSubmatch(e.Message)
			if len(portStrs) < 1 {
				portStrs = []string{"", ""}
			}
			port, err := strconv.Atoi(portStrs[1])
			if err != nil {
				port = -1
			}
			if _, ok := <-readyChan; ok {
				startupChan <- port
			}
			return nil
		},
	})
	config.AddFilter(&config.RegexpFilter{
		Name:   "xrootd_startup_failed",
		Regexp: regexp.MustCompile(`^------ xrootd [A-Za-z0-9]+@[A-Za-z0-9.\-]+:([0-9]+) initialization failed.*`),
		Levels: []log.Level{log.InfoLevel},
		Fire: func(e *log.Entry) error {
			if _, ok := <-readyChan; ok {
				startupChan <- -1
			}
			return nil
		},
	})
	defer func() {
		config.RemoveFilter("xrootd_startup")
		config.RemoveFilter("xrootd_startup_failed")
		close(startupChan)
	}()

	pids, err = daemon.LaunchDaemons(ctx, launchers, egrp)
	if err != nil {
		return
	}

	ticker := time.NewTicker(param.Xrootd_MaxStartupWait.GetDuration())
	defer ticker.Stop()
	select {
	case <-ctx.Done():
		err = ctx.Err()
		return
	case readyChan <- true:
		port := <-startupChan
		if port == -1 {
			err = errors.New("Xrootd initialization failed")
			return
		} else {
			portStartCallback(port)
		}
	case <-ticker.C:
		log.Errorln("XRootD did not startup after", param.Xrootd_MaxStartupWait.GetDuration().String(), "of waiting")
		err = errors.New("XRootD did not startup after " + param.Xrootd_MaxStartupWait.GetDuration().String() + " of waiting")
		return
	}

	return
}
