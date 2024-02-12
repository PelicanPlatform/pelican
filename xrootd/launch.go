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
	_ "embed"
	"path/filepath"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
)

type (
	PrivilegedXrootdLauncher struct {
		daemonName string
		configPath string
	}

	UnprivilegedXrootdLauncher struct {
		daemon.DaemonLauncher
	}
)

func (launcher PrivilegedXrootdLauncher) Name() string {
	return launcher.daemonName
}

func makeUnprivilegedXrootdLauncher(daemonName string, configPath string, isCache bool) (result UnprivilegedXrootdLauncher, err error) {
	result.DaemonName = daemonName
	result.Uid = -1
	result.Gid = -1
	xrootdRun := param.Xrootd_RunLocation.GetString()
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

	if isCache {
		result.ExtraEnv = []string{
			"XRD_PELICANBROKERSOCKET=" + filepath.Join(xrootdRun, "cache-reversal.sock"),
			"XRD_PLUGINCONFDIR=" + filepath.Join(xrootdRun, "cache-client.plugins.d"),
			"X509_CERT_FILE=" + filepath.Join(xrootdRun, "ca-bundle.crt"),
		}
	}
	return
}

func ConfigureLaunchers(privileged bool, configPath string, useCMSD bool, enableCache bool) (launchers []daemon.Launcher, err error) {
	if privileged {
		launchers = append(launchers, PrivilegedXrootdLauncher{"xrootd", configPath})
		if useCMSD {
			launchers = append(launchers, PrivilegedXrootdLauncher{"cmsd", configPath})
		}
	} else {
		var result UnprivilegedXrootdLauncher
		result, err = makeUnprivilegedXrootdLauncher("xrootd", configPath, enableCache)
		if err != nil {
			return
		}
		launchers = append(launchers, result)
		if useCMSD {
			result, err = makeUnprivilegedXrootdLauncher("cmsd", configPath, false)
			if err != nil {
				return
			}
			launchers = append(launchers, result)
		}
	}
	return
}
