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

package launchers

import (
	"context"
	_ "embed"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func OriginServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) (server_utils.XRootDServer, error) {

	err := xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return nil, err
	}

	originServer := &origin_ui.OriginServer{}
	err = server_ui.CheckDefaults(originServer)
	if err != nil {
		return nil, err
	}

	// Set up the APIs unrelated to UI, which only contains director-based health test reporting endpoint for now
	if err = origin_ui.ConfigureOriginAPI(engine, ctx, egrp); err != nil {
		return nil, err
	}

	// In posix mode, we rely on xrootd to export keys. When we run the origin with
	// different backends, we instead export the keys via the Pelican process
	if param.Origin_Mode.GetString() != "posix" {
		if err = origin_ui.ConfigIssJWKS(engine.Group("/.well-known")); err != nil {
			return nil, err
		}
	}

	if param.Origin_EnableIssuer.GetBool() {
		if err = oa4mp.ConfigureOA4MPProxy(engine); err != nil {
			return nil, err
		}
	}

	configPath, err := xrootd.ConfigXrootd(ctx, true)
	if err != nil {
		return nil, err
	}

	if param.Origin_SelfTest.GetBool() {
		egrp.Go(func() error { return origin_ui.PeriodicSelfTest(ctx) })
	}

	xrootd.LaunchXrootdMaintenance(ctx, originServer, 2*time.Minute)

	privileged := param.Origin_Multiuser.GetBool()
	launchers, err := xrootd.ConfigureLaunchers(privileged, configPath, param.Origin_EnableCmsd.GetBool(), false)
	if err != nil {
		return nil, err
	}

	if param.Origin_EnableIssuer.GetBool() {
		oa4mp_launcher, err := oa4mp.ConfigureOA4MP()
		if err != nil {
			return nil, err
		}
		launchers = append(launchers, oa4mp_launcher)
	}

	startupChan := make(chan int)
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
			select {
			case <-ctx.Done():
				return nil
			case startupChan <- port:
				return nil
			}
		},
	})
	defer func() {
		config.RemoveFilter("xrootd_startup")
		close(startupChan)
	}()

	if err = daemon.LaunchDaemons(ctx, launchers, egrp); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case port := <-startupChan:
		if port == -1 {
			return nil, errors.New("Xrootd initialization failed")
		} else {
			viper.Set("Xrootd.Port", port)
			log.Infoln("Origin startup complete on port", port)
		}
	}

	return originServer, nil
}

// Finish configuration of the origin server.  To be invoked after the web UI components
// have been launched.
func OriginServeFinish(ctx context.Context, egrp *errgroup.Group) error {
	return server_ui.RegisterNamespaceWithRetry(ctx, egrp)
}
