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

package launchers

import (
	"context"
	_ "embed"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/xrootd"
)

func OriginServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules config.ServerType) (server_utils.XRootDServer, error) {

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

	// Director also registers this metadata URL; avoid registering twice.
	if !modules.IsEnabled(config.DirectorType) {
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

	if err = xrootd.LaunchOriginDaemons(ctx, launchers, egrp); err != nil {
		return nil, err
	}

	// LaunchOriginDaemons may edit the viper config; these launched goroutines are purposely
	// delayed until after the viper config is done.
	xrootd.LaunchXrootdMaintenance(ctx, originServer, 2*time.Minute)
	origin_ui.LaunchOriginFileTestMaintenance(ctx)

	return originServer, nil
}

// Finish configuration of the origin server.  To be invoked after the web UI components
// have been launched.
func OriginServeFinish(ctx context.Context, egrp *errgroup.Group) error {
	originExports, err := common.GetOriginExports()
	if err != nil {
		return err
	}

	for _, export := range *originExports {
		if err := server_ui.RegisterNamespaceWithRetry(ctx, egrp, export.FederationPrefix); err != nil {
			return err
		}
	}

	return nil
}
