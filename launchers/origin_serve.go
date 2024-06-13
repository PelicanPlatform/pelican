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
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/xrootd"
)

func OriginServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules config.ServerType) (server_structs.XRootDServer, error) {

	err := xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return nil, err
	}

	originServer := &origin.OriginServer{}
	err = launcher_utils.CheckDefaults(originServer)
	if err != nil {
		return nil, err
	}

	if err := origin.InitializeDB(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize origin sqlite database")
	}

	origin.ConfigOriginTTLCache(ctx, egrp)

	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize origin exports")
	}

	if param.Origin_StorageType.GetString() == string(server_utils.OriginStorageGlobus) {
		if err := origin.InitGlobusBackend(originExports); err != nil {
			return nil, errors.Wrap(err, "failed to initialize Globus backend")
		}
		origin.LaunchGlobusTokenRefresh(ctx, egrp)
	}

	// Set up the APIs unrelated to UI, which only contains director-based health test reporting endpoint for now
	if err = origin.RegisterOriginAPI(engine, ctx, egrp); err != nil {
		return nil, err
	}

	// Set up the APIs for the origin UI
	if err = origin.RegisterOriginWebAPI(engine); err != nil {
		return nil, err
	}

	// Director also registers this metadata URL; avoid registering twice.
	if !modules.IsEnabled(config.DirectorType) {
		server_utils.RegisterOIDCAPI(engine.Group("/"), false)
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
		egrp.Go(func() error { return origin.PeriodicSelfTest(ctx) })
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

	portStartCallback := func(port int) {
		viper.Set("Origin.Port", port)
		if originUrl, err := url.Parse(param.Origin_Url.GetString()); err == nil {
			originUrl.Host = originUrl.Hostname() + ":" + strconv.Itoa(port)
			viper.Set("Origin.Url", originUrl.String())
			log.Debugln("Resetting Origin.Url to", originUrl.String())
		}
		log.Infoln("Origin startup complete on port", port)
	}

	pids, err := xrootd.LaunchDaemons(ctx, launchers, egrp, portStartCallback)
	if err != nil {
		return nil, err
	}
	originServer.SetPids(pids)

	// LaunchOriginDaemons may edit the viper config; these launched goroutines are purposely
	// delayed until after the viper config is done.
	xrootd.LaunchXrootdMaintenance(ctx, originServer, 2*time.Minute)
	origin.LaunchOriginFileTestMaintenance(ctx)

	return originServer, nil
}

// Finish configuration of the origin server.  To be invoked after the web UI components
// have been launched.
func OriginServeFinish(ctx context.Context, egrp *errgroup.Group) error {
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusWarning, "Start to register namespaces for the origin server")
	log.Debug("Register Origin")
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	// Only use hostname:port
	if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, server_structs.GetOriginNs(extUrl.Host)); err != nil {
		return err
	}
	log.Debug("Origin is registered")
	for _, export := range originExports {
		if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, export.FederationPrefix); err != nil {
			return err
		}
	}

	egrp.Go(func() error {
		<-ctx.Done()
		return origin.ShutdownOriginDB()
	})

	return nil
}
