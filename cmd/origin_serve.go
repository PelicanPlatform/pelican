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

package main

import (
	"context"
	_ "embed"
	"os"
	"os/signal"
	"syscall"

	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func serveOrigin(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	egrp, ctx := errgroup.WithContext(shutdownCtx)

	defer func() {
		shutdownCancel()
		if err := egrp.Wait(); err != nil {
			log.Errorln("Failure when cleaning up origin:", err)
		}
	}()

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	if param.Server_EnableUI.GetBool() {
		// Set up necessary APIs to support Web UI, including auth and metrics
		if err := web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
			return err
		}
	}

	originServer, err := launchers.OriginServe(ctx, engine, egrp)
	if err != nil {
		return err
	}

	log.Info("Starting web engine...")
	go func() {
		if err := web_ui.RunEngine(shutdownCtx, engine, egrp); err != nil {
			log.Panicln("Failure when running the web engine:", err)
		}
		shutdownCancel()
	}()

	if param.Server_EnableUI.GetBool() {
		if err := web_ui.InitServerWebLogin(ctx); err != nil {
			log.Panicln("Failure when initializing the web login:", err)
		}
	}

	if err = launchers.OriginServeFinish(ctx, egrp); err != nil {
		return err
	}

	if err := server_ui.LaunchPeriodicAdvertise(ctx, egrp, []server_utils.XRootDServer{originServer}); err != nil {
		return err
	}

	egrp.Go(func() error {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-sigs
		_ = sig
		shutdownCancel()
		return errors.New("Origin process has been cancelled")
	})

	return nil
}
