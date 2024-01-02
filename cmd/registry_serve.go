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
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
)

func serveRegistry(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

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

	if err = launchers.RegistryServe(ctx, engine, egrp); err != nil {
		return err
	}

	log.Info("Starting web engine...")
	go func() {
		if err := web_ui.RunEngine(ctx, engine, egrp); err != nil {
			log.Panicln("Failure when running the web engine:", err)
		}
		cancel()
	}()

	if param.Server_EnableUI.GetBool() {
		if err := web_ui.InitServerWebLogin(ctx); err != nil {
			log.Panicln("Failure when initializing the web login:", err)
		}
	}

	egrp.Go(func() error {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-sigs
		_ = sig
		cancel()
		return errors.New("Registry process has been cancelled")
	})

	return nil
}
