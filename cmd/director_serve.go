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

	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func serveDirector(cmd *cobra.Command, args []string) error {

	shutdownCtx, shutdownCancel := context.WithCancel(cmd.Context())
	egrp, ctx := errgroup.WithContext(shutdownCtx)

	defer func() {
		shutdownCancel()
		if err := egrp.Wait(); err != nil {
			log.Errorln("Failure when cleaning up director:", err)
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

	if err = launchers.DirectorServe(ctx, engine, egrp); err != nil {
		return err
	}

	log.Info("Starting web engine...")
	egrp.Go(func() error {
		if err := web_ui.RunEngine(ctx, engine, egrp); err != nil {
			return errors.Wrap(err, "Failure when running the web engine:")
		}
		shutdownCancel()
		return nil
	})

	if param.Server_EnableUI.GetBool() {
		log.Info("Starting web engine...")
		if err = web_ui.InitServerWebLogin(ctx); err != nil {
			return err
		}
	}

	egrp.Go(func() error {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-sigs
		_ = sig
		shutdownCancel()
		return errors.New("Director process has been cancelled")
	})

	return egrp.Wait()
}
