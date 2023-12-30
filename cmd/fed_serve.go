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
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type modulePorts struct {
	Registry uint16
	Director uint16
	Origin   uint16
}

func fedServeStart(cmd *cobra.Command, args []string) error {
	moduleSlice := param.Server_Modules.GetStringSlice()
	if len(moduleSlice) == 0 {
		return errors.New("No modules are enabled; pass the --module flag or set the Server.Modules parameter")
	}
	modules := config.NewServerType()
	for _, module := range moduleSlice {
		if !modules.SetString(module) {
			return errors.Errorf("Unknown module name: %s", module)
		}
	}
	if modules.IsEnabled(config.CacheType) {
		return errors.New("`pelican serve` does not support the cache module")
	}
	ports := modulePorts{}
	var err error
	if modules.IsEnabled(config.RegistryType) {
		ports.Registry, err = cmd.Flags().GetUint16("reg-port")
		if err != nil {
			return errors.Wrap(err, "Failed to parse registry port")
		}
	}
	if modules.IsEnabled(config.DirectorType) {
		ports.Director, err = cmd.Flags().GetUint16("director-port")
		if err != nil {
			return errors.Wrap(err, "Failed to parse director port")
		}
	}
	if modules.IsEnabled(config.OriginType) {
		ports.Origin, err = cmd.Flags().GetUint16("origin-port")
		if err != nil {
			return errors.Wrap(err, "Failed to parse origin port")
		}
	}
	ctx := cmd.Context()
	return fedServeInternal(ctx, ports)
}

func fedServeInternal(ctx context.Context, ports modulePorts) error {

	hostname := param.Server_Hostname.GetString()

	if ports.Registry != 0 {
		err := initRegistry()
		if err != nil {
			return errors.Wrap(err, "Failure when initializing the registry")
		}

		ctx, cancel := context.WithCancel(context.Background())
		viper.Set("Server.WebPort", ports.Registry)

		registryUrl := "https://" + hostname + ":" + fmt.Sprint(ports.Registry)
		viper.Set("Federation.NamespaceURL", registryUrl)

		go func() {
			err = serveRegistryInternal(ctx)
			if err != nil {
				return
			}
		}()
		defer cancel()

		err = server_utils.WaitUntilWorking("GET", param.Federation_NamespaceUrl.GetString()+"/api/v1.0/registry", "Registry", http.StatusOK)
		if err != nil {
			return err
		}
	}

	if ports.Director != 0 {

		err := initDirector()
		if err != nil {
			return errors.Wrap(err, "Failure when initializing for director")
		}

		viper.Set("Director.DefaultResponse", "cache")

		ctx, cancel := context.WithCancel(context.Background())
		viper.Set("Server.WebPort", ports.Director)

		directorUrl := "https://" + hostname + ":" + fmt.Sprint(ports.Director)
		viper.Set("Federation.DirectorURL", directorUrl)

		go func() {
			err = serveDirectorInternal(ctx)
			if err != nil {
				return
			}
		}()
		defer cancel()

		err = server_utils.WaitUntilWorking(
			"GET",
			param.Federation_DirectorUrl.GetString()+"/api/v1.0/director/listNamespaces",
			"Director",
			http.StatusOK,
		)
		if err != nil {
			return err
		}
	}

	if ports.Origin != 0 {
		err := initOrigin()
		if err != nil {
			return errors.Wrap(err, "Failure when initializing for origin")
		}

		if param.Origin_Mode.GetString() != "posix" {
			return errors.Errorf("Origin Mode must be set to posix, S3 is not currently supported.")
		}

		if param.Origin_ExportVolume.GetString() == "" {
			return errors.Errorf("Origin.ExportVolume must be set in the parameters.yaml file.")
		}

		ctx, cancel := context.WithCancel(context.Background())
		viper.Set("Server.WebPort", 8444) //TODO remove hard coding once we add web support
		viper.Set("Xrootd.Port", ports.Origin)

		originUrl := "https://" + hostname + ":8444" //TODO remove hard coding once we add web support
		issuerUrl := "https://" + hostname + ":" + fmt.Sprint(ports.Origin)
		viper.Set("OriginURL", originUrl)
		viper.Set("Server.IssuerUrl", issuerUrl)
		viper.Set("Server.ExternalWebUrl", originUrl)

		go func() {
			err = serveOriginInternal(ctx)
			if err != nil {
				return
			}
		}()
		defer cancel()

		err = server_utils.WaitUntilWorking("GET", param.Origin_Url.GetString()+"/.well-known/openid-configuration", "Origin", http.StatusOK)
		if err != nil {
			return err
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
