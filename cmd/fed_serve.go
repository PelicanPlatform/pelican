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
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var currentModules = map[string]string{"registry": "", "director": "", "origin": ""}
var cModsStringList = "registry, director, origin"

func fedCheckWorking(reqUrl string, server string) error {
	expiry := time.Now().Add(10 * time.Second)
	success := false
	for !(success || time.Now().After(expiry)) {
		time.Sleep(50 * time.Millisecond)
		req, err := http.NewRequest("GET", reqUrl, nil)
		if err != nil {
			return err
		}
		httpClient := http.Client{
			Transport: config.GetTransport(),
			Timeout:   50 * time.Millisecond,
		}
		_, err = httpClient.Do(req)
		if err != nil {
			log.Infoln("Failed to send request to "+server+"; likely server is not up (will retry in 50ms):", err)
		} else {
			success = true
			log.Debugln(server + " server appears to be functioning")
		}
	}

	return nil
}

func fedServeStart(cmd *cobra.Command, args []string) error {
	moduleSlice, err := cmd.Flags().GetStringSlice("modules")
	if err != nil {
		return errors.Wrap(err, "Failed to load modules passed via --module flag")
	}
	// Faking a set of certain values
	var moduleMap map[string]uint16 = map[string]uint16{}
	for _, mod := range moduleSlice {
		if _, ok := currentModules[mod]; ok {
			switch mod {
			case "registry":
				port, err := cmd.Flags().GetUint16("reg-port")
				if err != nil {
					return errors.Wrap(err, "Failed to parse registry port")
				}
				moduleMap[mod] = port
			case "director":
				port, err := cmd.Flags().GetUint16("director-port")
				if err != nil {
					return errors.Wrap(err, "Failed to parse director port")
				}
				moduleMap[mod] = port
			case "origin":
				port, err := cmd.Flags().GetUint16("origin-port")
				if err != nil {
					return errors.Wrap(err, "Failed to parse origin port")
				}
				moduleMap[mod] = port
			default:
				moduleMap[mod] = 0 //Should never happen
			}
		} else {
			return errors.New(fmt.Sprintf("Unknown module %s: Modules must be one of %s", mod, cModsStringList))
		}
	}
	ctx := cmd.Context()
	return fedServeInternal(ctx, moduleMap)
}

func fedServeInternal(ctx context.Context, moduleMap map[string]uint16) error {

	hostname, err := os.Hostname()
	if err != nil {
		return errors.Wrap(err, "Failed to get hostname from os")
	}

	if regPort, ok := moduleMap["registry"]; ok {
		err = initRegistry()
		if err != nil {
			return errors.Wrap(err, "Failure when initializing for registry")
		}

		ctx, cancel := context.WithCancel(context.Background())
		viper.Set("Server.WebPort", regPort)

		registryUrl := "https://" + hostname + ":" + fmt.Sprint(regPort)
		viper.Set("Federation.NamespaceURL", registryUrl)

		go func() {
			err = serveNamespaceRegistryInternal(ctx)
			if err != nil {
				return
			}
		}()
		defer cancel()

		err = fedCheckWorking(param.Federation_NamespaceUrl.GetString()+"/api/v1.0/registry", "Registry")
		if err != nil {
			return err
		}
	}

	if directorPort, ok := moduleMap["director"]; ok {

		err = initDirector()
		if err != nil {
			return errors.Wrap(err, "Failure when initializing for director")
		}

		viper.Set("Director.DefaultResponse", "cache")

		ctx, cancel := context.WithCancel(context.Background())
		viper.Set("Server.WebPort", directorPort)

		directorUrl := "https://" + hostname + ":" + fmt.Sprint(directorPort)
		viper.Set("Federation.DirectorURL", directorUrl)

		go func() {
			err = serveDirectorInternal(ctx)
			if err != nil {
				return
			}
		}()
		defer cancel()

		err = fedCheckWorking(param.Federation_DirectorUrl.GetString()+"/api/v1.0/director/listNamespaces", "Director")
		if err != nil {
			return err
		}
	}

	if originPort, ok := moduleMap["origin"]; ok {
		err = initOrigin()
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
		viper.Set("Xrootd.Port", originPort)

		originUrl := "https://" + hostname + ":8444" //TODO remove hard coding once we add web support
		issuerUrl := "https://" + hostname + ":" + fmt.Sprint(originPort)
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

		err = fedCheckWorking(param.Origin_Url.GetString(), "Origin")
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
