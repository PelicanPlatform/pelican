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

// Package launcher_utils contains utility functions for the [github.com/pelicanplatform/pelican/launcher] package.
//
// It should only be imported by the launchers package
// It should NOT be imported to any server packages (origin/cache/registry) or other lower level packages (config/utils/etc)
package launcher_utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type directorResponse struct {
	Error         string `json:"error"`
	ApprovalError bool   `json:"approval_error"`
}

func doAdvertise(ctx context.Context, servers []server_structs.XRootDServer) {
	log.Debugf("About to advertise %d XRootD servers", len(servers))
	start := time.Now()
	err := Advertise(ctx, servers)
	duration := time.Since(start)
	if err != nil {
		log.Warningf("XRootD server advertise failed (duration %v): %s", duration.String(), err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server failed to advertise to the director: %v", err))
	} else {
		log.Debugf("XRootD server advertise successful (duration %v)", duration.String())
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
	}
}

// Launch periodic advertise of xrootd servers (origin and cache) to the director, in the errogroup
func LaunchPeriodicAdvertise(ctx context.Context, egrp *errgroup.Group, servers []server_structs.XRootDServer) error {
	metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusWarning, "First attempt to advertise to the director...")
	doAdvertise(ctx, servers)

	advertiseInterval := param.Server_AdvertisementInterval.GetDuration()
	if advertiseInterval > param.Server_AdLifetime.GetDuration()/3 {
		newInterval := param.Server_AdLifetime.GetDuration() / 3
		log.Warningln("The advertise interval", advertiseInterval.String(), "is set to above 1/3 of the ad lifetime.  Decreasing it to", newInterval.String())
		advertiseInterval = newInterval
	}

	shutdownAny := ctx.Value(director.AdvertiseShutdownKey)
	var shutdownChannel <-chan struct{} = nil
	if shutdownCtx, ok := shutdownAny.(context.Context); ok {
		shutdownChannel = shutdownCtx.Done()
	}

	ticker := time.NewTicker(advertiseInterval)
	egrp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-shutdownChannel:
				log.Infoln("Periodic advertise shut down on command")
				return nil
			case <-ticker.C:
				doAdvertise(ctx, servers)
			case <-ctx.Done():
				log.Infoln("Periodic advertisement loop has been terminated")
				return nil
			}
		}
	})

	return nil
}

// Advertise ONCE the xrootd servers (origin and cache) to the director
func Advertise(ctx context.Context, servers []server_structs.XRootDServer) error {
	var firstErr error
	for _, server := range servers {
		err := advertiseInternal(ctx, server)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func advertiseInternal(ctx context.Context, server server_structs.XRootDServer) error {
	name, err := server_utils.GetServiceName(ctx, server.GetServerType())
	if err != nil {
		return errors.Wrap(err, "failed to determine service name for advertising to director")
	}

	// Keep the service name in local database up to date
	if err = database.UpsertServiceName(name, server.GetServerType()); err != nil {
		return errors.Wrapf(err, "failed to upsert service name %s in local database", name)
	}

	if err = server.GetNamespaceAdsFromDirector(); err != nil {
		return errors.Wrapf(err, "%s failed to get namespaceAds from the director", server.GetServerType())
	}
	serverUrl := param.Origin_Url.GetString()
	webUrl := param.Server_ExternalWebUrl.GetString()

	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		serverUrl = param.Cache_Url.GetString()
	}

	ad, err := server.CreateAdvertisement(name, serverUrl, webUrl)
	if err != nil {
		return err
	}
	ad.Now = time.Now()

	body, err := json.Marshal(*ad)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to generate JSON description of %s", server.GetServerType()))
	}

	egrp := &errgroup.Group{}
	successCount := atomic.Int32{}
	for _, directorAd := range server_utils.GetDirectorAds() {
		adCopy := directorAd
		egrp.Go(func() error {
			directorUrlStr := adCopy.AdvertiseUrl
			if directorUrlStr == "" {
				return errors.New("Director endpoint URL is not known")
			}
			directorUrl, err := url.Parse(directorUrlStr)
			if err != nil {
				return errors.Wrap(err, "failed to parse Federation.DirectorURL")
			}

			directorUrl.Path = "/api/v1.0/director/register" + server.GetServerType().String()

			tok, err := server_utils.GetAdvertisementTok(server, directorUrlStr)
			if err != nil {
				return errors.Wrap(err, "failed to get advertisement token")
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, directorUrl.String(), bytes.NewBuffer(body))
			if err != nil {
				return errors.Wrap(err, "failed to create a POST request for director advertisement")
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			userAgent := "pelican-" + strings.ToLower(server.GetServerType().String()) + "/" + config.GetVersion()
			req.Header.Set("User-Agent", userAgent)

			tr := config.GetTransport()
			client := http.Client{Transport: tr}

			resp, err := client.Do(req)
			if err != nil {
				return errors.Wrap(err, "failed to start the request for director advertisement")
			}
			defer resp.Body.Close()

			respbody, err := io.ReadAll(resp.Body)
			if err != nil {
				return errors.Wrap(err, "failed to read the response body for director advertisement")
			}
			if resp.StatusCode > 299 {
				var respErr directorResponse
				if unmarshalErr := json.Unmarshal(respbody, &respErr); unmarshalErr != nil { // Error creating json
					return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(body))
				}
				if respErr.ApprovalError {
					// Removed the "Please contact admin..." section since the director now provides contact information
					return fmt.Errorf("the director rejected the server advertisement: %s", respErr.Error)
				}
				if respErr.Error != "" {
					return errors.Errorf("error during director advertisement: %v", respErr.Error)
				}
				var respSimpleError server_structs.SimpleApiResp
				if unmarshalErr := json.Unmarshal(respbody, &respSimpleError); unmarshalErr != nil { // Error creating json
					return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(body))
				}
				log.Warningln("Error response from", directorUrl.String(), "status:", resp.StatusCode, "message:", respSimpleError.Msg)
				return errors.Errorf("error during director advertisement: %v", respSimpleError.Msg)
			}
			successCount.Add(1)
			return nil
		})
	}
	// If at least one advertise succeeded, we're good
	err = egrp.Wait()
	if successCount.Load() > 0 {
		return nil
	}
	return err
}
