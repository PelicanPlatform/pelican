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

// launcher_utils are utility functions for laucnhers package.
// It should only be imported by the launchers package
// It should NOT be imported to any server pacakges (origin/cache/registry) or other lower level packages (config/utils/etc)
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
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type directorResponse struct {
	Error         string `json:"error"`
	ApprovalError bool   `json:"approval_error"`
}

func doAdvertise(ctx context.Context, servers []server_structs.XRootDServer) {
	log.Debugf("About to advertise %d XRootD servers", len(servers))
	err := Advertise(ctx, servers)
	if err != nil {
		log.Warningln("XRootD server advertise failed:", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server advertise failed: %v", err))
	} else {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
	}
}

// Launch periodic advertise of xrootd servers (origin and cache) to the director, in the errogroup
func LaunchPeriodicAdvertise(ctx context.Context, egrp *errgroup.Group, servers []server_structs.XRootDServer) error {
	metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusWarning, "First attempt to advertise to the director...")
	doAdvertise(ctx, servers)

	ticker := time.NewTicker(1 * time.Minute)
	egrp.Go(func() error {

		for {
			select {
			case <-ticker.C:
				err := Advertise(ctx, servers)
				if err != nil {
					log.Warningln("XRootD server advertise failed:", err)
					metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server failed to advertise to the director: %v", err))
				} else {
					metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
				}
			case <-ctx.Done():
				log.Infoln("Periodic advertisement loop has been terminated")
				return nil
			}

			doAdvertise(ctx, servers)
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
	name := param.Xrootd_Sitename.GetString()
	if name == "" {
		return errors.New(fmt.Sprintf("%s name isn't set", server.GetServerType()))
	}

	err := server.GetNamespaceAdsFromDirector()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("%s failed to get namespaceAds from the director", server.GetServerType()))
	}
	serverUrl := param.Origin_Url.GetString()
	webUrl := param.Server_ExternalWebUrl.GetString()
	serverIssuer, err := config.GetServerIssuerURL()
	if err != nil {
		return errors.Wrap(err, "failed to get server issuer URL")
	}

	if server.GetServerType().IsEnabled(config.CacheType) {
		serverUrl = param.Cache_Url.GetString()
		webUrl = param.Server_ExternalWebUrl.GetString()
	}

	ad, err := server.CreateAdvertisement(name, serverUrl, webUrl)
	if err != nil {
		return err
	}

	body, err := json.Marshal(*ad)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to generate JSON description of %s", server.GetServerType()))
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return err
	}
	directorUrlStr := fedInfo.DirectorEndpoint
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "failed to parse Federation.DirectorURL")
	}

	directorUrl.Path = "/api/v1.0/director/register" + server.GetServerType().String()

	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = serverIssuer
	advTokenCfg.AddAudiences(fedInfo.DirectorEndpoint)
	advTokenCfg.Subject = "origin"
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	// CreateToken also handles validation for us
	tok, err := advTokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create director advertisement token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "failed to create a POST request for director advertisement")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	userAgent := "pelican-" + strings.ToLower(server.GetServerType().String()) + "/" + config.GetVersion()
	req.Header.Set("User-Agent", userAgent)

	// We should switch this over to use the common transport, but for that to happen
	// that function needs to be exported from pelican
	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to start the request for director advertisement")
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(body))
		}
		if respErr.ApprovalError {
			return fmt.Errorf("the director rejected the server advertisement with error: %s. Please contact the administrators of %s for more information.", respErr.Error, fedInfo.NamespaceRegistrationEndpoint)
		}
		return errors.Errorf("error during director registration: %v", respErr.Error)
	}

	return nil
}
