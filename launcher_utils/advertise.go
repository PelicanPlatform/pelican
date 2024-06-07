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
	"github.com/pelicanplatform/pelican/utils"
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

// Get the site name from the registry given a namespace prefix
func getSitenameFromReg(ctx context.Context, prefix string) (sitename string, err error) {
	fed, err := config.GetFederation(ctx)
	if err != nil {
		return
	}
	if fed.NamespaceRegistrationEndpoint == "" {
		err = fmt.Errorf("unable to fetch site name from the registry. Federation.RegistryUrl or Federation.DiscoveryUrl is unset")
		return
	}
	requestUrl, err := url.JoinPath(fed.NamespaceRegistrationEndpoint, "api/v1.0/registry", prefix)
	if err != nil {
		return
	}
	res, err := utils.MakeRequest(context.Background(), requestUrl, http.MethodGet, nil, nil)
	if err != nil {
		return
	}
	ns := server_structs.Namespace{}
	err = json.Unmarshal(res, &ns)
	if err != nil {
		return
	}
	sitename = ns.AdminMetadata.SiteName
	return
}

func advertiseInternal(ctx context.Context, server server_structs.XRootDServer) error {
	name := ""
	var err error
	// Fetch site name from the registry, if not, fall back to Xrootd.Sitename.
	if server.GetServerType().IsEnabled(config.OriginType) {
		// Note we use Server_ExternalWebUrl as the origin prefix
		// But caches still use Xrootd_Sitename, which will be changed to Server_ExternalWebUrl in
		// https://github.com/PelicanPlatform/pelican/issues/1351
		extUrlStr := param.Server_ExternalWebUrl.GetString()
		extUrl, _ := url.Parse(extUrlStr)
		// Only use hostname:port
		originPrefix := server_structs.GetOriginNs(extUrl.Host)
		name, err = getSitenameFromReg(ctx, originPrefix)
		if err != nil {
			log.Errorf("Failed to get sitename from the registry for the origin. Will fallback to use Xrootd.Sitename: %v", err)
		}
	} else if server.GetServerType().IsEnabled(config.CacheType) {
		cachePrefix := server_structs.GetCacheNS(param.Xrootd_Sitename.GetString())
		name, err = getSitenameFromReg(ctx, cachePrefix)
		if err != nil {
			log.Errorf("Failed to get sitename from the registry for the cache. Will fallback to use Xrootd.Sitename: %v", err)
		}
	}

	if name == "" {
		log.Infof("Sitename from the registry is empty, fall back to Xrootd.Sitename: %s", param.Xrootd_Sitename.GetString())
		name = param.Xrootd_Sitename.GetString()
	}
	if name == "" {
		return errors.New(fmt.Sprintf("%s name isn't set. Please set the name via Xrootd.Sitename", server.GetServerType()))
	}

	if err = server.GetNamespaceAdsFromDirector(); err != nil {
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
	if server.GetServerType().IsEnabled(config.CacheType) {
		advTokenCfg.Subject = "cache"
	} else if server.GetServerType().IsEnabled(config.OriginType) {
		advTokenCfg.Subject = "origin"
	}
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

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read the response body for director advertisement")
	}
	if resp.StatusCode > 299 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(body))
		}
		if respErr.ApprovalError {
			// Removed the "Please contact admin..." section since the director now provides contact information
			return fmt.Errorf("the director rejected the server advertisement: %s", respErr.Error)
		}
		return errors.Errorf("error during director advertisement: %v", respErr.Error)
	}

	return nil
}
