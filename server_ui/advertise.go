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

package server_ui

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
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type directorResponse struct {
	Error         string `json:"error"`
	ApprovalError bool   `json:"approval_error"`
}

func doAdvertise(ctx context.Context, servers []server_utils.XRootDServer) {
	log.Debugf("About to advertise %d XRootD servers", len(servers))
	err := Advertise(ctx, servers)
	if err != nil {
		log.Warningln("XRootD server advertise failed:", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server advertise failed: %v", err))
	} else {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
	}
}

func LaunchPeriodicAdvertise(ctx context.Context, egrp *errgroup.Group, servers []server_utils.XRootDServer) error {
	doAdvertise(ctx, servers)

	ticker := time.NewTicker(1 * time.Minute)
	egrp.Go(func() error {

		for {
			select {
			case <-ticker.C:
				err := Advertise(ctx, servers)
				if err != nil {
					log.Warningln("XRootD server advertise failed:", err)
					metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server advertise failed: %v", err))
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

func Advertise(ctx context.Context, servers []server_utils.XRootDServer) error {
	var firstErr error
	for _, server := range servers {
		err := advertiseInternal(ctx, server)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func advertiseInternal(ctx context.Context, server server_utils.XRootDServer) error {
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
	prefix := param.Origin_NamespacePrefix.GetString()
	if server.GetServerType().IsEnabled(config.CacheType) {
		serverUrl = param.Cache_Url.GetString()
		webUrl = param.Server_ExternalWebUrl.GetString()
		prefix = "/caches/" + param.Xrootd_Sitename.GetString()
	}

	ad, err := server.CreateAdvertisement(name, serverUrl, webUrl)
	if err != nil {
		return err
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to generate JSON description of %s", server.GetServerType()))
	}

	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse Federation.DirectorURL")
	}

	directorUrl.Path = "/api/v1.0/director/register" + server.GetServerType().String()

	issuerUrl, err := server_utils.GetNSIssuerURL(prefix)
	if err != nil {
		return err
	}

	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = issuerUrl
	advTokenCfg.AddAudiences(param.Federation_DirectorUrl.GetString())
	advTokenCfg.Subject = "origin"
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	// CreateToken also handles validation for us
	tok, err := advTokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create director advertisement token")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for director registration")
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
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return errors.Wrapf(unmarshalErr, "Could not unmarshal the director's response, which responded %v from director registration: %v", resp.StatusCode, resp.Status)
		}
		if respErr.ApprovalError {
			return fmt.Errorf("The namespace %q requires administrator approval. Please contact the administrators of %s for more information.", param.Origin_NamespacePrefix.GetString(), param.Federation_RegistryUrl.GetString())
		}
		return errors.Errorf("Error during director registration: %v\n", respErr.Error)
	}

	return nil
}
