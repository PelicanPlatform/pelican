/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package server_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	baseAdOnce sync.Once
	baseAd     server_structs.ServerBaseAd
	baseAdErr  error
)

// Get the server's metadata from the registry given a namespace prefix.
//
// Here, the "prefix" is typically /origins/<hostname> or similar,
// not the namespace prefix for an object.
func getServerMetadataFromReg(ctx context.Context, prefix string) (server server_structs.ServerRegistration, err error) {
	fed, err := config.GetFederation(ctx)
	if err != nil {
		return
	}
	if fed.RegistryEndpoint == "" {
		err = fmt.Errorf("unable to fetch site name from the registry. Federation.RegistryUrl or Federation.DiscoveryUrl is unset")
		return
	}
	requestUrl, err := url.JoinPath(fed.RegistryEndpoint, "api/v1.0/registry/server", prefix)
	if err != nil {
		return
	}
	tr := config.GetTransport()
	res, err := utils.MakeRequest(context.Background(), tr, requestUrl, http.MethodGet, nil, nil)
	if err != nil {
		return
	}
	err = json.Unmarshal(res, &server)
	if err != nil {
		return
	}
	return
}

// Centralized code for determining the "name" and "id" of the service.
//
// The server's name should be unique and machine-friendly: typically, it's
// the hostname/FQDN of the host.  It will be registered at the registry to
// ensure uniqueness within the federation.
//
// There are improvements to do here: once registered, the server should
// serialize the name.  It should also be for the service itself, not
// specific to the "origin" or "cache" component.
//
// In the current implementation, if the origin component is enabled, we
// always look up the registered "site name" for the hostname in the registry
// under /origins; otherwise, we look it up under /caches.
func GetServerMetadata(ctx context.Context, server server_structs.ServerType) (name string, id string, err error) {

	var nameFromReg string
	var idFromReg string
	var serverReg server_structs.ServerRegistration
	// Fetch site name from the registry, if not, fall back to Xrootd.Sitename.
	if server.IsEnabled(server_structs.DirectorType) {
		exturlStr := param.Server_ExternalWebUrl.GetString()
		var extUrl *url.URL
		extUrl, err = url.Parse(exturlStr)
		if err != nil {
			err = errors.Wrap(err, "unable to determine service name")
			return
		}
		nameFromReg = extUrl.Host
	} else if server.IsEnabled(server_structs.OriginType) {
		// Note we use Server_ExternalWebUrl as the origin prefix
		// But caches still use Xrootd_Sitename, which will be changed to Server_ExternalWebUrl in
		// https://github.com/PelicanPlatform/pelican/issues/1351
		extUrlStr := param.Server_ExternalWebUrl.GetString()
		extUrl, _ := url.Parse(extUrlStr)
		// Only use hostname:port
		originPrefix := server_structs.GetOriginNs(extUrl.Host)
		serverReg, err = getServerMetadataFromReg(ctx, originPrefix)
		if err != nil {
			log.Errorf("Failed to get metadata from the registry for the origin. Will fallback to using %s: %v", param.Xrootd_Sitename.GetName(), err)
		} else {
			nameFromReg = serverReg.Name
			idFromReg = serverReg.ID
		}
	} else if server.IsEnabled(server_structs.CacheType) {
		cachePrefix := server_structs.GetCacheNs(param.Xrootd_Sitename.GetString())
		serverReg, err = getServerMetadataFromReg(ctx, cachePrefix)
		if err != nil {
			log.Errorf("Failed to get metadata from the registry for the cache. Will fallback to use %s: %v", param.Xrootd_Sitename.GetName(), err)
		} else {
			nameFromReg = serverReg.Name
			idFromReg = serverReg.ID
		}
	}

	if nameFromReg == "" {
		log.Infof("Sitename from the registry is empty, fall back to %s: %s", param.Xrootd_Sitename.GetName(), param.Xrootd_Sitename.GetString())
		name = param.Xrootd_Sitename.GetString()
	} else {
		// Use the registered sitename as service name if it is not empty
		name = nameFromReg
		id = idFromReg
		// Warn the user if the sitename from the registry does not match the local configuration
		if nameFromReg != param.Xrootd_Sitename.GetString() && param.Xrootd_Sitename.GetString() != "" {
			log.Warningf("Sitename mismatch detected:\n"+
				"  Registered sitename: %q\n"+
				"  Local sitename:      %q\n"+
				"Pelican will use the registered sitename as your service name.\n"+
				"Contact the federation administrator to update the sitename in the Registry or update your local config to maintain consistency.",
				nameFromReg, param.Xrootd_Sitename.GetString())
		}
	}
	if name == "" {
		err = errors.Errorf("%s name isn't set. Please set the name via %s", server.String(), param.Xrootd_Sitename.GetName())
	}
	return
}

// Returns `true` if the provided ad was generated by the current process.
//
// We define "self" to be any ad with our name and instance ID.
func IsDirectorAdFromSelf(ctx context.Context, ad server_structs.ServerBaseAdInterface) (bool, error) {
	if ad == nil {
		return false, fmt.Errorf("received nil advertisement")
	}

	baseAdOnce.Do(func() {
		var name string
		name, _, baseAdErr = GetServerMetadata(ctx, server_structs.DirectorType)
		if baseAdErr != nil {
			return
		}
		baseAd.Initialize(name)
	})
	if baseAdErr != nil {
		return false, baseAdErr
	}
	if ad.GetName() != baseAd.GetName() {
		return false, nil
	}
	if ad.GetInstanceID() != baseAd.GetInstanceID() {
		return false, nil
	}
	return true, nil
}
