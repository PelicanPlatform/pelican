/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package origin

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/web_ui"
)

// federationDiscoveryPath is where every Pelican client begins: a pelican://
// URL names a federation by hostname, and the client fetches this document from
// that host to learn what services the federation has.
const federationDiscoveryPath = "/.well-known/pelican-configuration"

// RegisterStandaloneFederationMetadata makes a standalone origin
// (Origin.EnableStandaloneMode) answer the one federation-level question a
// client asks before it transfers anything.
//
// The document names no director.  That absence is the signal: a client that
// discovers a federation with no director resolves objects against the
// discovery host itself, reading namespace and issuer metadata from the
// X-Pelican-* headers the origin returns on the object (see the auth middleware
// in origin_serve).  Nothing redirects -- the object lives at the URL the client
// already constructed.
//
// It must only be called when config.IsStandaloneOrigin() is true; a federated
// origin's federation metadata belongs to its director.
func RegisterStandaloneFederationMetadata(engine *gin.Engine) error {
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, err := url.Parse(extUrlStr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse %s while publishing the standalone origin's federation metadata",
			param.Server_ExternalWebUrl.GetName())
	}
	// Rewriting the scheme here would publish an https:// endpoint for a port
	// that speaks cleartext, and every client that trusted the document would
	// fail its handshake.  config.ComputeExternalWebUrl already defaults the
	// scheme to https and strips an explicit :443, so a non-https value can only
	// come from an operator who set one deliberately.
	if extUrl.Scheme != "https" {
		return errors.Errorf("%s must be an https:// URL to publish the standalone origin's federation metadata, but it is %q; "+
			"clients discover this federation over TLS and have no way to fall back",
			param.Server_ExternalWebUrl.GetName(), extUrlStr)
	}
	self := extUrl.String()

	engine.GET(federationDiscoveryPath, web_ui.ServerHeaderMiddleware, func(ctx *gin.Context) {
		// Director, registry, and broker endpoints are all deliberately empty:
		// none of those services exist here, and naming this origin for them
		// would send clients into a 404 rather than the directorless path they
		// are meant to take.
		rs := pelican_url.FederationDiscovery{
			DiscoveryEndpoint: self,
			JwksUri:           self + "/.well-known/issuer.jwks",
		}

		jsonData, err := json.MarshalIndent(rs, "", "  ")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to marshal the standalone origin's discovery response",
			})
			return
		}
		jsonData = append(jsonData, '\n')
		ctx.Header("Content-Disposition", "attachment; filename=pelican-configuration.json")
		ctx.Data(http.StatusOK, "application/json", jsonData)
	})

	log.Infof("Standalone origin is publishing federation metadata at %s%s", self, federationDiscoveryPath)
	return nil
}
