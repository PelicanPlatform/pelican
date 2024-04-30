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

package origin

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

type (
	exportsRes struct {
		Type    string             `json:"type"` // either "posix" or "s3"
		Exports []exportWithStatus `json:"exports"`
	}
)

func handleExports(ctx *gin.Context) {
	storageType := param.Origin_StorageType.GetString()
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		log.Errorf("Failed to get the origin exports: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Server encountered error when getting the origin exports: " + err.Error()})
		return
	}
	wrappedExports, err := wrapExportsByStatus(exports)
	if err != nil {
		log.Errorf("Failed to get the registration status of the exported prefixes: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Server encountered error when getting the registration status for the exported prefixes: " + err.Error()})
		return
	}
	// Create token for accessing registry edit page
	issuerUrl, err := config.GetServerIssuerURL()
	if err != nil {
		log.Errorf("Failed to get server issuer url %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Server encountered error when getting server issuer url " + err.Error()})
		return
	}
	fed, err := config.GetFederation(ctx)
	if err != nil {
		log.Error("handleExports: failed to get federaion:", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server error when getting federation information: " + err.Error(),
		})
	}
	tc := token.NewWLCGToken()
	tc.Issuer = issuerUrl
	tc.Lifetime = 15 * time.Minute
	tc.Subject = issuerUrl
	tc.AddScopes(token_scopes.Registry_EditRegistration)
	tc.AddAudiences(fed.NamespaceRegistrationEndpoint)
	token, err := tc.CreateToken()
	if err != nil {
		log.Errorf("Failed to create access token for editing registration %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Server encountered error when creating token for access registry edit page " + err.Error()})
		return
	}

	for idx, export := range wrappedExports {
		if export.EditUrl != "" {
			parsed, err := url.Parse(export.EditUrl)
			if err != nil {
				// current editUrl ends with "/?id=<x>"
				wrappedExports[idx].EditUrl += "&access_token=" + token
				continue
			}
			exQuery := parsed.Query()
			exQuery.Add("access_token", token)
			parsed.RawQuery = exQuery.Encode()
			wrappedExports[idx].EditUrl = parsed.String()
		}
	}

	ctx.JSON(http.StatusOK, exportsRes{Type: storageType, Exports: wrappedExports})
}

func RegisterOriginWebAPI(engine *gin.Engine) {
	originWebAPI := engine.Group("/api/v1.0/origin_ui")
	{
		originWebAPI.GET("/exports", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleExports)
	}
}
