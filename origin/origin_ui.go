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
	"github.com/pkg/errors"
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
		Type              string        `json:"type"`              // "posix" | "s3" | "https" | "globus" | "xroot"
		Status            regStatusEnum `json:"status"`            // Origin registration status
		StatusDescription string        `json:"statusDescription"` // Description of the status
		EditUrl           string        `json:"editUrl"`           // URL to edit the origin registration

		// For S3 backend
		S3Region     string `json:"s3Region,omitempty"`
		S3ServiceUrl string `json:"s3ServiceUrl,omitempty"`
		S3UrlStyle   string `json:"s3UrlStyle,omitempty"`

		// For https backend
		HttpServiceUrl string `json:"httpServiceUrl,omitempty"`

		Exports []exportWithStatus `json:"exports"`
	}
)

func handleExports(ctx *gin.Context) {
	st := param.Origin_StorageType.GetString()
	storageType, err := server_utils.ParseOriginStorageType(st)
	if err != nil {
		log.Errorf("Failed to parse origin storage type: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Server encountered error when parsing the storage type of the origin: " + err.Error()})
	}

	res := exportsRes{Type: string(storageType)}

	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	// Only use hostname:port
	originPrefix := server_structs.GetOriginNs(extUrl.Host)
	if !registrationsStatus.Has(originPrefix) {
		if err := FetchAndSetRegStatus(originPrefix); err != nil {
			log.Errorf("Failed to fetch registration status from the registry: %v", err)
			ctx.JSON(http.StatusInternalServerError,
				server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to fetch registration status from the registry"})
			return
		}
	}
	if rs := registrationsStatus.Get(originPrefix); rs == nil {
		log.Error("Failed to fetch registration status from the registry: can't find registration status after querying registry")
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to fetch registration status from the registry"})
		return
	} else {
		// rs is not nil
		res.Status = rs.Value().Status
		res.StatusDescription = rs.Value().Msg
		res.EditUrl = rs.Value().EditUrl
	}

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

	if res.EditUrl != "" {
		res.EditUrl += "&access_token=" + token
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

	res.Exports = wrappedExports

	switch storageType {
	case server_utils.OriginStorageS3:
		res.S3Region = param.Origin_S3Region.GetString()
		res.S3ServiceUrl = param.Origin_S3ServiceUrl.GetString()
		res.S3UrlStyle = param.Origin_S3UrlStyle.GetString()
	case server_utils.OriginStorageHTTPS:
		res.HttpServiceUrl = param.Origin_HttpServiceUrl.GetString()
	}
	ctx.JSON(http.StatusOK, res)
}

func RegisterOriginWebAPI(engine *gin.Engine) error {
	originWebAPI := engine.Group("/api/v1.0/origin_ui")
	{
		originWebAPI.GET("/exports", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleExports)
	}

	// Globus backend specific. Config other origin routes above this line
	if server_utils.OriginStorageType(param.Origin_StorageType.GetString()) !=
		server_utils.OriginStorageGlobus {
		return nil
	}

	_, err := GetGlobusOAuthCfg()
	if err != nil {
		return errors.Wrapf(err, "failed to initialize Globus OAuth client")
	}

	seHandler, err := web_ui.GetSessionHandler()
	if err != nil {
		return err
	}

	originGlobusAPI := originWebAPI.Group("/globus")
	{
		originGlobusAPI.GET("/exports", web_ui.AuthHandler, web_ui.AdminAuthHandler, listGlobusExports)

		globusAuthAPI := originGlobusAPI.Group("/auth", seHandler)
		globusAuthAPI.GET("/login/:id", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleGlobusAuth)
		globusAuthAPI.GET("/callback", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleGlobusCallback)
	}
	return nil
}
