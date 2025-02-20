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
	"github.com/google/uuid"
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

	DowntimeInput struct {
		CreatedBy   string                  `json:"createdBy"` // Person who created this downtime
		Class       server_structs.Class    `json:"class"`
		Description string                  `json:"description"`
		Severity    server_structs.Severity `json:"severity"`
		StartTime   int64                   `json:"startTime"` // Epoch UTC in seconds
		EndTime     int64                   `json:"endTime"`   // Epoch UTC in seconds
	}
)

func handleExports(ctx *gin.Context) {
	st := param.Origin_StorageType.GetString()
	storageType, err := server_structs.ParseOriginStorageType(st)
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
	tc.AddAudiences(fed.RegistryEndpoint)
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
	case server_structs.OriginStorageS3:
		res.S3Region = param.Origin_S3Region.GetString()
		res.S3ServiceUrl = param.Origin_S3ServiceUrl.GetString()
		res.S3UrlStyle = param.Origin_S3UrlStyle.GetString()
	case server_structs.OriginStorageHTTPS:
		res.HttpServiceUrl = param.Origin_HttpServiceUrl.GetString()
	}
	ctx.JSON(http.StatusOK, res)
}

func isValidClass(class server_structs.Class) bool {
	validClasses := map[server_structs.Class]bool{
		server_structs.SCHEDULED:   true,
		server_structs.UNSCHEDULED: true,
	}
	return validClasses[class]
}

func isValidSeverity(severity server_structs.Severity) bool {
	validSeverities := map[server_structs.Severity]bool{
		server_structs.Outage:                      true,
		server_structs.Severe:                      true,
		server_structs.IntermittentOutage:          true,
		server_structs.NoSignificantOutageExpected: true,
	}
	return validSeverities[severity]
}

func handleCreateDowntime(ctx *gin.Context) {
	var downtimeInput DowntimeInput
	if err := ctx.ShouldBindJSON(&downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid downtime request payload"})
		return
	}

	id, err := uuid.NewV7()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to create new UUID for new entry in downtimes table",
		})
		return
	}

	if !isValidClass(downtimeInput.Class) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid downtime class"})
		return
	}
	if !isValidSeverity(downtimeInput.Severity) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid downtime severity"})
		return
	}

	downtime := server_structs.Downtime{
		UUID:        id.String(),
		CreatedBy:   downtimeInput.CreatedBy,
		Class:       downtimeInput.Class,
		Description: downtimeInput.Description,
		Severity:    downtimeInput.Severity,
		StartTime:   downtimeInput.StartTime,
		EndTime:     downtimeInput.EndTime,
	}

	if err := createDowntime(&downtime); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to create downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func handleGetActiveDowntime(ctx *gin.Context) {
	downtime, err := getActiveDowntimes()
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to get active downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func handleGetAllDowntime(ctx *gin.Context) {
	downtime, err := getAllDowntimes()
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to get all downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func handleGetDowntimeByUUID(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	downtime, err := getDowntimeByUUID(uuid)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to get downtime by UUID: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func handleUpdateDowntime(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	var downtimeInput DowntimeInput
	if err := ctx.ShouldBindJSON(&downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid request payload"})
		return
	}

	if downtimeInput.Class != "" && !isValidClass(downtimeInput.Class) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid input downtime class"})
		return
	}
	if downtimeInput.Severity != "" && !isValidSeverity(downtimeInput.Severity) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid input downtime severity"})
		return
	}

	// Retrieve existing downtime record from the database
	existingDowntime, err := getDowntimeByUUID(uuid)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Downtime record not found",
		})
		return
	}

	// Only update fields provided in the request
	if downtimeInput.CreatedBy != "" {
		existingDowntime.CreatedBy = downtimeInput.CreatedBy
	}
	if downtimeInput.Class != "" {
		existingDowntime.Class = downtimeInput.Class
	}
	if downtimeInput.Description != "" {
		existingDowntime.Description = downtimeInput.Description
	}
	if downtimeInput.Severity != "" {
		existingDowntime.Severity = downtimeInput.Severity
	}
	if downtimeInput.StartTime != 0 {
		existingDowntime.StartTime = downtimeInput.StartTime
	}
	if downtimeInput.EndTime != 0 {
		existingDowntime.EndTime = downtimeInput.EndTime
	}

	if err := updateDowntime(uuid, existingDowntime); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to update downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, existingDowntime)
}

func handleDeleteDowntime(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	if err := deleteDowntime(uuid); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to delete downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "Downtime deleted successfully"})
}

func RegisterOriginWebAPI(engine *gin.Engine) error {
	originWebAPI := engine.Group("/api/v1.0/origin_ui", web_ui.ServerHeaderMiddleware)
	{
		originWebAPI.GET("/exports", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleExports)
	}

	originDowntimeAPI := originWebAPI.Group("/downtime")
	{
		originDowntimeAPI.POST("/", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleCreateDowntime)
		originDowntimeAPI.GET("/", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleGetActiveDowntime)
		originDowntimeAPI.GET("/all", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleGetAllDowntime)
		originDowntimeAPI.GET("/:uuid", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleGetDowntimeByUUID)
		originDowntimeAPI.PUT("/:uuid", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleUpdateDowntime)
		originDowntimeAPI.DELETE("/:uuid", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleDeleteDowntime)
	}

	// Globus backend specific. Config other origin routes above this line
	if server_structs.OriginStorageType(param.Origin_StorageType.GetString()) !=
		server_structs.OriginStorageGlobus {
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
