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
package web_ui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	DowntimeInput struct {
		CreatedBy   string                  `json:"createdBy"`  // Person who created this downtime
		UpdatedBy   string                  `json:"updatedBy"`  // Person who last updated this downtime
		ServerName  string                  `json:"serverName"` // Empty for Origin/Cache input; Not empty for Registry input
		ServerID    string                  `json:"serverId"`
		Source      string                  `json:"source"` // Automatically set by the server; should only be set by input during testing
		Class       server_structs.Class    `json:"class"`
		Description string                  `json:"description"`
		Severity    server_structs.Severity `json:"severity"`
		StartTime   int64                   `json:"startTime"` // Epoch UTC in seconds
		EndTime     int64                   `json:"endTime"`   // Epoch UTC in seconds
	}
)

// Get the Pelican service that set the downtime
func getDowntimeSource() (string, error) {
	enabledServers := config.GetEnabledServerString(true)
	if len(enabledServers) == 0 {
		log.Warningf("Downtime source is not set. No Pelican service is enabled.")
		return "", errors.New("No Pelican service is enabled")
	}
	// Multiple servers in a single process ("federation in a box") are not supported.
	// Because it only happens in testing, we don't need to handle it.
	if len(enabledServers) > 1 {
		log.Warningf("Downtime source is not set. Cannot determine which Pelican service set the downtime. Multiple servers are enabled: %s", enabledServers)
		return "", nil
	}
	// Only one server is enabled
	enabledServer := enabledServers[0]
	return enabledServer, nil
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

func isValidTimeRange(startTime, endTime int64) bool {
	// Check both startTime and endTime are in milliseconds
	// All reasonable millisecond timestamps today are >= 10^11, so
	// 0 < timestamp < 10^11 => not valid
	const msThreshold = int64(100_000_000_000)

	// startTime must be non‑negative, and if non‑zero, large enough to be ms
	if startTime < 0 {
		return false
	}
	if startTime != 0 && startTime < msThreshold {
		return false
	}

	// endTime must be either:
	//  • the special IndefiniteEndTime,
	//  • zero (meaning “not provided” in partial update), or
	//  • a non‑negative ms value ≥ msThreshold
	if endTime < 0 && endTime != server_structs.IndefiniteEndTime {
		return false
	}
	if endTime != 0 && endTime != server_structs.IndefiniteEndTime && endTime < msThreshold {
		return false
	}

	// When endTime is indefinite, the downtime is considered ongoing forever
	// Note: when you do a partial update and not provide startTime/endTime,
	// they are 0 by default and should be considered as valid input
	if endTime == server_structs.IndefiniteEndTime {
		return true
	}
	return startTime <= endTime
}

func validateDowntimeInput(downtimeInput DowntimeInput) error {
	if downtimeInput.Class != "" && !isValidClass(downtimeInput.Class) {
		return errors.New("Invalid input downtime class")
	}
	if downtimeInput.Severity != "" && !isValidSeverity(downtimeInput.Severity) {
		return errors.New("Invalid input downtime severity")
	}
	if !isValidTimeRange(downtimeInput.StartTime, downtimeInput.EndTime) {
		return errors.New("Invalid downtime time range")
	}
	return nil
}

// validateServerType checks if any currently enabled server matches the allowed server types slice.
func validateServerType(allowedServerTypes []server_structs.ServerType) bool {
	if len(allowedServerTypes) == 0 {
		return false
	}

	enabledServers := config.GetEnabledServerString(true)
	if len(enabledServers) == 0 {
		return false
	}

	allowed := make(map[string]struct{}, len(allowedServerTypes))
	for _, serverType := range allowedServerTypes {
		allowed[strings.ToLower(serverType.String())] = struct{}{}
	}

	for _, enabled := range enabledServers {
		if _, ok := allowed[enabled]; ok {
			return true
		}
	}

	return false
}

func HandleCreateDowntime(ctx *gin.Context) {
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
	idStr := id.String()
	if ctx.Param("uuid") != "" {
		idStr = ctx.Param("uuid")
	}

	if err = validateDowntimeInput(downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	}

	user, _, _, err := GetUserGroups(ctx)
	if user == "" || err != nil {
		user = ctx.GetString("User")
		if user == "" {
			log.Warning("Failed to get user from context")
		}
	}

	// Source stands for the Pelican service that creates this downtime
	// Mostly automatically set by the server via getDowntimeSource function; should only be set by input during testing
	if downtimeInput.Source == "" {
		downtimeInput.Source, err = getDowntimeSource()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		}
	}

	// If the downtime is created by the Origin or Cache, and the current server is not a Registry, serverName and serverID will be set automatically
	serverType := server_structs.NewServerType()
	serverType.SetString(downtimeInput.Source)
	if (serverType == server_structs.OriginType || serverType == server_structs.CacheType) && !validateServerType([]server_structs.ServerType{server_structs.RegistryType}) {
		metadata, err := server_utils.GetServerMetadata(ctx, serverType)
		if err != nil {
			log.Debugf("Unable to get server metadata for %s: %v", serverType.String(), err)
		}
		if downtimeInput.ServerName == "" {
			downtimeInput.ServerName = metadata.Name
		}
		if downtimeInput.ServerID == "" {
			downtimeInput.ServerID = metadata.ID
		}
	}

	downtime := server_structs.Downtime{
		UUID:        idStr,
		CreatedBy:   user,
		UpdatedBy:   user,
		ServerID:    downtimeInput.ServerID,
		ServerName:  downtimeInput.ServerName,
		Source:      downtimeInput.Source,
		Class:       downtimeInput.Class,
		Description: downtimeInput.Description,
		Severity:    downtimeInput.Severity,
		StartTime:   downtimeInput.StartTime,
		EndTime:     downtimeInput.EndTime,
	}

	// Mirror to Registry when running as Origin/Cache so downtime persists centrally (Director polls Registry for all sources)
	// This prevents the Registry database from getting out of sync with the Origin/Cache local downtime state.
	if err := mirrorDowntimeToRegistry(ctx, downtime, http.MethodPost, idStr); err != nil {
		ctx.JSON(http.StatusBadGateway, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to create downtime with UUID " + idStr + " at the Registry: " + err.Error(),
		})
		return
	}

	if err := database.CreateDowntime(&downtime); err != nil {
		// [For federation-in-a-box only] If the downtime already exists, update the metadata
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			log.Debugf("Downtime already exists: %v; syncing metadata", downtime)
			existing, getErr := database.GetDowntimeByUUID(idStr)
			if getErr != nil {
				ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Failed to load existing downtime with UUID " + idStr + " during create: " + getErr.Error(),
				})
				return
			}

			existing.CreatedBy = downtime.CreatedBy
			existing.UpdatedBy = downtime.UpdatedBy
			if downtime.ServerName != "" {
				existing.ServerName = downtime.ServerName
			}
			if downtime.ServerID != "" {
				existing.ServerID = downtime.ServerID
			}
			existing.Description = downtime.Description
			existing.Class = downtime.Class
			existing.Severity = downtime.Severity
			existing.StartTime = downtime.StartTime
			existing.EndTime = downtime.EndTime

			if updateErr := database.UpdateDowntime(idStr, existing); updateErr != nil {
				ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Failed to update existing downtime with UUID " + idStr + " during create: " + updateErr.Error(),
				})
				return
			}
			downtime = *existing
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to create downtime with UUID " + idStr + ": " + err.Error(),
			})
			return
		}
	}
	ctx.JSON(http.StatusOK, downtime)
}

func HandleGetDowntime(ctx *gin.Context) {
	status := ctx.Query("status")
	source := strings.ToLower(ctx.Query("source")) // Which Pelican service set the downtime
	var downtimes []server_structs.Downtime
	var err error

	switch status {
	case "all":
		downtimes, err = database.GetAllDowntimes(source)
	default:
		// "incomplete" includes active and future downtimes
		downtimes, err = database.GetIncompleteDowntimes(source)
	}

	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to get active downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtimes)
}

func HandleGetDowntimeByUUID(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	downtime, err := database.GetDowntimeByUUID(uuid)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get downtime by UUID " + uuid + ": " + err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func HandleUpdateDowntime(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	var downtimeInput DowntimeInput
	if err := ctx.ShouldBindJSON(&downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Invalid request payload"})
		return
	}

	if err := validateDowntimeInput(downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	}

	// Retrieve existing downtime record from the database
	existingDowntime, err := database.GetDowntimeByUUID(uuid)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Downtime record not found",
		})
		return
	}

	// Downtimes created by a server admin are read-only for federation admins
	dtSourceServer := server_structs.NewServerType()
	dtSourceServer.SetString(existingDowntime.Source)
	if validateServerType([]server_structs.ServerType{server_structs.RegistryType}) && dtSourceServer != server_structs.RegistryType {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Downtimes created by a server admin are read-only for federation admins",
		})
		return
	}

	user, _, _, err := GetUserGroups(ctx)
	if user == "" || err != nil {
		user = ctx.GetString("User")
		if user == "" {
			log.Warningf("Failed to get user from context")
		}
	}
	downtimeInput.UpdatedBy = user

	updatedDowntime := *existingDowntime
	// Only update fields provided in the request (different from default values)
	if downtimeInput.CreatedBy != "" {
		updatedDowntime.CreatedBy = downtimeInput.CreatedBy
	}
	if downtimeInput.Class != "" {
		updatedDowntime.Class = downtimeInput.Class
	}
	if downtimeInput.Description != "" {
		updatedDowntime.Description = downtimeInput.Description
	}
	if downtimeInput.Severity != "" {
		updatedDowntime.Severity = downtimeInput.Severity
	}
	if downtimeInput.StartTime != 0 {
		updatedDowntime.StartTime = downtimeInput.StartTime
	}
	if downtimeInput.EndTime != 0 {
		updatedDowntime.EndTime = downtimeInput.EndTime
	}
	updatedDowntime.UpdatedBy = downtimeInput.UpdatedBy
	// To avoid confusion, we don't allow to change the server name and id in an update

	// Mirror updates to the Registry to keep the central downtime records consistent with local changes.
	// This prevents the Registry database from getting out of sync with the Origin/Cache local downtime state.
	if err := mirrorDowntimeToRegistry(ctx, updatedDowntime, http.MethodPut, uuid); err != nil {
		ctx.JSON(http.StatusBadGateway, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to update downtime with UUID " + uuid + " at the Registry: " + err.Error(),
		})
		return
	}

	if err := database.UpdateDowntime(uuid, &updatedDowntime); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to update downtime with UUID " + uuid + ": " + err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, updatedDowntime)
}

func HandleDeleteDowntime(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	existingDowntime, err := database.GetDowntimeByUUID(uuid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Downtime record not found for delete: UUID " + uuid,
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to query downtime for delete by UUID " + uuid + ": " + err.Error(),
			})
		}
		return
	}

	// Mirror deletion to the Registry so the central DB removes the downtime as well.
	// This prevents the Registry database from getting out of sync with the Origin/Cache local downtime state.
	if err := mirrorDowntimeToRegistry(ctx, *existingDowntime, http.MethodDelete, uuid); err != nil {
		ctx.JSON(http.StatusBadGateway, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to delete downtime with UUID " + uuid + " at the Registry: " + err.Error(),
		})
		return
	}

	if err := database.DeleteDowntime(uuid); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to delete downtime with UUID " + uuid + ": " + err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "Downtime deleted successfully"})
}

// mirrorDowntimeToRegistry forwards a downtime CRUD to the Registry, if the
// current server has an Origin or Cache service. It uses the server's issuer key to mint a short-lived
// service token and sets Authorization: Bearer <token>.
func mirrorDowntimeToRegistry(ctx *gin.Context, dt server_structs.Downtime, method string, id string) error {
	if id == "" {
		return errors.New("downtime ID is required")
	}

	// Only mirror downtime to Registry when this server is an Origin or Cache
	if !validateServerType([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType}) {
		return nil
	}

	fed, err := config.GetFederation(ctx)
	if err != nil || fed.RegistryEndpoint == "" {
		return errors.Wrap(err, "failed to load federation configuration")
	}

	regURL, err := url.Parse(fed.RegistryEndpoint)
	if err != nil {
		return errors.Wrap(err, "failed to parse registry endpoint")
	}

	// In "federation in a box" scenario, all services run in the same process with the same URL.
	// Skip mirroring if the Registry endpoint is the same as the current server to avoid recursion.
	currentServerURL := param.Server_ExternalWebUrl.GetString()
	if currentServerURL != "" {
		currentURL, err := url.Parse(currentServerURL)
		if err == nil && currentURL.Host == regURL.Host {
			log.Debugf("Skipping mirror to registry because Registry endpoint (%s) is the same as current server (%s)", regURL.Host, currentURL.Host)
			return nil
		}
	}

	regURL.Path = path.Join(regURL.Path, "api", "v1.0", "downtime", id)

	tokCfg := token.NewWLCGToken()
	tokCfg.Lifetime = 2 * time.Minute
	tokCfg.Subject = dt.ServerID
	tokCfg.AddAudienceAny()
	switch method {
	case http.MethodPost:
		tokCfg.AddScopes(token_scopes.Pelican_DowntimeCreate)
	case http.MethodPut:
		tokCfg.AddScopes(token_scopes.Pelican_DowntimeModify)
	case http.MethodDelete:
		tokCfg.AddScopes(token_scopes.Pelican_DowntimeDelete)
	default:
		// For safety, do not mint a token with an unexpected scope for unknown methods
		return errors.Errorf("unsupported downtime mirror method: %s", method)
	}
	tok, err := tokCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to mint downtime token")
	}

	headers := map[string]string{"Authorization": "Bearer " + tok}
	var data map[string]interface{}
	if method == http.MethodPost || method == http.MethodPut {
		payload, err := json.Marshal(dt)
		if err != nil {
			return errors.Wrap(err, "failed to marshal downtime payload")
		}
		if err := json.Unmarshal(payload, &data); err != nil {
			return errors.Wrap(err, "failed to unmarshal downtime payload")
		}
	}
	tr := config.GetTransport()
	if _, err := utils.MakeRequest(ctx, tr, regURL.String(), method, data, headers); err != nil {
		return errors.Wrapf(err, "failed to mirror downtime to registry at %s", regURL.String())
	}

	return nil
}
