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
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"google.golang.org/appengine/log"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	DowntimeInput struct {
		CreatedBy   string                  `json:"createdBy"` // Person who created this downtime
		Class       server_structs.Class    `json:"class"`
		Description string                  `json:"description"`
		Severity    server_structs.Severity `json:"severity"`
		StartTime   int64                   `json:"startTime"` // Epoch UTC in seconds
		EndTime     int64                   `json:"endTime"`   // Epoch UTC in seconds
	}
)

// Indicate the downtime is ongoing indefinitely.
// We chose -1 to avoid the default value (0) of the int64 type
const indefiniteEndTime int64 = -1

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
	// When endTime is indefinite, the downtime is considered ongoing forever
	// Note: when you do a partial update and not provide startTime/endTime,
	// they are 0 by default and should be considered as valid input
	if endTime == indefiniteEndTime {
		return startTime >= 0
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

	if err = validateDowntimeInput(downtimeInput); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	}

	user, _, err := GetUserGroups(ctx)
	if user == "" || err != nil {
		user = ctx.GetString("User")
		if user == "" {
			user = "unknown"
			log.Warningf(ctx, "Failed to get user from context")
		}
	}
	downtime := server_structs.Downtime{
		UUID:        id.String(),
		CreatedBy:   user,
		Class:       downtimeInput.Class,
		Description: downtimeInput.Description,
		Severity:    downtimeInput.Severity,
		StartTime:   downtimeInput.StartTime,
		EndTime:     downtimeInput.EndTime,
	}

	if err := database.CreateDowntime(&downtime); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to create downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, downtime)
}

func HandleGetDowntime(ctx *gin.Context) {
	status := ctx.Query("status")
	var downtimes []server_structs.Downtime
	var err error

	switch status {
	case "all":
		downtimes, err = database.GetAllDowntimes()
	default:
		// "incomplete" includes active and future downtimes
		downtimes, err = database.GetIncompleteDowntimes()
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
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to get downtime by UUID: " + err.Error()})
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

	// Only update fields provided in the request (different from default values)
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

	if err := database.UpdateDowntime(uuid, existingDowntime); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to update downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, existingDowntime)
}

func HandleDeleteDowntime(ctx *gin.Context) {
	uuid := ctx.Param("uuid")
	if err := database.DeleteDowntime(uuid); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to delete downtime: " + err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "Downtime deleted successfully"})
}
