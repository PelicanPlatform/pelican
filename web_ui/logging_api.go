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

package web_ui

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	// SetLogLevelRequest represents a request to temporarily change log level
	SetLogLevelRequest struct {
		Level         string `json:"level" binding:"required"`          // Log level (e.g., "debug", "info", "warn", "error")
		Duration      int    `json:"duration" binding:"required,min=1"` // Duration in seconds
		ParameterName string `json:"parameterName"`                     // Parameter name like "Logging.Level" or "Logging.Origin.Xrootd"
	}

	// LogLevelChangeResponse represents a log level change with its metadata
	LogLevelChangeResponse struct {
		ChangeID      string    `json:"changeId"`
		Level         string    `json:"level"`
		ParameterName string    `json:"parameterName,omitempty"`
		EndTime       time.Time `json:"endTime"`
		Remaining     int       `json:"remainingSeconds"`
	}

	// LogLevelStatusResponse represents the current log level status
	LogLevelStatusResponse struct {
		CurrentLevel  string                   `json:"currentLevel"`
		BaseLevel     string                   `json:"baseLevel"`
		ActiveChanges []LogLevelChangeResponse `json:"activeChanges"`
		Parameters    []ParameterLevelStatus   `json:"parameters"`
	}

	// ParameterLevelStatus summarizes the current/base level for a parameter.
	ParameterLevelStatus struct {
		ParameterName string `json:"parameterName"`
		CurrentLevel  string `json:"currentLevel"`
		BaseLevel     string `json:"baseLevel"`
	}
)

// HandleSetLogLevel handles POST requests to temporarily change log level
func HandleSetLogLevel(ctx *gin.Context) {
	var req SetLogLevelRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request: " + err.Error(),
		})
		return
	}

	// Parse and validate the log level
	level, err := log.ParseLevel(req.Level)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid log level: " + req.Level,
		})
		return
	}

	parameterName := req.ParameterName
	if parameterName == "" {
		parameterName = "Logging.Level"
	}

	// Limit duration to a reasonable maximum (e.g., 24 hours)
	maxDuration := 24 * 60 * 60 // 24 hours in seconds
	if req.Duration > maxDuration {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Duration exceeds maximum allowed (24 hours)",
		})
		return
	}

	// Generate a unique ID for this change
	changeID := uuid.New().String()

	// Add the change to the log level manager
	duration := time.Duration(req.Duration) * time.Second
	manager := logging.GetLogLevelManager()
	if !manager.HasParameter(parameterName) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unsupported parameter for log level change",
		})
		return
	}
	if err := manager.AddChange(changeID, parameterName, level, duration); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to apply log level change: " + err.Error(),
		})
		return
	}

	endTime := time.Now().Add(duration)
	response := LogLevelChangeResponse{
		ChangeID:      changeID,
		Level:         level.String(),
		ParameterName: parameterName,
		EndTime:       endTime,
		Remaining:     req.Duration,
	}

	log.WithFields(log.Fields{
		"change_id": changeID,
		"level":     level.String(),
		"duration":  duration.String(),
		"user":      ctx.GetString("User"),
	}).Info("Temporary log level change requested")

	ctx.JSON(http.StatusOK, response)
}

// HandleGetLogLevel handles GET requests to retrieve current log level status
func HandleGetLogLevel(ctx *gin.Context) {
	manager := logging.GetLogLevelManager()
	activeChanges := manager.GetActiveChanges()
	parameterSnapshot := manager.GetParameterSnapshot()

	responseChanges := make([]LogLevelChangeResponse, 0, len(activeChanges))
	for _, change := range activeChanges {
		remaining := int(time.Until(change.EndTime).Seconds())
		if remaining < 0 {
			remaining = 0
		}
		responseChanges = append(responseChanges, LogLevelChangeResponse{
			ChangeID:      change.ChangeID,
			Level:         change.Level.String(),
			ParameterName: change.ParameterName,
			EndTime:       change.EndTime,
			Remaining:     remaining,
		})
	}

	parameters := make([]ParameterLevelStatus, 0, len(parameterSnapshot))
	globalCurrent := config.GetEffectiveLogLevel()
	globalBase := config.GetEffectiveLogLevel()
	if globalStatus, ok := parameterSnapshot[param.Logging_Level.GetName()]; ok {
		globalCurrent = globalStatus.Current
		globalBase = globalStatus.Base
	}

	for paramName, status := range parameterSnapshot {
		parameters = append(parameters, ParameterLevelStatus{
			ParameterName: paramName,
			CurrentLevel:  status.Current.String(),
			BaseLevel:     status.Base.String(),
		})
	}

	response := LogLevelStatusResponse{
		CurrentLevel:  globalCurrent.String(),
		BaseLevel:     globalBase.String(),
		ActiveChanges: responseChanges,
		Parameters:    parameters,
	}

	ctx.JSON(http.StatusOK, response)
}

// HandleDeleteLogLevel handles DELETE requests to remove a temporary log level change
func HandleDeleteLogLevel(ctx *gin.Context) {
	changeID := ctx.Param("changeId")
	if changeID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Change ID is required",
		})
		return
	}

	manager := logging.GetLogLevelManager()

	// Check if the change exists
	found := false
	for _, change := range manager.GetActiveChanges() {
		if change.ChangeID == changeID {
			found = true
			break
		}
	}

	if !found {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Change ID not found",
		})
		return
	}

	manager.RemoveChange(changeID)

	log.WithFields(log.Fields{
		"change_id": changeID,
		"user":      ctx.GetString("User"),
	}).Info("Temporary log level change removed")

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Log level change removed successfully",
	})
}
