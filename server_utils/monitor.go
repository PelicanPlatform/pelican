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

package server_utils

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	// Duration to wait before timeout
	directorTimeoutDuration = 30 * time.Second
)

// Notify the periodic ticker for director-based health test timeout that we have received a new response and it
// should reset
func notifyNewDirectorResponse(ctx context.Context, nChan chan bool) {
	select {
	case <-ctx.Done():
		return
	case nChan <- true:
		return
	}
}

// Launch a go routine in errorgroup to report timeout if director-based health test
// response was not sent within the defined time limit
func LaunchPeriodicDirectorTimeout(ctx context.Context, egrp *errgroup.Group, nChan chan bool) {
	directorTimeoutTicker := time.NewTicker(directorTimeoutDuration)

	egrp.Go(func() error {
		for {
			select {
			case <-directorTimeoutTicker.C:
				// If origin can't contact the director, record the error without warning
				status, err := metrics.GetComponentStatus(metrics.OriginCache_Federation)
				if err == nil && status == "critical" {
					metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, "Failed to advertise to the director. Tests are not expected")
				} else {
					// Timer fired because no message was received in time.
					log.Warningln("No director test report received within the time limit")
					metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, "No director test report received within the time limit")
				}
			case <-nChan:
				log.Debugln("Received director report of health test result")
				directorTimeoutTicker.Reset(directorTimeoutDuration)
			case <-ctx.Done():
				log.Infoln("Director health test timeout loop has been terminated")
				return nil
			}
		}
	})
}

// The director periodically uploads/downloads files to/from all online
// origins for testing. It sends a request reporting the status of the test result to this endpoint,
// and we will update origin internal health status metric by what director returns.
func HandleDirectorTestResponse(ctx *gin.Context, nChan chan bool) {
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.FederationIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorTestReport},
	})
	if !ok || err != nil {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Failed to verify the token: ", err),
		})
		return
	}

	dt := server_structs.DirectorTestResult{}
	if err := ctx.ShouldBind(&dt); err != nil {
		log.Errorf("Invalid director test response: %v", err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid director test response: " + err.Error(),
		})
		return
	}
	// We will let the timer go timeout if director didn't send a valid json request
	notifyNewDirectorResponse(ctx, nChan)
	if dt.Status == "ok" {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusOK, fmt.Sprintf("Director timestamp: %v", dt.Timestamp))
		ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "Success",
		})
	} else if dt.Status == "error" {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, dt.Message)
		ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "Success",
		})
	} else {
		log.Errorf("Invalid director test response, status: %s", dt.Status)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid director test response status: %s", dt.Status),
		})
	}
}
