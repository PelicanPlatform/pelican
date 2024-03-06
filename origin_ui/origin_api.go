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

package origin_ui

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	// Duration to wait before timeout
	directorTimeoutDuration = 30 * time.Second

	notifyResponseOnce sync.Once
	notifyChannel      chan bool
)

// Notify the periodic ticker that we have received a new response and it
// should reset
func notifyNewDirectorResponse(ctx context.Context) {
	nChan := getNotifyChannel()
	select {
	case <-ctx.Done():
		return
	case nChan <- true:
		return
	}
}

// Get the notification channel in a thread-safe manner
func getNotifyChannel() chan bool {
	notifyResponseOnce.Do(func() {
		notifyChannel = make(chan bool)
	})
	return notifyChannel
}

// Reset the timer safely
func LaunchPeriodicDirectorTimeout(ctx context.Context, egrp *errgroup.Group) {
	directorTimeoutTicker := time.NewTicker(directorTimeoutDuration)
	nChan := getNotifyChannel()

	egrp.Go(func() error {
		for {
			select {
			case <-directorTimeoutTicker.C:
				// Timer fired because no message was received in time.
				log.Warningln("No director test report received within the time limit")
				metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, "No director test report received within the time limit")
			case <-nChan:
				log.Debugln("Got notification from director")
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
func directorTestResponse(ctx *gin.Context) {
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.FederationIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorTestReport},
	})
	if !ok {
		ctx.JSON(status, gin.H{"error": err.Error()})
	}

	dt := common.DirectorTestResult{}
	if err := ctx.ShouldBind(&dt); err != nil {
		log.Errorf("Invalid director test response: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid director test response: " + err.Error()})
		return
	}
	// We will let the timer go timeout if director didn't send a valid json request
	notifyNewDirectorResponse(ctx)
	if dt.Status == "ok" {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusOK, fmt.Sprintf("Director timestamp: %v", dt.Timestamp))
		ctx.JSON(http.StatusOK, gin.H{"msg": "Success"})
	} else if dt.Status == "error" {
		metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, dt.Message)
		ctx.JSON(http.StatusOK, gin.H{"msg": "Success"})
	} else {
		log.Errorf("Invalid director test response, status: %s", dt.Status)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid director test response status: %s", dt.Status)})
	}
}

// Configure API endpoints for origin that are not tied to UI
func ConfigureOriginAPI(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusWarning, "Initializing origin, unknown status for director")
	// start the timer for the director test report timeout
	LaunchPeriodicDirectorTimeout(ctx, egrp)

	group := router.Group("/api/v1.0/origin-api")
	group.POST("/directorTest", directorTestResponse)

	return nil
}
