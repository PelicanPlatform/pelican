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
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	notificationChan = make(chan bool)
)

// Configure API endpoints for origin that are not tied to UI
func RegisterOriginAPI(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusWarning, "Initializing the server, unknown status from the director file transfer test")
	// start the timer for the director test report timeout
	server_utils.LaunchPeriodicDirectorTimeout(ctx, egrp, notificationChan)

	deprecatedGroup := router.Group("/api/v1.0/origin-api")
	{
		deprecatedGroup.POST("/directorTest", func(ctx *gin.Context) { server_utils.HandleDirectorTestResponse(ctx, notificationChan) })
	}

	group := router.Group("/api/v1.0/origin")
	{
		group.POST("/directorTest", func(ctx *gin.Context) { server_utils.HandleDirectorTestResponse(ctx, notificationChan) })
	}
	return nil
}
