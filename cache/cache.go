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

package cache

import (
	"context"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	notificationChan = make(chan bool)
)

func RegisterCacheAPI(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) {
	// start the timer for the director test report timeout
	server_utils.LaunchPeriodicDirectorTimeout(ctx, egrp, notificationChan)

	group := router.Group("/api/v1.0/cache")
	{
		group.POST("/directorTest", func(ginCtx *gin.Context) { server_utils.HandleDirectorTestResponse(ginCtx, notificationChan) })
	}
}
