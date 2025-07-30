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
	"github.com/pelicanplatform/pelican/web_ui"
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
		group.POST("/collections", web_ui.AuthHandler, handleCreateCollection)
		group.PATCH("/collections/:id", web_ui.AuthHandler, handleUpdateCollection)
		group.DELETE("/collections/:id", web_ui.AuthHandler, handleDeleteCollection)
		group.GET("/collections/:id", web_ui.AuthHandler, handleGetCollection)
		group.POST("/collections/:id/members", web_ui.AuthHandler, handleAddCollectionMembers)
		group.DELETE("/collections/:id/members", web_ui.AuthHandler, handleRemoveCollectionMembers)
		group.DELETE("/collections/:id/members/:encoded_object_url", web_ui.AuthHandler, handleRemoveCollectionMember)
		group.GET("/collections/:id/members", web_ui.AuthHandler, handleListCollectionMembers)
		group.GET("/collections/:id/metadata", web_ui.AuthHandler, handleGetCollectionMetadata)
		group.PUT("/collections/:id/metadata/:key", web_ui.AuthHandler, handlePutCollectionMetadata)
		group.DELETE("/collections/:id/metadata/:key", web_ui.AuthHandler, handleDeleteCollectionMetadata)
		group.GET("/collections/:id/acl", web_ui.AuthHandler, handleGetCollectionAcls)
		group.POST("/collections/:id/acl", web_ui.AuthHandler, handleGrantCollectionAcl)
		group.DELETE("/collections/:id/acl", web_ui.AuthHandler, handleRevokeCollectionAcl)
	}
	return nil
}
