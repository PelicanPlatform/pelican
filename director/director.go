/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

type (
	listServerRequest struct {
		ServerType string `form:"server_type"` // "cache" or "origin"
	}

	listServerResponse struct {
		Name      string     `json:"name"`
		AuthURL   string     `json:"authUrl"`
		URL       string     `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL    string     `json:"webUrl"` // This is server's Web interface and API
		Type      ServerType `json:"type"`
		Latitude  float64    `json:"latitude"`
		Longitude float64    `json:"longitude"`
	}

	statResponse struct {
		Message  string            `json:"message"`
		Metadata []*objectMetadata `json:"metadata"`
	}
)

func (req listServerRequest) ToInternalServerType() ServerType {
	if req.ServerType == "cache" {
		return CacheType
	}
	if req.ServerType == "origin" {
		return OriginType
	}
	return ""
}

func listServers(ctx *gin.Context) {
	queryParams := listServerRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	var servers []ServerAd
	if queryParams.ServerType != "" {
		if !strings.EqualFold(queryParams.ServerType, string(OriginType)) && !strings.EqualFold(queryParams.ServerType, string(CacheType)) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
			return
		}
		servers = ListServerAds([]ServerType{ServerType(queryParams.ToInternalServerType())})
	} else {
		servers = ListServerAds([]ServerType{OriginType, CacheType})

	}
	resList := make([]listServerResponse, 0)
	for _, server := range servers {
		res := listServerResponse{
			Name:      server.Name,
			AuthURL:   server.AuthURL.String(),
			URL:       server.URL.String(),
			WebURL:    server.WebURL.String(),
			Type:      server.Type,
			Latitude:  server.Latitude,
			Longitude: server.Longitude,
		}
		resList = append(resList, res)
	}
	ctx.JSON(http.StatusOK, resList)
}

func queryOrigins(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	path := path.Clean(pathParam)
	if path == "" || strings.HasSuffix(path, "/") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Path should not be empty or ended with slash '/'"})
		return
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta, msg, err := NewObjectStat().Query(path, cancelCtx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	res := statResponse{Message: msg, Metadata: meta}
	ctx.JSON(http.StatusOK, res)
}

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	directorWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		directorWebAPI.GET("/servers", listServers)
		directorWebAPI.GET("/servers/origins/stat/*path", queryOrigins)
	}
}
