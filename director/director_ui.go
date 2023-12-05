package director

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type listServerRequest struct {
	ServerType string `form:"server_type,omitempty"` // "cache" or "origin"
}

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

	if queryParams.ServerType != "" {
		if !strings.EqualFold(queryParams.ServerType, string(OriginType)) && !strings.EqualFold(queryParams.ServerType, string(CacheType)) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
			return
		}
		servers := ListServerAds([]ServerType{ServerType(queryParams.ToInternalServerType())})
		ctx.JSON(http.StatusOK, servers)
	} else {
		servers := ListServerAds([]ServerType{OriginType, CacheType})
		ctx.JSON(http.StatusOK, servers)
	}
}

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	registryWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		registryWebAPI.GET("/servers", listServers)
	}
}
