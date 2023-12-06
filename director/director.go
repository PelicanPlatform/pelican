package director

import (
	"net/http"
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

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	registryWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		registryWebAPI.GET("/servers", listServers)
	}
}
