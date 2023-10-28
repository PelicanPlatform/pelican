package director

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
)

type DiscoveryResponse struct {
	JwksUri string `json:"jwks_uri"`
}

// Returns links related to director's authentication, including the link
// to get the public key from the director
func discoveryHandler(ctx *gin.Context) {
	directorUrl := param.Federation_DirectorUrl.GetString()
	if len(directorUrl) == 0 {
		ctx.JSON(500, gin.H{"error": "Bad server configuration: Director URL is not set"})
		return
	}
	rs := DiscoveryResponse{
		JwksUri: directorUrl + "/.well-known/public-signing-key.jwks",
	}
	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to marshal director's discovery response"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", "attachment; filename=pelican-director-configuration.json")
	ctx.Data(200, "application/json", jsonData)
}

// Returns director's public key
func jwksHandler(ctx *gin.Context) {
	issuerKeyfile := param.IssuerKey.GetString()
	key, err := config.LoadPublicKey("", issuerKeyfile)
	if err != nil {
		log.Errorf("Failed to load director's public key: %v", err)
		ctx.JSON(500, gin.H{"error": "Failed to load director's public key"})
	} else {
		jsonData, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			ctx.JSON(500, gin.H{"error": "Failed to marshal director's public key"})
			return
		}
		// Append a new line to the JSON data
		jsonData = append(jsonData, '\n')
		ctx.Header("Content-Disposition", "attachment; filename=public-signing-key.jwks")
		ctx.Data(200, "application/json", jsonData)
	}
}

func RegisterDirectorAuth(router *gin.RouterGroup) {
	router.GET("/.well-known/pelican-configuration", discoveryHandler)
	router.GET("/.well-known/public-signing-key.jwks", jwksHandler)
}
