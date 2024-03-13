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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func exportOpenIDConfig(c *gin.Context) {
	issuerURL, _ := url.Parse(param.Server_ExternalWebUrl.GetString())
	jwksUri, _ := url.JoinPath(issuerURL.String(), "/.well-known/issuer.jwks")
	jsonData := gin.H{
		"issuer":   issuerURL.String(),
		"jwks_uri": jwksUri,
	}

	c.JSON(http.StatusOK, jsonData)
}

func exportIssuerJWKS(c *gin.Context) {
	keys, _ := config.GetIssuerPublicJWKS()
	buf, _ := json.MarshalIndent(keys, "", " ")

	c.Data(http.StatusOK, "application/json; charset=utf-8", buf)
}

// The director periodically uploads/downloads files to/from all online
// origins for testing. It sends a request reporting the status of the test result to this endpoint,
// and we will update origin internal health status metric by what director returns.
func handleDirectorTestResponse(ctx *gin.Context) {
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

func RegisterOriginOpenIDAPI(router *gin.RouterGroup) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	router.GET("/openid-configuration", exportOpenIDConfig)
	router.GET("/issuer.jwks", exportIssuerJWKS)
	return nil
}

// Configure API endpoints for origin that are not tied to UI
func RegisterOriginAPI(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusWarning, "Initializing origin, unknown status for director")
	// start the timer for the director test report timeout
	LaunchPeriodicDirectorTimeout(ctx, egrp)

	group := router.Group("/api/v1.0/origin-api")
	group.POST("/directorTest", handleDirectorTestResponse)

	return nil
}
