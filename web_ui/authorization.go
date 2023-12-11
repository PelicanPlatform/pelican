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

package web_ui

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	"github.com/prometheus/common/route"
)

// Create a token for accessing Prometheus /metrics endpoint on
// the server itself
func createPromMetricToken() (string, error) {
	serverURL := param.Server_ExternalWebUrl.GetString()
	tokenExpireTime := param.Monitoring_TokenExpiresIn.GetDuration()

	tok, err := jwt.NewBuilder().
		Claim("scope", "monitoring.scrape").
		Issuer(serverURL).
		Audience([]string{serverURL}).
		Subject(serverURL).
		Expiration(time.Now().Add(tokenExpireTime)).
		Build()
	if err != nil {
		return "", err
	}

	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the director's private JWK")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// Handle the authorization of Prometheus /metrics endpoint by checking
// if a valid token is present with correct scope
func promMetricAuthHandler(ctx *gin.Context) {
	if strings.HasPrefix(ctx.Request.URL.Path, "/metrics") {
		authRequired := param.Monitoring_MetricAuthorization.GetBool()
		if !authRequired {
			ctx.Next()
			return
		}
		// Auth is granted if the request is from either
		// 1.director scraper 2.server (self) scraper 3.authenticated web user (via cookie)
		authOption := utils.AuthOption{
			Sources: []utils.TokenSource{utils.Header, utils.Cookie},
			Issuers: []utils.TokenIssuer{utils.Director, utils.Issuer},
			Scopes:  []string{"monitoring.scrape"}}

		valid := utils.CheckAnyAuth(ctx, authOption)
		if !valid {
			ctx.AbortWithStatusJSON(403, gin.H{"error": "Authentication required to access this endpoint."})
		}
		// Valid director/self request, pass to the next handler
		ctx.Next()
	}
	// We don't care about other routes for this handler
	ctx.Next()
}

// Handle the authorization of Prometheus query engine endpoint at `/api/v1.0/prometheus`
func promQueryEngineAuthHandler(av1 *route.Router) gin.HandlerFunc {
	return func(c *gin.Context) {
		authOption := utils.AuthOption{
			// Cookie for web user access and header for external service like Grafana to access
			Sources: []utils.TokenSource{utils.Cookie, utils.Header},
			Issuers: []utils.TokenIssuer{utils.Issuer},
			Scopes:  []string{"monitoring.query"}}

		exists := utils.CheckAnyAuth(c, authOption)
		if exists {
			av1.ServeHTTP(c.Writer, c.Request)
		} else {
			c.JSON(http.StatusForbidden, gin.H{"error": "Correct authorization required to access Prometheus query engine APIs"})
		}
	}
}
