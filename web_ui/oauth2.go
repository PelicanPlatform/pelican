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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
	"golang.org/x/oauth2"
)

type oauthLoginRequest struct {
	NextUrl string `form:"next_url,omitempty"`
}

type oauthCallbackRequest struct {
	State   string `form:"state"`
	Code    string `form:"code"`
	NextUrl string `form:"next_url,omitempty"`
}

type cilogonUserInfo struct {
	Email string `json:"email,omitempty"`
	Sub   string `json:"sub"`
	SubID string `json:"subject_id,omitempty"`
}

const (
	oauthCallbackPath  = "/api/v1.0/auth/callback"
	cilogonUserInfoUrl = "https://cilogon.org/oauth2/userinfo"
)

var (
	// TODO: change to ComputeExternalAddress to param.ExternalWebUrl when #378 is merged
	callbackUrl     = url.URL{Host: config.ComputeExternalAddress(), Scheme: "https", Path: oauthCallbackPath}
	ciLogonEndpoint = oauth2.Endpoint{
		AuthURL:  "https://cilogon.org/authorize",
		TokenURL: "https://cilogon.org/oauth2/token",
	}
	ciLogonOAuthConfig = &oauth2.Config{
		RedirectURL:  callbackUrl.String(),
		ClientID:     param.Server_OAuthClientID.GetString(),
		ClientSecret: param.Server_OAuthClientSecret.GetString(),
		Endpoint:     ciLogonEndpoint,
		Scopes:       []string{"email"},
	}
)

func generateCSRFCookie(ctx *gin.Context) string {
	session := sessions.Default(ctx)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	session.Set("oauthstate", state)
	session.Save()

	return state
}

func handleOAuthLogin(ctx *gin.Context) {
	req := oauthLoginRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed to bind next url"})
	}

	// CSRF token is required
	csrfState := generateCSRFCookie(ctx)

	// Carry the Url that will redirect to when auth is successful
	authOption := oauth2.SetAuthURLParam("next_url", req.NextUrl)
	redirectUrl := ciLogonOAuthConfig.AuthCodeURL(csrfState, authOption)

	ctx.Redirect(302, redirectUrl)
}

func handleOAuthCallback(ctx *gin.Context) {
	session := sessions.Default(ctx)
	csrfFromSession := session.Get("oauthstate")
	if csrfFromSession == nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OAuth callback: CSRF token from cookie is missing"})
		return
	}

	req := oauthCallbackRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Invalid OAuth callback: fail to bind CSRF token from state query: ", ctx.Request.URL)})
		return
	}

	if req.State != csrfFromSession {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Invalid OAuth callback: CSRF token doesn't match", ctx.Request.URL)})
		return
	}

	// We only need this token to grab user id from cilogon
	// and we won't store it anywhere. We will later issue our own token
	// for user access
	token, err := ciLogonOAuthConfig.Exchange(context.Background(), req.Code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error in exchanging code for token", ctx.Request.URL)})
		return
	}

	resp, err := utils.MakeRequest(cilogonUserInfoUrl, "POST", map[string]interface{}{
		"access_token": token.AccessToken,
	}, nil)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error requesting user info from CILogon", ctx.Request.URL)})
		return
	}

	userInfo := cilogonUserInfo{}

	if err := json.Unmarshal(resp, &userInfo); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error parsing user info from CILogon", ctx.Request.URL)})
		return
	}

	userIdentifier := ""
	if userInfo.Email != "" {
		userIdentifier = userInfo.Email
	} else if userInfo.SubID != "" {
		userIdentifier = userInfo.SubID
	} else {
		userIdentifier = userInfo.Sub
	}
	if userIdentifier == "" {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error setting login cookie: can't find valid user id from CILogon"})
		return
	}

	redirectLocation := "/"
	if req.NextUrl != "" {
		redirectLocation = req.NextUrl
	}

	setLoginCookie(ctx, userIdentifier)
	ctx.Redirect(http.StatusTemporaryRedirect, redirectLocation)
}

func ConfigOAuthClientAPIs(engine *gin.Engine) {
	store := cookie.NewStore([]byte(param.Server_SessionSecret.GetString()))
	authGroup := gin.New().Group("/api/v1.0/auth")
	sessionHandler := sessions.Sessions("pelican-session", store)
	authGroup.GET("/cilogon/login", sessionHandler, handleOAuthLogin)
	authGroup.GET("/cilogon/callback", sessionHandler, handleOAuthCallback)
}
