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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/param"
	"golang.org/x/oauth2"
)

type (
	oauthLoginRequest struct {
		NextUrl string `form:"next_url,omitempty"`
	}

	oauthCallbackRequest struct {
		State   string `form:"state"`
		Code    string `form:"code"`
		NextUrl string `form:"next_url,omitempty"`
	}

	cilogonUserInfo struct {
		Email string `json:"email,omitempty"`
		Sub   string `json:"sub"`
		SubID string `json:"subject_id,omitempty"`
	}
)

const (
	oauthCallbackPath  = "/api/v1.0/auth/cilogon/callback"
	cilogonUserInfoUrl = "https://cilogon.org/oauth2/userinfo"
)

var ciLogonOAuthConfig atomic.Pointer[oauth2.Config]

// Generate a 16B random string and set ctx session key oauthstate as the random string
// return the random string with URL encoded nextUrl for CSRF token validation
func generateCSRFCookie(ctx *gin.Context, nextUrl string) (string, error) {
	session := sessions.Default(ctx)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	session.Set("oauthstate", state)
	err = session.Save()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", state, url.QueryEscape(nextUrl)), nil
}

// Handler to redirect user to the login page of OAuth2 provider (CILogon)
// You can pass an optional next_url as query param if you want the user
// to be redirected back to where they were before hitting the login when
// the user is successfully authenticated against CILogon
func handleOAuthLogin(ctx *gin.Context) {
	req := oauthLoginRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed to bind next url"})
	}

	// CSRF token is required, embed next URL to the state
	csrfState, err := generateCSRFCookie(ctx, req.NextUrl)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
		return
	}

	redirectUrl := ciLogonOAuthConfig.Load().AuthCodeURL(csrfState)

	ctx.Redirect(302, redirectUrl)
}

// Handle the callback request from CILogon when user is successfully authenticated
// Get user info from CILogon and issue our token for user to access web UI
func handleOAuthCallback(ctx *gin.Context) {
	session := sessions.Default(ctx)
	c := context.Background()
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

	// Format of state: <[16]byte>:<nextURL>
	parts := strings.SplitN(req.State, ":", 2)
	if len(parts) != 2 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Invalid OAuth callback: fail to split state param: ", ctx.Request.URL)})
		return
	}
	nextURL, err := url.QueryUnescape(parts[1])
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Invalid OAuth callback: fail to parse next_url: ", ctx.Request.URL)})
	}

	if parts[0] != csrfFromSession {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Invalid OAuth callback: CSRF token doesn't match: ", ctx.Request.URL)})
		return
	}

	// We only need this token to grab user id from cilogon
	// and we won't store it anywhere. We will later issue our own token
	// for user access
	token, err := ciLogonOAuthConfig.Load().Exchange(c, req.Code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error in exchanging code for token: ", ctx.Request.URL)})
		return
	}

	client := ciLogonOAuthConfig.Load().Client(c, token)
	data := url.Values{}
	data.Add("access_token", token.AccessToken)

	// Use access_token to get user info from CILogon
	resp, err := client.PostForm(cilogonUserInfoUrl, data)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error requesting user info from CILogon: ", err)})
		return
	}
	body, _ := io.ReadAll(resp.Body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error parsing user info from CILogon: ", err)})
		return
	}

	userInfo := cilogonUserInfo{}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error parsing user info from CILogon: ", err)})
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
	if nextURL != "" {
		redirectLocation = nextURL
	}

	// Issue our own JWT for web UI access
	setLoginCookie(ctx, userIdentifier)

	// Redirect user to where they were or root path
	ctx.Redirect(http.StatusTemporaryRedirect, redirectLocation)
}

// Configure OAuth2 client and register endpoints
func ConfigOAuthClientAPIs(engine *gin.Engine) error {
	if param.Server_OAuthClientID.GetString() == "" || param.Server_OAuthClientSecret.GetString() == "" {
		return errors.New("Fail to configure OAuth client: OAuth client ID or client secret is empty")
	}
	if param.Server_SessionSecret.GetString() == "" {
		return errors.New("Fail to configure OAuth client: Session secret is empty")
	}
	redirectUrlStr := param.Server_ExternalWebUrl.GetString()
	redirectUrl, err := url.Parse(redirectUrlStr)
	if err != nil {
		return err
	}
	redirectUrl.Path = oauthCallbackPath
	redirectHostname := param.Server_OAuthClientRedirectHostname.GetString()
	if redirectHostname != "" {
		_, _, err := net.SplitHostPort(redirectHostname)
		if err != nil {
			// Port not present
			redirectUrl.Host = fmt.Sprint(redirectHostname, ":", param.Server_WebPort.GetInt())
		} else {
			// Port present
			redirectUrl.Host = redirectHostname
		}
	}
	config := &oauth2.Config{
		RedirectURL:  redirectUrl.String(),
		ClientID:     param.Server_OAuthClientID.GetString(),
		ClientSecret: param.Server_OAuthClientSecret.GetString(),
		Scopes:       []string{"openid", "email"}, //openid scope is required by CILogon
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://cilogon.org/authorize",
			TokenURL: "https://cilogon.org/oauth2/token",
		},
	}
	ciLogonOAuthConfig.Store(config)

	store := cookie.NewStore([]byte(param.Server_SessionSecret.GetString()))
	sessionHandler := sessions.Sessions("pelican-session", store)

	ciLogonGroup := engine.Group("/api/v1.0/auth/cilogon", sessionHandler)
	{
		ciLogonGroup.GET("/login", handleOAuthLogin)
		ciLogonGroup.GET("/callback", handleOAuthCallback)
	}
	return nil
}
