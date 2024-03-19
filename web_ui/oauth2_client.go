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

package web_ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type (
	oauthLoginRequest struct {
		NextUrl string `form:"next_url,omitempty"`
	}

	oauthCallbackRequest struct {
		State string `form:"state"`
		Code  string `form:"code"`
	}

	cilogonUserInfo struct {
		Email string `json:"email,omitempty"`
		Sub   string `json:"sub"`
		SubID string `json:"subject_id,omitempty"`
	}
)

const (
	oauthCallbackPath = "/api/v1.0/auth/oauth/callback"
)

var (
	oauthConfig      *oauth2.Config
	oauthUserInfoUrl = "" // Value will be set at ConfigOAuthClientAPIs
)

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

// Handler to redirect user to the login page of OAuth2 provider
// You can pass an optional next_url as query param if you want the user
// to be redirected back to where they were before hitting the login when
// the user is successfully authenticated against the OAuth2 provider
func handleOAuthLogin(ctx *gin.Context) {
	req := oauthLoginRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed to bind next url"})
	}

	// CSRF token is required, embed next URL to the state
	csrfState, err := generateCSRFCookie(ctx, req.NextUrl)

	if err != nil {
		log.Errorf("Failed to generate CSRF token: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
		return
	}

	redirectUrl := oauthConfig.AuthCodeURL(csrfState)
	ctx.Redirect(http.StatusTemporaryRedirect, redirectUrl)
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
	token, err := oauthConfig.Exchange(c, req.Code)
	if err != nil {
		log.Errorf("Error in exchanging code for token:  %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error in exchanging code for token: ", ctx.Request.URL)})
		return
	}

	client := oauthConfig.Client(c, token)
	client.Transport = config.GetTransport()
	// CILogon requires token to be set as part of post form
	data := url.Values{}
	data.Add("access_token", token.AccessToken)

	// Use access_token to get user info from CILogon
	userInfoReq, err := http.NewRequest("POST", oauthUserInfoUrl, strings.NewReader(data.Encode()))
	if err != nil {
		log.Errorf("Error creating a new request for user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error  creating a new request for user info from auth provider: ", err)})
		return
	}
	userInfoReq.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	userInfoReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(userInfoReq)
	if err != nil {
		log.Errorf("Error requesting user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error requesting user info from auth provider: ", err)})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error getting user info response from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error getting user info response from auth provider: ", err)})
		return
	}

	if resp.StatusCode != 200 {
		log.Errorf("Error requesting user info from auth provider at %s with status code %d and body %s", oauthUserInfoUrl, resp.StatusCode, string(body))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error requesting user info from auth provider with status code ", resp.StatusCode)})
		return
	}

	userInfo := cilogonUserInfo{}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		log.Errorf("Error parsing user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error parsing user info from auth provider: ", err)})
		return
	}

	userIdentifier := userInfo.Sub
	if userIdentifier == "" {
		log.Errorf("sub field of user info response from auth provider is empty. Can't determine user identity")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error setting login cookie: can't find valid user id from auth provider"})
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

// Configure OAuth2 client and register related authentication endpoints for Web UI
func ConfigOAuthClientAPIs(engine *gin.Engine) error {
	sessionSecretByte, err := config.LoadSessionSecret()
	if err != nil {
		return errors.Wrap(err, "Failed to configure OAuth client")
	}
	oauthCommonConfig, provider, err := pelican_oauth2.ServerOIDCClient()
	if err != nil {
		return errors.Wrap(err, "Failed to load server OIDC client config")
	}
	// Pelican registry relies on OAuth2 device flow for CLI-based registration
	// and Globus does not support such flow. So users should not use Globus for the registry
	if config.IsServerEnabled(config.RegistryType) && provider == pelican_oauth2.Globus {
		return errors.New("You are using Globus as the OIDC auth server. However, Pelican registry server does not support Globus. Please use CILogon as the auth server instead.")
	}

	oauthUserInfoUrl = oauthCommonConfig.Endpoint.UserInfoURL

	redirectUrlStr := param.Server_ExternalWebUrl.GetString()
	redirectUrl, err := url.Parse(redirectUrlStr)
	if err != nil {
		return err
	}
	redirectUrl.Path = oauthCallbackPath
	redirectHostname := param.OIDC_ClientRedirectHostname.GetString()
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
	oauthConfig = &oauth2.Config{
		RedirectURL:  redirectUrl.String(),
		ClientID:     oauthCommonConfig.ClientID,
		ClientSecret: oauthCommonConfig.ClientSecret,
		Scopes:       oauthCommonConfig.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauthCommonConfig.Endpoint.AuthURL,
			TokenURL: oauthCommonConfig.Endpoint.TokenURL,
		},
	}

	store := cookie.NewStore(sessionSecretByte)
	sessionHandler := sessions.Sessions("pelican-session", store)

	oauthGroup := engine.Group("/api/v1.0/auth/oauth", sessionHandler)
	{
		oauthGroup.GET("/login", handleOAuthLogin)
		oauthGroup.GET("/callback", handleOAuthCallback)
	}
	return nil
}
