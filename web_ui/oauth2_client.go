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
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	oauthLoginPath    = "/api/v1.0/auth/oauth/login"
	oauthCallbackPath = "/api/v1.0/auth/oauth/callback"
)

// Group source types
const (
	GroupSourceTypeOIDC     string = "oidc"
	GroupSourceTypeFile     string = "file"
	GroupSourceTypeInternal string = "internal"
	GroupSourceTypeGitHub   string = "github"
)

var (
	oauthConfig      *oauth2.Config
	oauthUserInfoUrl = "" // Value will be set at ConfigOAuthClientAPIs
)

// Parse the OAuth2 callback state into a key-val map. Error if keys are duplicated
// state is the url-decoded value of the query parameter "state" in the the OAuth2 callback request
func ParseOAuthState(state string) (metadata map[string]string, err error) {
	metadata = map[string]string{}
	if state == "" {
		return metadata, nil
	}

	stateBytes, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to base64 decode the OAuth state: %v", state)
	}
	state = string(stateBytes)

	keyvals := strings.Split(state, "&")
	metadata = map[string]string{}
	for _, kvStr := range keyvals {
		kvpair := strings.SplitN(kvStr, "=", 2)
		if len(kvpair) < 2 {
			continue
		}
		key := kvpair[0]
		val, err := url.QueryUnescape(kvpair[1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unescape the value for the key %s:%s", key, val)
		}
		if _, ok := metadata[key]; ok {
			return nil, fmt.Errorf("duplicated keys %s:%s", key, state)
		}
		metadata[key] = val
	}
	return
}

// Generate the state for the authentication request in OAuth2 code flow.
// The metadata are formatted similar to url query parameters:
//
// key1=val1&key2=val2
//
// where values are url-encoded. We then base64 encode the resulting string
// in order to ensure that over-zealous providers do not treat the final URL
// as a double-encoding attack or somesuch.
func GenerateOAuthState(metadata map[string]string) string {
	metaStr := ""
	for key, val := range metadata {
		metaStr += key + "=" + url.QueryEscape(val) + "&"
	}
	metaStr = strings.TrimSuffix(metaStr, "&")
	return base64.RawURLEncoding.EncodeToString([]byte(metaStr))
}

// Generate a 16B random string and set as the value of ctx session key "oauthstate"
// return a string for OAuth2 "state" query parameter including the random string and other
// metadata
func GenerateCSRFCookie(ctx *gin.Context, metadata map[string]string) (string, error) {
	session := sessions.Default(ctx)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	pkceStr := base64.URLEncoding.EncodeToString(b)
	session.Set("oauthstate", pkceStr)
	err = session.Save()
	if err != nil {
		return "", err
	}
	if _, ok := metadata["pkce"]; ok {
		return "", errors.New("key \"pkce\" is not allowed")
	}
	metadata["pkce"] = pkceStr
	metaStr := GenerateOAuthState(metadata)
	return metaStr, nil
}

// Handler to redirect user to the login page of OAuth2 provider
// You can pass an optional next_url as query param if you want the user
// to be redirected back to where they were before hitting the login when
// the user is successfully authenticated against the OAuth2 provider
func handleOAuthLogin(ctx *gin.Context) {
	req := server_structs.OAuthLoginRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to bind next url",
			})
	}

	// CSRF token is required, embed next URL to the state
	csrfState, err := GenerateCSRFCookie(ctx, map[string]string{"nextUrl": req.NextUrl})

	if err != nil {
		log.Errorf("Failed to generate CSRF token: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to generate CSRF token",
			})
		return
	}

	redirectUrl := oauthConfig.AuthCodeURL(csrfState)
	ctx.Redirect(http.StatusTemporaryRedirect, redirectUrl)
}

// Fetch GitHub organization memberships for the authenticated user
// Uses the OAuth access token to call GitHub's /user/orgs endpoint
func fetchGitHubOrganizations(accessToken string) ([]string, error) {
	client := config.GetClient()

	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/orgs", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GitHub orgs request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch GitHub organizations")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read GitHub orgs response")
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("GitHub orgs API returned status %d with body: %s", resp.StatusCode, string(body))
		return nil, errors.Errorf("GitHub orgs API returned status %d", resp.StatusCode)
	}

	var orgs []struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, errors.Wrap(err, "failed to parse GitHub orgs response")
	}

	groups := make([]string, 0, len(orgs))
	for _, org := range orgs {
		groups = append(groups, org.Login)
	}

	log.Debugf("Fetched %d GitHub organizations for user", len(groups))
	return groups, nil
}

// Given a user name, return the list of groups they belong to
func generateGroupInfo(user string) (groups []string, err error) {
	groupFile := param.Issuer_GroupFile.GetString()
	if groupFile == "" {
		return
	}
	groupBytes, err := os.ReadFile(groupFile)
	if err != nil {
		err = errors.Wrap(err, "failed to read Issuer.GroupFile for group information")
		return
	}
	var groupTable map[string][]string
	if err = json.Unmarshal(groupBytes, &groupTable); err != nil {
		err = errors.Wrapf(err, "failed to parse Issuer.GroupFile (%s) as JSON", groupFile)
		return
	}
	groups = groupTable[user]
	return
}

// Given the maps for the UserInfo and ID token JSON objects, generate
// user/group information according to the current policy.
// The accessToken parameter is optional and only used when GroupSource is "github"
func generateUserGroupInfo(userInfo map[string]interface{}, idToken map[string]interface{}, accessToken string) (userRecord *database.User, groups []string, err error) {
	claimsSource := maps.Clone(userInfo)
	if param.Issuer_OIDCPreferClaimsFromIDToken.GetBool() {
		maps.Copy(claimsSource, idToken)
	}
	userClaim := param.Issuer_OIDCAuthenticationUserClaim.GetString()
	if userClaim == "" {
		userClaim = "sub"
	}

	var displayName string
	// If the configured claim is "sub" (default), try to find a more human-readable username from standard claims
	// This addresses Issue #3044 where users get non-sensical usernames like "http://cilogon.org/..."
	if userClaim == "sub" {
		usernameCandidates := []string{"preferred_username", "name", "nickname", "email"}
		for _, candidate := range usernameCandidates {
			if val, ok := claimsSource[candidate]; ok {
				if strVal, ok := val.(string); ok && strVal != "" {
					displayName = strVal
					log.Debugf("Found human-readable username from claim '%s': %s", candidate, displayName)
					break
				}
			}
		}
	}

	// Fallback: If no human-readable name found, or if configured claim is not "sub", use the configured claim
	if displayName == "" {
		if val, ok := claimsSource[userClaim]; ok {
			if strVal, ok := val.(string); ok {
				displayName = strVal
			} else {
				log.Errorln("User info endpoint did not return a string for the user claim", userClaim)
				err = errors.New("identity provider did not return an identity for logged-in user")
				return
			}
		} else {
			log.Errorln("User info endpoint did not return a value for the user claim", userClaim)
			err = errors.New("identity provider did not return an identity for logged-in user")
			return
		}
	}
	if param.Issuer_UserStripDomain.GetBool() {
		lastAt := strings.LastIndex(displayName, "@")
		if lastAt >= 0 {
			displayName = displayName[:strings.LastIndex(displayName, "@")]
		}
	}
	if displayName == "" {
		log.Errorf("'%s' field of user info response from auth provider is empty. Can't determine user identity", userClaim)
		err = errors.New("identity provider returned an empty username")
		return
	}
	username := displayName

	// Get the subject (sub) claim - this uniquely identifies the user at the identity provider
	// For OIDC, this is the standard "sub" claim. For OAuth2 providers like GitHub, we may need
	// to use a different claim (e.g., "id" for GitHub)
	subClaim := param.Issuer_OIDCSubjectClaim.GetString()
	if subClaim == "" {
		subClaim = "sub"
	}

	subIface, ok := claimsSource[subClaim]
	var sub string
	if !ok {
		// If the sub claim is not found, log a warning and fall back to the username
		// This allows OAuth2 providers that don't provide a sub claim to still work
		log.Warnf("User info endpoint did not return a value for the subject claim '%s', falling back to username '%s'", subClaim, username)
		sub = username
	} else {
		// Try to convert the sub claim to a string
		if subStr, ok := subIface.(string); ok {
			sub = subStr
		} else if subNum, ok := subIface.(float64); ok {
			// Some providers (like GitHub) return a numeric ID
			// Convert to int64 first to avoid floating-point precision issues
			if subNum >= 0 && subNum <= float64(^uint64(0)>>1) && subNum == float64(int64(subNum)) {
				sub = fmt.Sprintf("%d", int64(subNum))
			} else {
				log.Errorf("User info endpoint returned an out-of-range numeric value for the subject claim '%s': %v", subClaim, subNum)
				err = errors.New("identity provider returned an invalid numeric subject for logged-in user")
				return
			}
		} else {
			log.Errorf("User info endpoint returned a non-string/non-numeric value for the subject claim '%s'", subClaim)
			err = errors.New("identity provider did not return a valid subject for logged-in user")
			return
		}
	}

	// Get the issuer claim - this identifies the authentication provider
	// For OIDC, this is the standard "iss" claim. For OAuth2 providers like GitHub,
	// we may need to fall back to a configured value or the OIDC.Issuer setting
	issuerClaimName := param.Issuer_OIDCIssuerClaim.GetString()
	if issuerClaimName == "" {
		issuerClaimName = "iss"
	}

	issuerClaimValueIface, ok := claimsSource[issuerClaimName]
	var issuerClaimValue string
	if !ok {
		// If the issuer claim is not found in the user info, fall back to OIDC.Issuer or authorization endpoint
		log.Warnf("User info endpoint did not return a value for the issuer claim '%s'", issuerClaimName)

		// Try to get from OIDC.Issuer configuration
		if param.OIDC_Issuer.IsSet() {
			issuerClaimValue = param.OIDC_Issuer.GetString()
			log.Debugf("Using OIDC.Issuer as issuer: %s", issuerClaimValue)
		} else if param.OIDC_AuthorizationEndpoint.IsSet() {
			// Fall back to using the authorization endpoint hostname as the issuer
			authEndpoint := param.OIDC_AuthorizationEndpoint.GetString()
			parsedURL, parseErr := url.Parse(authEndpoint)
			if parseErr == nil {
				// Construct the issuer URL from scheme and host
				issuerURL := &url.URL{
					Scheme: parsedURL.Scheme,
					Host:   parsedURL.Host,
				}
				issuerClaimValue = issuerURL.String()
				log.Debugf("Using authorization endpoint host as issuer: %s", issuerClaimValue)
			} else {
				log.Errorf("Failed to parse authorization endpoint to determine issuer")
				err = errors.New("identity provider did not return an issuer and unable to determine one from configuration")
				return
			}
		} else {
			log.Errorf("Unable to determine issuer: no '%s' claim in user info and OIDC.Issuer is not set", issuerClaimName)
			err = errors.New("identity provider did not return an issuer claim value")
			return
		}
	} else {
		var ok bool
		issuerClaimValue, ok = issuerClaimValueIface.(string)
		if !ok {
			log.Errorf("'%s' field of user info response from auth provider is not a string", issuerClaimName)
			err = errors.New("identity provider returned an invalid issuer claim value")
			return
		}
	}

	// now that we have verified that the user belongs to a group we should create the user if it doesn't exist
	userRecord, err = database.GetOrCreateUser(database.ServerDatabase, username, sub, issuerClaimValue)
	if err != nil {
		return nil, nil, err
	}

	groupSource := strings.ToLower(param.Issuer_GroupSource.GetString())
	switch groupSource {
	case GroupSourceTypeOIDC:
		groupClaim := param.Issuer_OIDCGroupClaim.GetString()
		groupList, ok := claimsSource[groupClaim]
		if ok {
			if groupsStr, ok := groupList.(string); ok {
				groupsInfo := strings.Split(groupsStr, ",")
				groups = make([]string, 0, len(groupsInfo))
				for _, groupRaw := range groupsInfo {
					group := strings.TrimSpace(groupRaw)
					if group != "" {
						groups = append(groups, group)
					}
				}
			} else if groupsTmp, ok := groupList.([]interface{}); ok {
				groups = make([]string, 0, len(groupsTmp))
				for _, groupObj := range groupsTmp {
					if groupStr, ok := groupObj.(string); ok {
						groups = append(groups, groupStr)
					}
				}
			}
		}
	case GroupSourceTypeFile:
		groups, err = generateGroupInfo(username)
		if err != nil {
			return nil, nil, err
		}
	case GroupSourceTypeInternal:
		log.Debugf("Getting groups for user %s (ID: %s)", username, userRecord.ID)
		groupList, err := database.GetMemberGroups(database.ServerDatabase, userRecord.ID)
		if err != nil {
			return nil, nil, err
		}
		groups = make([]string, 0, len(groupList))
		for _, group := range groupList {
			groups = append(groups, group.Name)
		}
	case GroupSourceTypeGitHub:
		if accessToken == "" {
			log.Errorf("GitHub group source requires an access token")
			err = errors.New("GitHub group source requires an access token")
			return nil, nil, err
		}
		groups, err = fetchGitHubOrganizations(accessToken)
		if err != nil {
			log.Errorf("Failed to fetch GitHub organizations: %v", err)
			return nil, nil, errors.Wrap(err, "failed to fetch GitHub organizations")
		}
	case "", "none":
		log.Debugf("No group source specified; no groups will be used")
		return
	default:
		err = errors.Errorf("invalid group source: %s", groupSource)
		return nil, nil, err
	}

	log.Debugf("Groups for user %s (source=%s): %v", username, groupSource, groups)
	return userRecord, groups, nil
}

// Handle the callback request when the user is successfully authenticated.
// Get the user's info and issue our token for accessing the web UI.
func handleOAuthCallback(ctx *gin.Context) {
	session := sessions.Default(ctx)
	c := context.Background()
	csrfFromSession := session.Get("oauthstate")
	if csrfFromSession == nil {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid OAuth callback: CSRF token from cookie is missing",
			})
		return
	}

	req := server_structs.OAuthCallbackRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: fail to bind CSRF token from state query: ", ctx.Request.URL),
			})
		return
	}

	stateMap, err := ParseOAuthState(req.State)
	if err != nil {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: failed to parse state metadata", ctx.Request.URL),
			})
		return
	}
	pkce, ok := stateMap["pkce"]
	if !ok {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: pkce is missing from the callback state", ctx.Request.URL),
			})
		return
	}

	nextURL := stateMap["nextUrl"]

	if pkce != csrfFromSession {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: CSRF token doesn't match: ", ctx.Request.URL),
			})
		return
	}

	// We need this token only to get the user's info.
	// We will later issue our own token for user access.
	token, err := oauthConfig.Exchange(c, req.Code)
	if err != nil {
		log.Errorf("Error in exchanging code for token:  %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error in exchanging code for token: ", ctx.Request.URL),
			})
		return
	}

	var idToken = make(map[string]interface{})
	if idTokenRaw := token.Extra("id_token"); idTokenRaw != nil {
		// Check if the id_token is a non-empty string before parsing
		// Some OAuth2 providers (e.g., GitHub) don't provide an ID token
		idTokenStr, ok := idTokenRaw.(string)
		if !ok || idTokenStr == "" {
			log.Debugf("ID token is not a valid string or is empty")
		} else {
			log.Debugln("ID token from auth provider:", idTokenStr)

			// We were given this ID token by the authentication provider, not
			// some third party. If we don't trust the provider, we have greater
			// issues.
			skew, _ := time.ParseDuration("6s")
			idTokenJWT, err := jwt.ParseString(idTokenStr, jwt.WithVerify(false), jwt.WithAcceptableSkew(skew))
			if err != nil {
				log.Errorf("Error parsing OIDC ID token: %v", err)
				ctx.JSON(http.StatusInternalServerError,
					server_structs.SimpleApiResp{
						Status: server_structs.RespFailed,
						Msg:    fmt.Sprint("Error parsing OIDC ID token: ", ctx.Request.URL),
					})
				return
			}

			idToken, err = idTokenJWT.AsMap(ctx)
			if err != nil {
				log.Errorf("Error converting OIDC ID token to a map: %v", err)
				ctx.JSON(http.StatusInternalServerError,
					server_structs.SimpleApiResp{
						Status: server_structs.RespFailed,
						Msg:    fmt.Sprint("Error converting OIDC ID token to a map: ", ctx.Request.URL),
					})
				return
			}
		}
	} else {
		log.Debugf("Did not find an OIDC ID token")
	}

	client := oauthConfig.Client(c, token)
	client.Transport = config.GetTransport()

	userInfoReq, err := http.NewRequest(http.MethodGet, oauthUserInfoUrl, nil)
	if err != nil {
		log.Errorf("Error creating a new request for user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error requesting user info from auth provider: ", err),
			})
		return
	}
	userInfoReq.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)

	resp, err := client.Do(userInfoReq)
	if err != nil {
		log.Errorf("Error requesting user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error requesting user info from auth provider: ", err),
			})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error getting user info response from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Failed to get OAuth2 user info response: ", err),
			})
		return
	}

	if resp.StatusCode != 200 {
		log.Errorf("Error requesting user info from auth provider at %s with status code %d and body %s", oauthUserInfoUrl, resp.StatusCode, string(body))
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error requesting user info from auth provider with status code ", resp.StatusCode),
			})
		return
	}
	log.Debugf("User info from auth provider: %v", string(body))

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		log.Errorf("Error parsing user info from auth provider at %s. %v", oauthUserInfoUrl, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error parsing user info from auth provider: ", err),
			})
		return
	}

	userRecord, groups, err := generateUserGroupInfo(userInfo, idToken, token.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
		return
	}

	redirectLocation := "/"
	if nextURL != "" {
		redirectLocation = nextURL
	}

	// Issue our own JWT for web UI access
	setLoginCookie(ctx, userRecord, groups)

	// Redirect user to where they were or root path
	ctx.Redirect(http.StatusTemporaryRedirect, redirectLocation)
}

// Configure OAuth2 client and register related authentication endpoints for Web UI
func ConfigOAuthClientAPIs(engine *gin.Engine) error {
	oauthCommonConfig, provider, err := pelican_oauth2.ServerOIDCClient()
	if err != nil {
		return errors.Wrap(err, "failed to load server OIDC client config")
	}
	// Pelican registry relies on OAuth2 device flow for CLI-based registration
	// and Globus does not support such flow. So users should not use Globus for the registry
	if config.IsServerEnabled(server_structs.RegistryType) && provider == config.Globus {
		return errors.New("you are using Globus as the OIDC auth server. However, Pelican registry server does not support Globus. Please use CILogon as the auth server instead.")
	}

	oauthUserInfoUrl = oauthCommonConfig.Endpoint.UserInfoURL

	ocfg, err := pelican_oauth2.ParsePelicanOAuth(oauthCommonConfig, oauthCallbackPath)
	if err != nil {
		return err
	}
	oauthConfig = &ocfg

	seHandler, err := GetSessionHandler()
	if err != nil {
		return err
	}

	oauthGroup := engine.Group("/api/v1.0/auth/oauth", seHandler, ServerHeaderMiddleware)
	{
		oauthGroup.GET("/login", handleOAuthLogin)
		oauthGroup.GET("/callback", handleOAuthCallback)
	}
	return nil
}
