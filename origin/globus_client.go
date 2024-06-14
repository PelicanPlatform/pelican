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
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/config"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/web_ui"
)

// https://docs.globus.org/api/transfer/endpoints_and_collections/#endpoint_or_collection_fields
type globusEndpointRes struct {
	HttpsServer string `json:"https_server"`
	DisplayName string `json:"display_name"`
}

type globusAuthCallbackRes struct {
	NextUrl string `json:"nextUrl"`
}

var (
	onceGlobusOAuthCfg sync.Once
	// A global Globus OAuth2 config. Do not directly access this value. Use GetGlobusOAuthCfg() instead
	globusOAuthCfg      *oauth2.Config
	globusOAuthCfgError error
)

const (
	globusIssuerEndpoint          = "https://auth.globus.org/" // Globus issuer endpoint
	globusTransferServer          = "transfer.api.globus.org"  // The resource name for the Globus transfer API server
	globusTransferEndpointBaseUrl = "https://transfer.api.globus.org/v0.10/endpoint/"
	globusTransferBaseScope       = "urn:globus:auth:scope:transfer.api.globus.org:all"
)

const (
	// We render the frontend and call the API from there for better user experience
	globusCallbackPath = "/view/origin/globus/callback"
)

// Setup the OAuth2 config for Globus backend
func setupGlobusOAuthCfg() {
	// First we try the server onboard OIDC issuer
	cfg, pvd, err := pelican_oauth2.ServerOIDCClient()
	if err == nil && pvd == config.Globus {
		parsedCfg, err := pelican_oauth2.ParsePelicanOAuth(cfg, globusCallbackPath)
		if err != nil {
			globusOAuthCfgError = err
			return
		}
		// Add Globus transfer scope as we need it for collection access
		parsedCfg.Scopes = append(parsedCfg.Scopes, globusTransferBaseScope)
		globusOAuthCfg = &parsedCfg
		return
	}

	// The server onboard OIDC issuer is not Globus
	// 1. Get Client ID and Secret
	clientIDPath := param.Origin_GlobusClientIDFile.GetString()
	contents, err := os.ReadFile(clientIDPath)
	if err != nil {
		globusOAuthCfgError = errors.Wrapf(err, "Failed reading Origin.GlobusClientIDFile %s", clientIDPath)
		return
	}
	clientID := strings.TrimSpace(string(contents))
	if clientID == "" {
		globusOAuthCfgError = errors.New("Origin.GlobusClientIDFile is empty")
		return
	}

	clientSecretPath := param.Origin_GlobusClientSecretFile.GetString()
	secretContent, err := os.ReadFile(clientSecretPath)
	if err != nil {
		globusOAuthCfgError = errors.Wrapf(err, "Failed reading Origin.GlobusClientSecretFile %s", clientSecretPath)
		return
	}
	clientSecret := strings.TrimSpace(string(secretContent))
	if clientSecret == "" {
		globusOAuthCfgError = errors.New("Origin.GlobusClientSecretFile is empty")
		return
	}

	// 2. Get Globus OAuth endpoints
	iss, err := config.GetIssuerMetadata(globusIssuerEndpoint)
	if err != nil {
		globusOAuthCfgError = err
		return
	}

	redirUrl, err := pelican_oauth2.GetRedirectURL(globusCallbackPath)
	if err != nil {
		globusOAuthCfgError = err
		return
	}

	clientCfg := oauth2.Config{
		RedirectURL:  redirUrl,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       append(iss.ScopesSupported, globusTransferBaseScope),
		Endpoint: oauth2.Endpoint{
			AuthURL:       iss.AuthURL,
			DeviceAuthURL: iss.DeviceAuthURL,
			TokenURL:      iss.TokenURL,
		},
	}

	globusOAuthCfg = &clientCfg
}

// Get a resource token from Globus token endpoint.
// Ref: https://docs.globus.org/api/auth/reference/#authorization_code_grant_preferred
func getGlobusResourceToken(token *oauth2.Token, name string) (globusTok *oauth2.Token, err error) {
	otok := token.Extra("other_tokens")
	if otok == nil {
		err = errors.New("other_tokens does not exist in the Globus token response")
		return
	}

	tokArr, ok := otok.([]interface{})
	if !ok {
		err = fmt.Errorf("other_tokens in Globus token response is not an array of interface: %T", otok)
		return
	}

	for _, tokInt := range tokArr {
		tok, ok := tokInt.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("Globus resource token is not a map with string keys and interface values: %T", tokInt)
			return
		}
		rs, ok := tok["resource_server"]
		if !ok {
			continue
		}
		rsStr, ok := rs.(string)
		if !ok {
			continue
		}
		if rsStr != name {
			continue
		} else {
			// This is the token we want!
			aTokRaw, ok := tok["access_token"]
			if !ok {
				err = fmt.Errorf("the requested resource %q does not have access_token", name)
				return
			}
			aTokStr, ok := aTokRaw.(string)
			if !ok {
				err = fmt.Errorf("the access_token of the requested resource %q is not a string: %T", name, aTokRaw)
				return
			}

			rTokRaw, ok := tok["refresh_token"]
			if !ok {
				err = fmt.Errorf("the requested resource %q does not have refresh_token", name)
				return
			}
			rTokStr, ok := rTokRaw.(string)
			if !ok {
				err = fmt.Errorf("the refresh_token of the requested resource %q is not a string: %T", name, rTokRaw)
				return
			}

			expireRaw, ok := tok["expires_in"]
			if !ok {
				err = fmt.Errorf("the requested resource %q does not have expires_in", name)
				return
			}
			expireInt, ok := expireRaw.(float64)
			if !ok {
				err = fmt.Errorf("the expires_in of the requested resource %q is not a float64 type: %T", name, expireRaw)
				return
			}

			tokTypeRaw, ok := tok["token_type"]
			if !ok {
				err = fmt.Errorf("the requested resource %q does not have token_type", name)
				return
			}
			tokTypeStr, ok := tokTypeRaw.(string)
			if !ok {
				err = fmt.Errorf("the token_type of the requested resource %q is not an string: %T", name, tokTypeRaw)
				return
			}
			tmpGTok := oauth2.Token{
				AccessToken:  aTokStr,
				RefreshToken: rTokStr,
				Expiry:       time.Now().Add(time.Duration(expireInt) * time.Second),
				TokenType:    tokTypeStr,
			}
			globusTok = &tmpGTok
			return
		}
	}
	return
}

func GetGlobusOAuthCfg() (client *oauth2.Config, err error) {
	onceGlobusOAuthCfg.Do(setupGlobusOAuthCfg)
	if globusOAuthCfgError != nil {
		err = errors.Wrap(globusOAuthCfgError, "failed to initialize Globus OAuth2 client")
		return
	}
	if globusOAuthCfg == nil {
		err = errors.New("failed to get Globus OAuth2 Client: client is nil")
		return
	}
	client = globusOAuthCfg
	return
}

// Handle Globus OAuth2 code flow callback
func handleGlobusCallback(ctx *gin.Context) {
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
				Msg:    fmt.Sprint("Invalid OAuth callback: fail to bind state: ", ctx.Request.URL),
			})
		return
	}

	stateMap, err := web_ui.ParseOAuthState(req.State)
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

	nextUrl := stateMap["nextUrl"]

	if pkce != csrfFromSession {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: CSRF token doesn't match: ", ctx.Request.URL),
			})
		return
	}

	cid, ok := stateMap["id"]
	if !ok {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Invalid OAuth callback: id is missing from the callback state: ", ctx.Request.URL),
			})
		return
	}
	// Make sure there's no path traversal here
	// We will eventually use the cid as the file name of the access token we persist on the disk
	// so we want to make sure this ID is not a path
	cid = path.Clean(cid)
	if path.Base(cid) != cid {
		// Someone is trying to hack us!
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Path traversal is forbidden for collection ID: ", cid),
			})
		return
	}

	client, err := GetGlobusOAuthCfg()
	if err != nil {
		log.Errorf("Error in getting Globus OAuth client: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error in getting Globus OAuth client: ", ctx.Request.URL),
			})
		return
	}

	token, err := client.Exchange(c, req.Code)
	if err != nil {
		log.Errorf("Error in exchanging code for token:  %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprint("Error in exchanging code for token: ", ctx.Request.URL),
			})
		return
	}

	// For getting the https server of the collection
	transferToken, err := getGlobusResourceToken(token, "transfer.api.globus.org")
	if err != nil {
		log.Errorf("Error getting token for Globus transfer API server: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Error getting token for Globus transfer API server: %v", err),
			})
		return
	}

	// For accessing files in the collection
	collectionToken, err := getGlobusResourceToken(token, cid)
	if err != nil {
		log.Errorf("Error getting token for Globus the collection %s: %v", cid, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Error getting token for Globus the collection %s: %v", cid, err),
			})
		return
	}

	// Get the https server of the collection from Globus transfer API server
	transferReq, err := http.NewRequest(http.MethodGet, globusTransferEndpointBaseUrl+cid, nil)
	if err != nil {
		log.Errorf("Error creating http request for Globus transfer API: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Error creating http request for Globus transfer API",
			})
		return
	}
	transferReq.Header.Add("Authorization", "Bearer "+transferToken.AccessToken)

	httpClient := http.Client{Transport: config.GetTransport()}

	transferRes, err := httpClient.Do(transferReq)
	if err != nil {
		log.Errorf("Error requesting Globus transfer API with URL %s: %v", transferReq.URL, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Error requesting Globus transfer API",
			})
		return
	}

	transferResBody, err := io.ReadAll(transferRes.Body)
	if err != nil {
		log.Errorf("Error reading response body from Globus transfer API with URL %s: %v", transferReq.URL, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Error reading response body from Globus transfer API",
			})
		return
	}

	if transferRes.StatusCode != 200 {
		log.Errorf("Globus transfer API returns non-200 status %d with URL %s and body %s", transferRes.StatusCode, transferReq.URL, string(transferResBody))
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Globus transfer API returns non-200 status %d with URL %s and body %s", transferRes.StatusCode, transferReq.URL, string(transferResBody)),
			})
		return
	}

	transferJSON := globusEndpointRes{}
	if err := json.Unmarshal(transferResBody, &transferJSON); err != nil {
		log.Errorf("Error parsing response body from Globus transfer API with URL %s and body %s: %v", transferReq.URL, string(transferResBody), err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Error parsing response body from Globus transfer API",
			})
		return
	}

	if transferJSON.HttpsServer == "" {
		log.Errorf("Globus collection %s with name %s does not enable https server", cid, transferJSON.DisplayName)
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Globus collection %s with name %s does not enable https server", cid, transferJSON.DisplayName),
			})
		return
	}

	// We have all the data in place, let's create/update related data strcutures:
	// 1. Pesist access token to disk for XRootD to read
	// 2.	Update in-memory globusExports struct with the OAuth token (both access and refresh token),
	//    	HttpsServer, and display name (from Globus API)
	// 3. Update origin DB to persist the refresh token, HttpsServer, and display name
	err = func() error {
		globusExportsMutex.Lock()
		defer globusExportsMutex.Unlock()

		if err := persistAccessToken(cid, collectionToken); err != nil {
			return err
		}

		if _, ok := globusExports[cid]; ok {
			log.Infof("Updating existing Globus export %s with new token", cid)
			globusExports[cid].HttpsServer = transferJSON.HttpsServer
			globusExports[cid].Token = collectionToken
			globusExports[cid].Status = GlobusActivated
			globusExports[cid].Description = ""
			if globusExports[cid].DisplayName == "" || globusExports[cid].DisplayName == cid {
				globusExports[cid].DisplayName = transferJSON.DisplayName
			}
		} else {
			// We should never go here
			return fmt.Errorf("Globus collection %s with name %s does not exist in Pelican", cid, transferJSON.DisplayName)
		}

		ok, err := collectionExistsByUUID(cid)
		if err != nil {
			return err
		}
		if !ok { // First time activate this collection
			gc := GlobusCollection{
				UUID:         cid,
				Name:         transferJSON.DisplayName,
				ServerURL:    transferJSON.HttpsServer,
				RefreshToken: collectionToken.RefreshToken,
			}
			return createCollection(&gc)
		} else { // Activated this collection before, but for some reason we want to update the credentials
			// although in the token refresh logic, if any of the credentials expires,
			// we should hard-delete this collection entry
			gc := GlobusCollection{
				Name:         transferJSON.DisplayName,
				ServerURL:    transferJSON.HttpsServer,
				RefreshToken: collectionToken.RefreshToken,
			}
			return updateCollection(cid, &gc)
		}
	}()

	if err != nil {
		log.Errorf("Failed to update Globus collection %s with name %s: %v", cid, transferJSON.DisplayName, err)
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update Globus collection %s with name %s: %v", cid, transferJSON.DisplayName, err),
			})
		return
	}

	ctx.JSON(http.StatusOK, globusAuthCallbackRes{NextUrl: nextUrl})

	// Restart the server
	config.RestartFlag <- true
}

// Start Globus OAuth2 code flow for a Globus collection
func handleGlobusAuth(ctx *gin.Context) {
	cid, ok := ctx.Params.Get("id")
	if !ok || cid == "" {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Collection ID is a required path parameter",
			})
	}
	req := server_structs.OAuthLoginRequest{}
	if ctx.ShouldBindQuery(&req) != nil {
		ctx.JSON(http.StatusBadRequest,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to bind next url",
			})
	}

	// CSRF token is required, embed next URL to the state
	csrfState, err := web_ui.GenerateCSRFCookie(
		ctx,
		map[string]string{"nextUrl": req.NextUrl, "id": cid},
	)

	if err != nil {
		log.Errorf("Failed to generate CSRF token: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to generate CSRF token",
			})
		return
	}

	client, err := GetGlobusOAuthCfg()
	if err != nil {
		log.Error("")
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: ""})
		return
	}

	baseScopes := client.Scopes
	reqScopes := append(
		baseScopes,
		fmt.Sprintf("https://auth.globus.org/scopes/%s/https", cid),
		fmt.Sprintf("https://auth.globus.org/scopes/%s/data_access", cid),
	)
	redirectUrl := client.AuthCodeURL(
		csrfState,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("scope", strings.Join(reqScopes, " ")),
	)
	ctx.Redirect(http.StatusTemporaryRedirect, redirectUrl)
}

// Persist the access token on the disk
func persistAccessToken(collectionID string, token *oauth2.Token) error {
	uid, err := config.GetDaemonUID()
	if err != nil {
		return errors.Wrap(err, "failed to persist Globus access token on disk: failed to get uid")
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to persist Globus access token on disk: failed to get gid")
	}
	globusFdr := param.Origin_GlobusConfigLocation.GetString()
	tokBase := filepath.Join(globusFdr, "tokens")
	if filepath.Clean(tokBase) == "" {
		return fmt.Errorf("failed to update Globus token: Origin.GlobusTokenLocation is not a valid path: %s", tokBase)
	}
	tokFileName := filepath.Join(tokBase, collectionID+GlobusTokenFileExt)
	tmpTokFile, err := os.CreateTemp(tokBase, collectionID+GlobusTokenFileExt)
	if err != nil {
		return errors.Wrap(err, "failed to update Globus token: unable to create a temporary Globus token file")
	}
	// We need to change the directory and file permission to XRootD user/group so that it can access the token
	if err = tmpTokFile.Chown(uid, gid); err != nil {
		return errors.Wrapf(err, "unable to change the ownership of Globus token file at %s to xrootd daemon", tmpTokFile.Name())
	}
	defer tmpTokFile.Close()

	_, err = tmpTokFile.Write([]byte(token.AccessToken + "\n"))
	if err != nil {
		return errors.Wrap(err, "failed to update Globus token: unable to write token to the tmp file")
	}

	if err = tmpTokFile.Sync(); err != nil {
		return errors.Wrap(err, "failed to update Globus token: unable to flush tmp file to disk")
	}

	if err := os.Rename(tmpTokFile.Name(), tokFileName); err != nil {
		return errors.Wrap(err, "failed to update Globus token: unable to rename tmp file to the token file")
	}
	return nil
}

// Refresh a Globus OAuth2 token for collection access
//
// Returns nil if the token is still valid (expire time > 5min) or the refreshed token.
// Returns error if any
func refreshGlobusToken(cid string, token *oauth2.Token) (*oauth2.Token, error) {
	if token == nil {
		return nil, fmt.Errorf("failed to update Globus token for collection %s: token is nil", cid)
	}
	// If token is not expired in the next 5min, return
	if !token.Expiry.Before(time.Now().Add(5 * time.Minute)) {
		return nil, nil
	}
	config, err := GetGlobusOAuthCfg()
	if err != nil {
		return nil, fmt.Errorf("failed to get Globus client to update Globus token for collection %s:", cid)
	}
	ts := config.TokenSource(context.Background(), token)
	newTok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to update Globus token for collection %s:", cid)
	}
	// Update access token location with the new token
	if err := persistAccessToken(cid, token); err != nil {
		return nil, err
	}

	if err := updateCollection(cid, &GlobusCollection{RefreshToken: newTok.RefreshToken}); err != nil {
		return nil, err
	}

	return newTok, nil
}
