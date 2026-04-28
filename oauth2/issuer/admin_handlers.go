/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package issuer

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// ---- Request / Response types for the admin client API ----

// AdminCreateClientRequest is the JSON body for POST /admin/clients.
type AdminCreateClientRequest struct {
	// ClientName is an optional human-readable label.
	ClientName string `json:"client_name"`
	// RedirectURIs accepted by this client.
	RedirectURIs []string `json:"redirect_uris"`
	// GrantTypes this client is allowed to use.
	// Accepted values: "authorization_code", "refresh_token",
	// "urn:ietf:params:oauth:grant-type:device_code",
	// "urn:ietf:params:oauth:grant-type:token-exchange".
	GrantTypes []string `json:"grant_types"`
	// ResponseTypes supported (e.g. "code", "token").
	ResponseTypes []string `json:"response_types"`
	// Scopes the client is allowed to request.
	Scopes []string `json:"scopes"`
	// Public indicates whether this client is a public (no secret) client.
	Public bool `json:"public"`
}

// AdminClientResponse is the JSON returned when listing or retrieving a client.
type AdminClientResponse struct {
	ClientID      string   `json:"client_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
	Public        bool     `json:"public"`
	CreatedAt     string   `json:"created_at"`
}

// AdminCreateClientResponse extends AdminClientResponse with the plaintext
// secret (only shown once, at creation time).
type AdminCreateClientResponse struct {
	AdminClientResponse
	ClientSecret string `json:"client_secret"`
}

// ---- Allowed grant types ----

// allowedGrantTypes is the set of grant types that may be configured via admin
// client management.
var allowedGrantTypes = map[string]bool{
	"authorization_code": true,
	"refresh_token":      true,
	"urn:ietf:params:oauth:grant-type:device_code":    true,
	"urn:ietf:params:oauth:grant-type:token-exchange": true,
}

// ---- Handlers ----

// handleAdminListClients returns all non-dynamic clients.
//
//	@Summary      List issuer clients
//	@Description  Returns all administrator-managed OIDC clients.
//	@Tags         issuer-admin
//	@Produce      json
//	@Success      200  {array}  AdminClientResponse
//	@Failure      500  {object} object  "server_error"
//	@Router       /issuer/admin/clients [get]
func handleAdminListClients(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clients, err := provider.Storage().ListClients(ctx)
		if err != nil {
			log.WithError(err).Warn("Embedded issuer admin: failed to list clients")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to list clients"})
			return
		}
		ctx.JSON(http.StatusOK, clients)
	}
}

// handleAdminGetClient returns details for a single client.
//
//	@Summary      Get issuer client
//	@Description  Returns details for a single OIDC client by ID.
//	@Tags         issuer-admin
//	@Produce      json
//	@Param        id   path      string  true  "Client ID"
//	@Success      200  {object}  AdminClientResponse
//	@Failure      404  {object}  object  "not_found"
//	@Failure      500  {object}  object  "server_error"
//	@Router       /issuer/admin/clients/{id} [get]
func handleAdminGetClient(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")
		detail, err := provider.Storage().GetClientDetail(ctx, clientID)
		if err != nil {
			if err == fosite.ErrNotFound {
				ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Client not found"})
				return
			}
			log.WithError(err).Warn("Embedded issuer admin: failed to get client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to get client"})
			return
		}
		ctx.JSON(http.StatusOK, detail)
	}
}

// handleAdminCreateClient creates a new administrator-managed client.
//
//	@Summary      Create issuer client
//	@Description  Creates a new OIDC client with the specified grant types and scopes.
//	@Tags         issuer-admin
//	@Accept       json
//	@Produce      json
//	@Param        body  body      AdminCreateClientRequest  true  "Client configuration"
//	@Success      201   {object}  AdminCreateClientResponse
//	@Failure      400   {object}  object  "invalid_request"
//	@Failure      500   {object}  object  "server_error"
//	@Router       /issuer/admin/clients [post]
func handleAdminCreateClient(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req AdminCreateClientRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid JSON body"})
			return
		}

		// Validate grant types
		if len(req.GrantTypes) == 0 {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "At least one grant_type is required"})
			return
		}
		for _, gt := range req.GrantTypes {
			if !allowedGrantTypes[gt] {
				ctx.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "Unsupported grant_type: " + gt,
				})
				return
			}
		}

		// Default scopes if none provided
		if len(req.Scopes) == 0 {
			req.Scopes = []string{"openid", "offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"}
		}

		// Default response types
		if len(req.ResponseTypes) == 0 {
			// Only add "code" if authorization_code is among the grant types.
			for _, gt := range req.GrantTypes {
				if gt == "authorization_code" {
					req.ResponseTypes = []string{"code"}
					break
				}
			}
		}

		// Generate credentials
		clientID, err := generateSecureToken(16)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		var clientSecret string
		var hashedSecret []byte
		if !req.Public {
			clientSecret, err = generateSecureToken(32)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
			hashedSecret, err = bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
		}

		client := &fosite.DefaultClient{
			ID:            clientID,
			Secret:        hashedSecret,
			RedirectURIs:  req.RedirectURIs,
			GrantTypes:    req.GrantTypes,
			ResponseTypes: req.ResponseTypes,
			Scopes:        req.Scopes,
			Audience:      fosite.Arguments{WLCGAudienceAny},
			Public:        req.Public,
		}

		if err := provider.Storage().CreateClient(ctx, client); err != nil {
			log.WithError(err).Warn("Embedded issuer admin: failed to create client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to create client"})
			return
		}

		log.Infof("Embedded issuer admin: created client %s with grant_types=%v", clientID, req.GrantTypes)

		resp := AdminCreateClientResponse{
			AdminClientResponse: AdminClientResponse{
				ClientID:      clientID,
				RedirectURIs:  req.RedirectURIs,
				GrantTypes:    req.GrantTypes,
				ResponseTypes: req.ResponseTypes,
				Scopes:        req.Scopes,
				Public:        req.Public,
			},
			ClientSecret: clientSecret,
		}

		ctx.JSON(http.StatusCreated, resp)
	}
}

// handleAdminDeleteClient removes a client by ID.
//
//	@Summary      Delete issuer client
//	@Description  Deletes an OIDC client by ID.
//	@Tags         issuer-admin
//	@Param        id   path      string  true  "Client ID"
//	@Success      204
//	@Failure      404  {object}  object  "not_found"
//	@Failure      500  {object}  object  "server_error"
//	@Router       /issuer/admin/clients/{id} [delete]
func handleAdminDeleteClient(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")

		deleted, err := provider.Storage().DeleteClient(ctx, clientID)
		if err != nil {
			log.WithError(err).Warn("Embedded issuer admin: failed to delete client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to delete client"})
			return
		}
		if !deleted {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Client not found"})
			return
		}

		log.Infof("Embedded issuer admin: deleted client %s", clientID)
		ctx.Status(http.StatusNoContent)
	}
}

// AdminUpdateClientRequest is the JSON body for PUT /admin/clients/:id.
// All fields are optional; only provided fields are updated.
type AdminUpdateClientRequest struct {
	RedirectURIs  *[]string `json:"redirect_uris"`
	GrantTypes    *[]string `json:"grant_types"`
	ResponseTypes *[]string `json:"response_types"`
	Scopes        *[]string `json:"scopes"`
}

// handleAdminUpdateClient updates mutable fields of an existing client.
//
//	@Summary      Update issuer client
//	@Description  Updates the configuration of an existing OIDC client. Only provided fields are changed.
//	@Tags         issuer-admin
//	@Accept       json
//	@Produce      json
//	@Param        id    path      string                   true  "Client ID"
//	@Param        body  body      AdminUpdateClientRequest  true  "Fields to update"
//	@Success      200   {object}  AdminClientResponse
//	@Failure      400   {object}  object  "invalid_request"
//	@Failure      404   {object}  object  "not_found"
//	@Failure      500   {object}  object  "server_error"
//	@Router       /issuer/admin/clients/{id} [put]
func handleAdminUpdateClient(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")

		var req AdminUpdateClientRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid JSON body"})
			return
		}

		// Validate grant types if provided.
		if req.GrantTypes != nil {
			if len(*req.GrantTypes) == 0 {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "grant_types must not be empty when provided"})
				return
			}
			for _, gt := range *req.GrantTypes {
				if !allowedGrantTypes[gt] {
					ctx.JSON(http.StatusBadRequest, gin.H{
						"error":             "invalid_request",
						"error_description": "Unsupported grant_type: " + gt,
					})
					return
				}
			}
		}

		update := ClientUpdate{
			RedirectURIs:  req.RedirectURIs,
			GrantTypes:    req.GrantTypes,
			ResponseTypes: req.ResponseTypes,
			Scopes:        req.Scopes,
		}

		updated, err := provider.Storage().UpdateClient(ctx, clientID, update)
		if err != nil {
			if err == fosite.ErrNotFound {
				ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Client not found"})
				return
			}
			log.WithError(err).Warn("Embedded issuer admin: failed to update client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to update client"})
			return
		}

		log.Infof("Embedded issuer admin: updated client %s", clientID)
		ctx.JSON(http.StatusOK, updated)
	}
}

// ---- Token Exchange (RFC 8693) ----

// tokenExchangeGrantType is the grant_type value for RFC 8693 token exchange.
const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// handleTokenExchange processes an RFC 8693 token exchange request.
// The client presents a subject_token (a valid access token issued by this
// server) and receives a new access token, potentially with narrower scopes
// or a different audience.
//
// This grant type is only available to clients whose grant_types include
// "urn:ietf:params:oauth:grant-type:token-exchange".
func handleTokenExchange(ctx *gin.Context, provider *OIDCProvider) {
	r := ctx.Request
	rCtx := r.Context()

	// ---- Authenticate the calling client ----
	clientID, clientSecret, hasAuth := r.BasicAuth()
	if !hasAuth {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Client authentication required"})
		return
	}

	client, err := provider.Storage().GetClient(rCtx, clientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Unknown client"})
		return
	}

	dc := client.(*fosite.DefaultClient)
	if !dc.Public {
		if err := bcrypt.CompareHashAndPassword(dc.Secret, []byte(clientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Invalid client credentials"})
			return
		}
	}

	// ---- Verify client is authorized for token exchange ----
	hasTokenExchange := false
	for _, gt := range dc.GrantTypes {
		if gt == tokenExchangeGrantType {
			hasTokenExchange = true
			break
		}
	}
	if !hasTokenExchange {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "This client is not authorized for the token-exchange grant type",
		})
		return
	}

	// ---- Parse & validate the subject token ----
	subjectToken := r.FormValue("subject_token")
	if subjectToken == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "subject_token is required"})
		return
	}

	subjectTokenType := r.FormValue("subject_token_type")
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Only subject_token_type=urn:ietf:params:oauth:token-type:access_token is supported",
		})
		return
	}

	// Introspect the subject token — this validates signature, expiry, etc.
	issuerURL := IssuerURLForNamespace(provider.Namespace)
	introSession := DefaultOIDCSession("", issuerURL, nil, nil)
	_, subjectAR, err := provider.Provider().IntrospectToken(rCtx, subjectToken, fosite.AccessToken, introSession)
	if err != nil {
		log.WithError(err).Debug("Embedded issuer: token exchange subject_token introspection failed")
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "The subject_token is invalid or expired",
		})
		return
	}

	// ---- Determine scopes for the exchanged token ----
	requestedScopeStr := r.FormValue("scope")
	var requestedScopes []string
	if requestedScopeStr != "" {
		requestedScopes = strings.Split(requestedScopeStr, " ")
	}

	// If no explicit scopes requested, inherit from the subject token.
	subjectGrantedScopes := subjectAR.GetGrantedScopes()
	if len(requestedScopes) == 0 {
		requestedScopes = subjectGrantedScopes
	}

	// The exchanged token's scopes must be a subset of both:
	// (a) what the subject token grants
	// (b) what the client is allowed to request
	// No scopes are auto-allowed — including standard ones like
	// offline_access — so that operators who omit a scope from a client's
	// configuration can enforce that restriction.
	grantedScopes := make([]string, 0, len(requestedScopes))
	for _, scope := range requestedScopes {
		// Check the scope is within the subject token's grants.
		if !scopeAllowed(scope, subjectGrantedScopes) {
			continue
		}
		// Check the scope is within the client's allowed scopes.
		if !scopeAllowed(scope, dc.Scopes) {
			continue
		}
		grantedScopes = append(grantedScopes, scope)
	}

	// ---- Determine audience ----
	requestedAudience := r.FormValue("audience")
	// We always grant the WLCG wildcard; if the caller requests a specific
	// audience it must already be present in the subject token's granted
	// audiences to prevent arbitrary audience injection.
	audiences := []string{WLCGAudienceAny}
	if requestedAudience != "" && requestedAudience != WLCGAudienceAny {
		subjectAudiences := subjectAR.GetGrantedAudience()
		audienceAllowed := false
		for _, aud := range subjectAudiences {
			if aud == requestedAudience {
				audienceAllowed = true
				break
			}
		}
		if !audienceAllowed {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_target",
				"error_description": "The requested audience is not present in the subject token",
			})
			return
		}
		audiences = append(audiences, requestedAudience)
	}

	// ---- Build the new session and issue tokens ----
	subject := subjectAR.GetSession().GetSubject()

	// Carry forward WLCG groups from the subject token's session.
	var groups []string
	if ws, ok := subjectAR.GetSession().(*WLCGSession); ok && ws.JWTClaims != nil && ws.JWTClaims.Extra != nil {
		if g, ok := ws.JWTClaims.Extra["wlcg.groups"]; ok {
			if gs, ok := g.([]interface{}); ok {
				for _, gi := range gs {
					if s, ok := gi.(string); ok {
						groups = append(groups, s)
					}
				}
			} else if gs, ok := g.([]string); ok {
				groups = gs
			}
		}
	}

	session := DefaultOIDCSession(subject, issuerURL, groups, grantedScopes)
	session.SetExpiresAt(fosite.AccessToken, time.Now().Add(provider.config.AccessTokenLifespan))
	ar := fosite.NewAccessRequest(session)
	ar.Client = client
	ar.GrantedScope = grantedScopes
	ar.RequestedScope = requestedScopes
	ar.Session = session
	for _, aud := range audiences {
		ar.GrantAudience(aud)
	}

	// Generate access token
	accessToken, accessSignature, err := provider.strategy.CoreStrategy.GenerateAccessToken(rCtx, ar)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to generate token-exchange access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to generate access token"})
		return
	}

	if err := provider.storage.CreateAccessTokenSession(rCtx, accessSignature, ar); err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to store token-exchange access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to store access token"})
		return
	}

	// Record client usage
	_ = provider.storage.TouchClientLastUsed(rCtx, clientID)

	// RFC 8693 §2.2.1: the response includes issued_token_type.
	result := gin.H{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        int(provider.config.AccessTokenLifespan.Seconds()),
	}

	// Optionally issue a refresh token if offline_access is among scopes
	// AND the client is authorized for the refresh_token grant type.
	hasRefreshGrant := false
	for _, gt := range dc.GrantTypes {
		if gt == "refresh_token" {
			hasRefreshGrant = true
			break
		}
	}
	if hasRefreshGrant {
		for _, s := range grantedScopes {
			if s == "offline_access" {
				ar.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().Add(provider.config.RefreshTokenLifespan))
				rt, rtSig, rtErr := provider.strategy.CoreStrategy.GenerateRefreshToken(rCtx, ar)
				if rtErr != nil {
					log.WithError(rtErr).Warn("Embedded issuer: failed to generate token-exchange refresh token")
					break
				}
				if rtErr = provider.storage.CreateRefreshTokenSession(rCtx, rtSig, accessSignature, ar); rtErr != nil {
					log.WithError(rtErr).Warn("Embedded issuer: failed to store token-exchange refresh token")
					break
				}
				result["refresh_token"] = rt
				break
			}
		}
	}

	ctx.Header("Content-Type", "application/json;charset=UTF-8")
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.JSON(http.StatusOK, result)
}
