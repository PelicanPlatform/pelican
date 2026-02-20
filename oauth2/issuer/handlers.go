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
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
)

// IssuerURL returns the issuer URL for the embedded OIDC provider.
// It prefers Issuer.IssuerClaimValue when explicitly set, falling back to
// Server.ExternalWebUrl.  This mirrors the logic in ConfigureOA4MP so that
// the embedded issuer and the OA4MP proxy produce consistent token claims.
func IssuerURL() string {
	if v := param.Issuer_IssuerClaimValue.GetString(); v != "" {
		return v
	}
	return param.Server_ExternalWebUrl.GetString()
}

// RegisterRoutesWithMiddleware registers all embedded OIDC issuer routes on the
// given engine, optionally applying the supplied middleware to the route group.
// This allows callers to inject user-identity-populating middleware (e.g. one
// that extracts a login cookie) without the issuer package importing web_ui.
func RegisterRoutesWithMiddleware(engine *gin.Engine, provider *OIDCProvider, middleware ...gin.HandlerFunc) {
	issuerGroup := engine.Group("/api/v1.0/issuer", middleware...)
	{
		issuerGroup.POST("/token", handleToken(provider))
		issuerGroup.GET("/authorize", handleAuthorize(provider))
		issuerGroup.POST("/authorize", handleAuthorize(provider))
		issuerGroup.POST("/device_authorization", handleDeviceAuthorization(provider))
		issuerGroup.GET("/device", handleDeviceVerify(provider))
		issuerGroup.POST("/device", handleDeviceVerifySubmit(provider))
		issuerGroup.GET("/userinfo", handleUserInfo(provider))
		issuerGroup.POST("/revoke", handleRevoke(provider))
		issuerGroup.POST("/introspect", handleIntrospect(provider))
		issuerGroup.POST("/oidc-cm", handleDynamicClientRegistration(provider))
		// OA4MP serves this under /api/v1.0/issuer/; replicate for compatibility
		issuerGroup.GET("/.well-known/openid-configuration", handleIssuerDiscovery(provider))
	}
}

// handleIssuerDiscovery returns the OIDC discovery document scoped to the issuer
// prefix so that the health-check in launcher.go works identically for both
// OA4MP and the embedded issuer.
func handleIssuerDiscovery(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		issuerURL := IssuerURL()
		serviceURI := issuerURL + "/api/v1.0/issuer"

		ctx.JSON(http.StatusOK, gin.H{
			"issuer":                 issuerURL,
			"token_endpoint":         serviceURI + "/token",
			"authorization_endpoint": serviceURI + "/authorize",
			"userinfo_endpoint":      serviceURI + "/userinfo",
			"revocation_endpoint":    serviceURI + "/revoke",
			"introspection_endpoint": serviceURI + "/introspect",
			"device_authorization_endpoint": serviceURI + "/device_authorization",
			"registration_endpoint":         serviceURI + "/oidc-cm",
			"jwks_uri":             issuerURL + "/.well-known/issuer.jwks",
			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
			},
			"scopes_supported": []string{
				"openid", "offline_access", "wlcg",
				"storage.read:/", "storage.modify:/", "storage.create:/",
			},
			"token_endpoint_auth_methods_supported": []string{
				"client_secret_basic", "client_secret_post",
			},
			"response_types_supported": []string{"code"},
			"subject_types_supported":  []string{"public"},
			"id_token_signing_alg_values_supported": []string{provider.signingAlgorithm()},
		})
	}
}

// handleToken handles the /token endpoint for all grant types:
// authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:device_code
func handleToken(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		w := ctx.Writer
		rCtx := r.Context()

		grantType := r.FormValue("grant_type")

		// Handle device code grant type specially
		if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			handleDeviceTokenExchange(ctx, provider)
			return
		}

		session := DefaultOIDCSession("", IssuerURL(), nil, nil)

		ar, err := provider.Provider().NewAccessRequest(rCtx, r, session)
		if err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to create access request")
			provider.Provider().WriteAccessError(rCtx, w, ar, err)
			return
		}

		// For refresh token grants, preserve the session claims
		if grantType == "refresh_token" {
			for _, scope := range ar.GetGrantedScopes() {
				ar.GrantScope(scope)
			}
		}

		response, err := provider.Provider().NewAccessResponse(rCtx, ar)
		if err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to create access response")
			provider.Provider().WriteAccessError(rCtx, w, ar, err)
			return
		}

		provider.Provider().WriteAccessResponse(rCtx, w, ar, response)
	}
}

// handleAuthorize handles the /authorize endpoint for the authorization code flow.
// It requires authentication via Pelican's auth middleware (applied at the route level).
func handleAuthorize(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := ctx.GetString("User")
		userID := ctx.GetString("UserId")
		groups := ctx.GetStringSlice("Groups")
		if user == "" {
			// Not authenticated - redirect to login
			origPath := ctx.Request.URL.RequestURI()
			redirUrl := url.URL{
				Path:     "/view/login",
				RawQuery: "nextUrl=" + url.QueryEscape(origPath),
			}
			ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
			ctx.Abort()
			return
		}

		r := ctx.Request
		w := ctx.Writer
		rCtx := r.Context()

		ar, err := provider.Provider().NewAuthorizeRequest(rCtx, r)
		if err != nil {
			log.WithError(err).Debug("Embedded issuer: failed to create authorize request")
			provider.Provider().WriteAuthorizeError(rCtx, w, ar, err)
			return
		}

		// Calculate allowed scopes for this user
		allowedScopes, matchedGroups := oa4mp.CalculateAllowedScopes(user, userID, groups)
		serverDB := database.ServerDatabase
		if serverDB == nil {
			serverDB = provider.storage.db
		}
		collectionScopes, collectionGroups, colErr := oa4mp.GetUserCollectionScopes(serverDB, user, groups)
		if colErr != nil {
			log.WithError(colErr).Warn("Embedded issuer: failed to get collection scopes")
		} else {
			allowedScopes = append(allowedScopes, collectionScopes...)
			matchedGroups = oa4mp.MergeGroups(matchedGroups, collectionGroups)
		}

		// Filter requested scopes to what the user is allowed.
		// When a requested scope is broader than what's permitted,
		// substitute in all narrower allowed scopes that fall under it.
		for _, scope := range ar.GetRequestedScopes() {
			if isStandardScope(scope) {
				ar.GrantScope(scope)
			} else if scopeAllowed(scope, allowedScopes) {
				ar.GrantScope(scope)
			} else {
				for _, ns := range collectNarrowerScopes(scope, allowedScopes) {
					ar.GrantScope(ns)
				}
			}
		}

		issuerURL := IssuerURL()
		session := DefaultOIDCSession(user, issuerURL, matchedGroups, ar.GetGrantedScopes())

		response, err := provider.Provider().NewAuthorizeResponse(rCtx, ar, session)
		if err != nil {
			log.WithError(err).Debug("Embedded issuer: failed to create authorize response")
			provider.Provider().WriteAuthorizeError(rCtx, w, ar, err)
			return
		}

		provider.Provider().WriteAuthorizeResponse(rCtx, w, ar, response)
	}
}

// handleDeviceAuthorization handles the /device_authorization endpoint (RFC 8628).
func handleDeviceAuthorization(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request

		// Authenticate client
		clientID, clientSecret, hasAuth := r.BasicAuth()
		if !hasAuth {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}

		if clientID == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Client authentication required"})
			return
		}

		client, err := provider.Storage().GetClient(ctx, clientID)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Unknown client"})
			return
		}

		// Verify client secret
		dc := client.(*fosite.DefaultClient)
		if err := bcrypt.CompareHashAndPassword(dc.Secret, []byte(clientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Invalid client credentials"})
			return
		}

		// Parse requested scopes
		scopeStr := r.FormValue("scope")
		var scopes []string
		if scopeStr != "" {
			scopes = strings.Split(scopeStr, " ")
		}

		resp, err := provider.DeviceCodeHandler.HandleDeviceAuthorizationRequest(ctx, client, scopes)
		if err != nil {
			log.WithError(err).Debug("Embedded issuer: device authorization failed")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, resp)
	}
}

// handleDeviceVerify serves the device code verification page (GET)
func handleDeviceVerify(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := ctx.GetString("User")
		if user == "" {
			origPath := ctx.Request.URL.RequestURI()
			redirUrl := url.URL{
				Path:     "/view/login",
				RawQuery: "nextUrl=" + url.QueryEscape(origPath),
			}
			ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
			ctx.Abort()
			return
		}

		userCode := ctx.Query("user_code")

		// Generate CSRF token and set it in a cookie
		csrfToken, err := generateSecureToken(32)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to generate CSRF token")
			return
		}
		ctx.SetCookie("csrf_token", csrfToken, 600, "/api/v1.0/issuer/device", "", true, true)

		tmpl, err := template.New("device-consent").Parse(deviceConsentTemplate)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Template error")
			return
		}

		data := map[string]interface{}{
			"UserCode":    userCode,
			"FormAction":  "/api/v1.0/issuer/device",
			"HasUserCode": userCode != "",
			"CSRFToken":   csrfToken,
		}

		ctx.Header("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(ctx.Writer, data); err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to render device consent template")
		}
	}
}

// handleDeviceVerifySubmit processes the device code verification form submission (POST)
func handleDeviceVerifySubmit(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := ctx.GetString("User")
		if user == "" {
			origPath := ctx.Request.URL.RequestURI()
			redirUrl := url.URL{
				Path:     "/view/login",
				RawQuery: "nextUrl=" + url.QueryEscape(origPath),
			}
			ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
			ctx.Abort()
			return
		}

		// Validate CSRF token
		csrfCookie, err := ctx.Cookie("csrf_token")
		csrfForm := ctx.PostForm("csrf_token")
		if err != nil || csrfCookie == "" || csrfForm == "" || csrfCookie != csrfForm {
			ctx.String(http.StatusForbidden, "CSRF validation failed")
			return
		}
		// Clear the CSRF cookie after validation
		ctx.SetCookie("csrf_token", "", -1, "/api/v1.0/issuer/device", "", true, true)

		userID := ctx.GetString("UserId")
		groups := ctx.GetStringSlice("Groups")

		userCode := ctx.PostForm("user_code")
		action := ctx.PostForm("action")

		if userCode == "" {
			renderDeviceResult(ctx, "error", "No user code provided")
			return
		}

		// Normalize user code
		userCode = strings.ToUpper(strings.TrimSpace(userCode))

		if action == "deny" {
			if err := provider.Storage().DenyDeviceCodeSession(ctx, userCode); err != nil {
				log.WithError(err).Warn("Embedded issuer: failed to deny device code")
			}
			renderDeviceResult(ctx, "denied", "")
			return
		}

		// Look up the device code
		dc, err := provider.Storage().GetDeviceCodeSessionByUserCode(ctx, userCode)
		if err != nil {
			renderDeviceResult(ctx, "error", "Invalid or expired user code")
			return
		}

		if dc.Status != "pending" {
			renderDeviceResult(ctx, "error", "This code has already been used")
			return
		}

		if time.Now().After(dc.ExpiresAt) {
			renderDeviceResult(ctx, "error", "This code has expired")
			return
		}

		// For dynamically registered clients, enforce single-user binding.
		// The first user to approve a device code for this client becomes the
		// only user who can ever use it.
		isDynamic, _ := provider.Storage().IsDynamicallyRegistered(ctx, dc.ClientID)
		if isDynamic {
			if err := provider.Storage().BindClientToUser(ctx, dc.ClientID, user); err != nil {
				log.WithError(err).Warnf("Embedded issuer: user %s cannot use client %s (bound to different user)", user, dc.ClientID)
				renderDeviceResult(ctx, "error", "This client is registered to a different user")
				return
			}
		}

		// Calculate allowed scopes
		allowedScopes, matchedGroups := oa4mp.CalculateAllowedScopes(user, userID, groups)
		serverDB := database.ServerDatabase
		if serverDB == nil {
			serverDB = provider.storage.db
		}
		collectionScopes, collectionGroups, colErr := oa4mp.GetUserCollectionScopes(serverDB, user, groups)
		if colErr == nil {
			allowedScopes = append(allowedScopes, collectionScopes...)
			matchedGroups = oa4mp.MergeGroups(matchedGroups, collectionGroups)
		}

		// Parse requested scopes from the device code session
		var requestedScopes []string
		if err := json.Unmarshal([]byte(dc.Scopes), &requestedScopes); err != nil {
			requestedScopes = []string{}
		}

		// Filter scopes — when a requested scope is broader than what's
		// permitted, substitute in all narrower allowed scopes.
		grantedScopes := make([]string, 0)
		for _, scope := range requestedScopes {
			if isStandardScope(scope) || scopeAllowed(scope, allowedScopes) {
				grantedScopes = append(grantedScopes, scope)
			} else {
				grantedScopes = append(grantedScopes, collectNarrowerScopes(scope, allowedScopes)...)
			}
		}

		issuerURL := IssuerURL()
		session := DefaultOIDCSession(user, issuerURL, matchedGroups, grantedScopes)
		sessionData, _ := json.Marshal(session)

		if err := provider.Storage().ApproveDeviceCodeSession(ctx, userCode, user, grantedScopes, sessionData); err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to approve device code")
			renderDeviceResult(ctx, "error", "Failed to approve device code")
			return
		}

		renderDeviceResult(ctx, "approved", "")
	}
}

// handleDeviceTokenExchange handles the token exchange for device code grant type.
func handleDeviceTokenExchange(ctx *gin.Context, provider *OIDCProvider) {
	r := ctx.Request
	w := ctx.Writer

	// Authenticate client
	clientID, clientSecret, hasAuth := r.BasicAuth()
	if !hasAuth {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	client, err := provider.Storage().GetClient(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	dc := client.(*fosite.DefaultClient)
	if err := bcrypt.CompareHashAndPassword(dc.Secret, []byte(clientSecret)); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device_code required"})
		return
	}

	issuerURL := IssuerURL()
	session := DefaultOIDCSession("", issuerURL, nil, nil)

	request, err := provider.DeviceCodeHandler.HandleDeviceAccessRequest(ctx, deviceCode, session)
	if err != nil {
		// Return the appropriate RFC 8628 error
		rfcErr, ok := err.(*fosite.RFC6749Error)
		if ok {
			ctx.JSON(rfcErr.CodeField, gin.H{
				"error":             rfcErr.ErrorField,
				"error_description": rfcErr.DescriptionField,
			})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	// Create access token using fosite
	rCtx := r.Context()

	// Build an access request with the approved session
	ar := fosite.NewAccessRequest(request.GetSession())
	ar.Client = client
	ar.RequestedAt = request.GetRequestedAt()
	ar.GrantedScope = request.GetGrantedScopes()
	ar.RequestedScope = request.GetRequestedScopes()
	ar.Session = request.GetSession()
	ar.Form = request.GetRequestForm()

	// Set the access token expiration on the session - required by JWT strategy
	ar.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().Add(provider.config.AccessTokenLifespan))

	// Generate an access token via the strategy
	accessToken, accessSignature, err := provider.strategy.CoreStrategy.GenerateAccessToken(rCtx, ar)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to generate device code access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate access token",
		})
		return
	}

	if err := provider.storage.CreateAccessTokenSession(rCtx, accessSignature, ar); err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to store device code access token")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to store access token",
		})
		return
	}

	result := gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(provider.config.AccessTokenLifespan.Seconds()),
	}

	// Record that this client was used (prevents unused-client cleanup).
	_ = provider.storage.TouchClientLastUsed(rCtx, clientID)

	// Generate refresh token if offline_access was requested
	for _, s := range request.GetGrantedScopes() {
		if s == "offline_access" {
			refreshToken, refreshSignature, rtErr := provider.strategy.CoreStrategy.GenerateRefreshToken(rCtx, ar)
			if rtErr != nil {
				log.WithError(rtErr).Warn("Embedded issuer: failed to generate device code refresh token")
				break
			}
			if rtErr = provider.storage.CreateRefreshTokenSession(rCtx, refreshSignature, accessSignature, ar); rtErr != nil {
				log.WithError(rtErr).Warn("Embedded issuer: failed to store device code refresh token")
				break
			}
			result["refresh_token"] = refreshToken
			break
		}
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// handleUserInfo handles the /userinfo endpoint.
func handleUserInfo(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		rCtx := r.Context()

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		token := parts[1]
		issuerURL := IssuerURL()
		session := DefaultOIDCSession("", issuerURL, nil, nil)

		_, ar, err := provider.Provider().IntrospectToken(rCtx, token, fosite.AccessToken, session)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		subject := ar.GetSession().GetSubject()
		ctx.JSON(http.StatusOK, gin.H{
			"sub":  subject,
			"name": subject,
		})
	}
}

// handleRevoke handles the /revoke endpoint (RFC 7009).
func handleRevoke(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		w := ctx.Writer
		rCtx := r.Context()

		err := provider.Provider().NewRevocationRequest(rCtx, r)
		if err != nil {
			provider.Provider().WriteRevocationResponse(rCtx, w, err)
			return
		}

		provider.Provider().WriteRevocationResponse(rCtx, w, nil)
	}
}

// handleIntrospect handles the /introspect endpoint (RFC 7662).
func handleIntrospect(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		w := ctx.Writer
		rCtx := r.Context()

		issuerURL := IssuerURL()
		session := DefaultOIDCSession("", issuerURL, nil, nil)

		ir, err := provider.Provider().NewIntrospectionRequest(rCtx, r, session)
		if err != nil {
			log.WithError(err).Debug("Embedded issuer: introspection failed")
			provider.Provider().WriteIntrospectionError(rCtx, w, err)
			return
		}

		provider.Provider().WriteIntrospectionResponse(rCtx, w, ir)
	}
}

// handleDynamicClientRegistration handles the /oidc-cm endpoint (RFC 7591).
//
// This endpoint is intentionally unauthenticated so that command-line tools can
// bootstrap tokens from scratch.  Several mitigations limit abuse:
//
//  1. Per-IP rate limiting (token-bucket, default 5 burst / 1 per minute).
//  2. Grant types are restricted to device_code + refresh_token — the only
//     grants that make sense for a headless bootstrap flow.
//  3. Dynamically registered clients are bound to their first user on device
//     code approval, preventing use by other users.
//  4. A background janitor deletes dynamically registered clients that are
//     never used within a configurable window.
func handleDynamicClientRegistration(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// ---- Rate limit ----
		clientIP := ctx.ClientIP()
		if !provider.RegistrationLimiter.Allow(clientIP) {
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many client registrations from this address; try again later",
			})
			return
		}

		var req struct {
			RedirectURIs  []string `json:"redirect_uris"`
			GrantTypes    []string `json:"grant_types"`
			ResponseTypes []string `json:"response_types"`
			ClientName    string   `json:"client_name"`
			Scope         string   `json:"scope"`
		}

		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
			return
		}

		// Validate redirect URIs against Issuer.RedirectUris
		allowedURIs := param.Issuer_RedirectUris.GetStringSlice()
		if len(allowedURIs) > 0 {
			allowedSet := make(map[string]bool)
			for _, uri := range allowedURIs {
				allowedSet[uri] = true
			}
			for _, uri := range req.RedirectURIs {
				if !allowedSet[uri] {
					ctx.JSON(http.StatusForbidden, gin.H{
						"error":             "invalid_redirect_uri",
						"error_description": "Unregistered redirect_uri: " + uri,
					})
					return
				}
			}
		}

		// Generate client credentials
		clientID, err := generateSecureToken(16)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		clientSecret, err := generateSecureToken(32)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		// Dynamically registered clients are restricted to the device code
		// grant (+ refresh) — the minimal set needed for CLI bootstrap.
		// Callers may request a subset, but we never grant authorization_code.
		grantTypes := []string{
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
		}
		responseTypes := []string{} // no interactive response types

		scopes := []string{"openid", "offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"}

		client := &fosite.DefaultClient{
			ID:            clientID,
			Secret:        hashedSecret,
			RedirectURIs:  req.RedirectURIs,
			GrantTypes:    grantTypes,
			ResponseTypes: responseTypes,
			Scopes:        scopes,
			Public:        false,
		}

		if err := provider.Storage().CreateDynamicClient(ctx, client, clientIP); err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to register client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		ctx.JSON(http.StatusCreated, gin.H{
			"client_id":                clientID,
			"client_secret":            clientSecret,
			"client_name":              req.ClientName,
			"redirect_uris":            req.RedirectURIs,
			"grant_types":              grantTypes,
			"response_types":           responseTypes,
			"scope":                    strings.Join(scopes, " "),
			"client_secret_expires_at": 0,
		})
	}
}

// renderDeviceResult renders the appropriate device flow result page.
func renderDeviceResult(ctx *gin.Context, status, errorMsg string) {
	var tmplStr string
	switch status {
	case "approved":
		tmplStr = deviceOkTemplate
	case "denied":
		tmplStr = deviceFailTemplate
	default:
		tmplStr = deviceFailTemplate
	}

	tmpl, err := template.New("device-result").Parse(tmplStr)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Template error")
		return
	}

	data := map[string]interface{}{
		"ErrorMessage": errorMsg,
		"Status":       status,
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(ctx.Writer, data); err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to render device result template")
	}
}

// Helpers

func isStandardScope(scope string) bool {
	switch scope {
	case "openid", "offline_access", "wlcg", "profile", "email":
		return true
	}
	return false
}

func scopeAllowed(scope string, allowed []string) bool {
	for _, a := range allowed {
		if a == scope {
			return true
		}
	}
	// Check hierarchical matching
	return matchHierarchical(scope, allowed)
}
