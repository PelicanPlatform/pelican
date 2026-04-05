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

// WLCGAudienceAny is the WLCG "wildcard" audience value.
// Tokens bearing this audience are accepted by any WLCG-compliant service.
// See https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md
const WLCGAudienceAny = "https://wlcg.cern.ch/jwt/v1/any"

const (
	// maxRedirectURIs is the maximum number of redirect URIs a dynamic client may register.
	maxRedirectURIs = 10
	// maxRedirectURILen is the maximum length (in bytes) of a single redirect URI.
	maxRedirectURILen = 2048
	// maxClientNameLen is the maximum length (in bytes) of a client_name.
	maxClientNameLen = 128
)

// IssuerURL returns the base issuer URL for this server (without any namespace path).
// It is simply the server's external web URL.
func IssuerURL() string {
	return param.Server_ExternalWebUrl.GetString()
}

// IssuerURLForNamespace returns the issuer URL for the given namespace.
// If a namespace is provided, the issuer URL is scoped to that namespace.
// Otherwise it falls back to the legacy global issuer URL for backward
// compatibility.
func IssuerURLForNamespace(namespace string) string {
	base := IssuerURL()
	if namespace == "" {
		return base
	}
	return base + "/api/v1.0/issuer/ns" + namespace
}

// ServiceURIForNamespace returns the base path for OIDC endpoints scoped to a namespace.
func ServiceURIForNamespace(issuerURL, namespace string) string {
	return issuerURL + "/api/v1.0/issuer/ns" + namespace
}

// RegisterRoutesWithMiddleware registers all embedded OIDC issuer routes on the
// given engine, optionally applying the supplied middleware to the route group.
// This allows callers to inject user-identity-populating middleware (e.g. one
// that extracts a login cookie) without the issuer package importing web_ui.
//
// Routes are registered under /api/v1.0/issuer/ns/*namespace so that each
// federation namespace gets its own OIDC issuer with isolated clients and tokens.
func RegisterRoutesWithMiddleware(engine *gin.Engine, registry *ProviderRegistry, middleware ...gin.HandlerFunc) {
	// Combine the caller's middleware with the namespace-resolution middleware.
	allMiddleware := append(middleware, NamespaceMiddleware(registry))
	issuerGroup := engine.Group("/api/v1.0/issuer/ns", allMiddleware...)
	{
		// Gin's wildcard parameter captures everything after /ns, e.g.
		// "/data/analysis/token" → *namespace="/data/analysis/token".
		// NamespaceMiddleware resolves the provider; the dispatch handler
		// routes to the correct action based on the suffix.
		issuerGroup.POST("/*namespace", handleDispatch)
		issuerGroup.GET("/*namespace", handleDispatch)
		issuerGroup.PUT("/*namespace", handleDispatchPut)
		issuerGroup.DELETE("/*namespace", handleDispatchDelete)
	}
}

// RegisterAdminRoutes registers admin middleware for admin client-management endpoints.
// The middleware is stored on each provider and enforced in the dispatch handler
// whenever an admin/* action is requested.
func RegisterAdminRoutes(registry *ProviderRegistry, middleware ...gin.HandlerFunc) {
	for _, ns := range registry.Namespaces() {
		if p := registry.Get(ns); p != nil {
			p.SetAdminMiddleware(middleware...)
		}
	}
}

// handleDispatch is the catch-all handler for GET and POST requests.
// It determines the action from the URL suffix after the namespace prefix.
func handleDispatch(ctx *gin.Context) {
	provider := GetProvider(ctx)
	if provider == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "no provider"})
		return
	}

	action := ActionSuffix(ctx)
	// Normalize: strip leading slash
	action = strings.TrimPrefix(action, "/")

	switch {
	case action == "token" && ctx.Request.Method == http.MethodPost:
		handleToken(provider)(ctx)
	case action == "authorize":
		handleAuthorize(provider)(ctx)
	case action == "device_authorization" && ctx.Request.Method == http.MethodPost:
		handleDeviceAuthorization(provider)(ctx)
	case action == "device" && ctx.Request.Method == http.MethodGet:
		handleDeviceVerify(provider)(ctx)
	case action == "device" && ctx.Request.Method == http.MethodPost:
		handleDeviceVerifySubmit(provider)(ctx)
	case action == "userinfo" && ctx.Request.Method == http.MethodGet:
		handleUserInfo(provider)(ctx)
	case action == "revoke" && ctx.Request.Method == http.MethodPost:
		handleRevoke(provider)(ctx)
	case action == "introspect" && ctx.Request.Method == http.MethodPost:
		handleIntrospect(provider)(ctx)
	case action == "oidc-cm" && ctx.Request.Method == http.MethodPost:
		handleDynamicClientRegistration(provider)(ctx)
	case strings.HasPrefix(action, "oidc-cm/") && ctx.Request.Method == http.MethodGet:
		clientID := strings.TrimPrefix(action, "oidc-cm/")
		ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
		handleClientConfigurationRead(provider)(ctx)
	case action == ".well-known/openid-configuration":
		handleIssuerDiscovery(provider)(ctx)
	// Admin endpoints — enforce admin middleware before dispatching.
	case strings.HasPrefix(action, "admin/"):
		if !runAdminMiddleware(ctx, provider) {
			return
		}
		switch {
		case action == "admin/clients" && ctx.Request.Method == http.MethodGet:
			handleAdminListClients(provider)(ctx)
		case action == "admin/clients" && ctx.Request.Method == http.MethodPost:
			handleAdminCreateClient(provider)(ctx)
		case strings.HasPrefix(action, "admin/clients/") && ctx.Request.Method == http.MethodGet:
			clientID := strings.TrimPrefix(action, "admin/clients/")
			ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
			handleAdminGetClient(provider)(ctx)
		default:
			ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		}
	default:
		ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	}
}

// handleDispatchPut handles PUT requests for the namespace dispatch.
func handleDispatchPut(ctx *gin.Context) {
	provider := GetProvider(ctx)
	if provider == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "no provider"})
		return
	}

	action := strings.TrimPrefix(ActionSuffix(ctx), "/")

	switch {
	case strings.HasPrefix(action, "oidc-cm/"):
		clientID := strings.TrimPrefix(action, "oidc-cm/")
		ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
		handleClientConfigurationUpdate(provider)(ctx)
	case strings.HasPrefix(action, "admin/clients/"):
		if !runAdminMiddleware(ctx, provider) {
			return
		}
		clientID := strings.TrimPrefix(action, "admin/clients/")
		ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
		handleAdminUpdateClient(provider)(ctx)
	default:
		ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	}
}

// handleDispatchDelete handles DELETE requests for the namespace dispatch.
func handleDispatchDelete(ctx *gin.Context) {
	provider := GetProvider(ctx)
	if provider == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "no provider"})
		return
	}

	action := strings.TrimPrefix(ActionSuffix(ctx), "/")

	switch {
	case strings.HasPrefix(action, "oidc-cm/"):
		clientID := strings.TrimPrefix(action, "oidc-cm/")
		ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
		handleClientConfigurationDelete(provider)(ctx)
	case strings.HasPrefix(action, "admin/clients/"):
		if !runAdminMiddleware(ctx, provider) {
			return
		}
		clientID := strings.TrimPrefix(action, "admin/clients/")
		ctx.Params = append(ctx.Params, gin.Param{Key: "id", Value: clientID})
		handleAdminDeleteClient(provider)(ctx)
	default:
		ctx.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	}
}

// handleIssuerDiscovery returns the OIDC discovery document scoped to the issuer
// prefix so that the health-check in launcher.go works identically for both
// OA4MP and the embedded issuer.
func handleIssuerDiscovery(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		issuerURL := IssuerURLForNamespace(provider.Namespace)
		serviceURI := ServiceURIForNamespace(IssuerURL(), provider.Namespace)

		ctx.JSON(http.StatusOK, gin.H{
			"issuer":                        issuerURL,
			"token_endpoint":                serviceURI + "/token",
			"authorization_endpoint":        serviceURI + "/authorize",
			"userinfo_endpoint":             serviceURI + "/userinfo",
			"revocation_endpoint":           serviceURI + "/revoke",
			"introspection_endpoint":        serviceURI + "/introspect",
			"device_authorization_endpoint": serviceURI + "/device_authorization",
			"registration_endpoint":         serviceURI + "/oidc-cm",
			"jwks_uri":                      IssuerURL() + "/.well-known/issuer.jwks",
			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			},
			"scopes_supported": []string{
				"openid", "offline_access", "wlcg",
				"storage.read:/", "storage.modify:/", "storage.create:/",
			},
			"token_endpoint_auth_methods_supported": []string{
				"client_secret_basic", "client_secret_post", "none",
			},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
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

		// Handle RFC 8693 token exchange
		if grantType == tokenExchangeGrantType {
			handleTokenExchange(ctx, provider)
			return
		}

		// Handle client_credentials as a validity check ("ping").
		// RFC 7592 does not define this, but it is useful for clients to
		// verify whether their credentials are still valid.
		// - Unknown client → 401 invalid_client
		// - Known client   → 400 unauthorized_client (grant not supported)
		if grantType == "client_credentials" {
			handleClientCredentialsPing(ctx, provider)
			return
		}

		session := DefaultOIDCSession("", IssuerURLForNamespace(provider.Namespace), nil, nil)

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

		// Update last_used_at on refresh so the client doesn't age out
		// while it is actively refreshing tokens.
		if grantType == "refresh_token" {
			_ = provider.storage.TouchClientLastUsed(rCtx, ar.GetClient().GetID())
		}

		provider.Provider().WriteAccessResponse(rCtx, w, ar, response)
	}
}

// handleClientCredentialsPing handles the client_credentials grant type as a
// client validity probe. This issuer does not support client_credentials as a
// real grant, but the endpoint authenticates the client and returns a
// distinguishable error:
//   - 401 invalid_client  → client_id/secret not recognised
//   - 400 unauthorized_client → client exists but the grant is not supported
//
// Clients can use this to test whether their credentials are still valid
// without needing a user-interactive flow.
func handleClientCredentialsPing(ctx *gin.Context, provider *OIDCProvider) {
	r := ctx.Request

	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		ctx.Header("WWW-Authenticate", "Basic")
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed: no client credentials provided",
		})
		return
	}

	client, err := provider.Storage().GetClient(ctx, clientID)
	if err != nil {
		ctx.Header("WWW-Authenticate", "Basic")
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed: unknown client",
		})
		return
	}

	// Validate the secret (public clients don't need one)
	if !client.IsPublic() {
		storedHash := client.GetHashedSecret()
		if err := bcrypt.CompareHashAndPassword(storedHash, []byte(clientSecret)); err != nil {
			ctx.Header("WWW-Authenticate", "Basic")
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication failed: invalid client secret",
			})
			return
		}
	}

	// Client is authenticated but the grant type is not supported.
	ctx.JSON(http.StatusBadRequest, gin.H{
		"error":             "unauthorized_client",
		"error_description": "The client_credentials grant type is not supported by this issuer",
	})
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

		// Calculate allowed scopes for this user using per-namespace rules
		// when available, falling back to the global rules.
		var allowedScopes []string
		var matchedGroups []string
		if len(provider.AuthzRules) > 0 {
			allowedScopes, matchedGroups = oa4mp.CalculateAllowedScopesWithRules(provider.AuthzRules, user, userID, groups)
		} else {
			allowedScopes, matchedGroups = oa4mp.CalculateAllowedScopes(user, userID, groups)
		}
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
			scope = cleanScopePath(scope)
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

		// Grant the WLCG wildcard audience so that caches (and any
		// other WLCG service) accept the resulting token.
		ar.GrantAudience(WLCGAudienceAny)

		issuerURL := IssuerURLForNamespace(provider.Namespace)
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

		// Verify client secret (public clients don't need one)
		dc := client.(*fosite.DefaultClient)
		if !dc.Public {
			if err := bcrypt.CompareHashAndPassword(dc.Secret, []byte(clientSecret)); err != nil {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Invalid client credentials"})
				return
			}
		}

		// Verify client is authorized for the device_code grant type
		hasDeviceGrant := false
		for _, gt := range dc.GrantTypes {
			if gt == "urn:ietf:params:oauth:grant-type:device_code" {
				hasDeviceGrant = true
				break
			}
		}
		if !hasDeviceGrant {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":             "unauthorized_client",
				"error_description": "This client is not authorized for the device_code grant type",
			})
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

		// Override the verification URIs to point to the Next.js UI page
		// instead of the API endpoint.
		baseURL := param.Server_ExternalWebUrl.GetString()
		viewBase := baseURL + "/view/issuer/device?namespace=" + url.QueryEscape(provider.Namespace)
		resp.VerificationURI = viewBase
		resp.VerificationURIComplete = viewBase + "&user_code=" + url.QueryEscape(resp.UserCode)

		ctx.JSON(http.StatusOK, resp)
	}
}

// handleDeviceVerify redirects the browser to the Next.js device verification page.
// The actual UI is served by the frontend; this API endpoint only generates a
// CSRF token and redirects.
func handleDeviceVerify(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := ctx.GetString("User")
		if user == "" {
			// Redirect to login, but point nextUrl at the Next.js page.
			viewURL := deviceViewURL(provider.Namespace, ctx.Query("user_code"))
			redirUrl := url.URL{
				Path:     "/view/login",
				RawQuery: "returnURL=" + url.QueryEscape(viewURL),
			}
			ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
			ctx.Abort()
			return
		}

		// Generate CSRF token and set it in a cookie scoped to the API path.
		csrfToken, err := generateSecureToken(32)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
			return
		}
		ctx.SetCookie("csrf_token", csrfToken, 600, "/api/v1.0/issuer/ns"+provider.Namespace+"/device", "", true, true)

		resp := gin.H{
			"csrf_token": csrfToken,
			"namespace":  provider.Namespace,
		}

		// If user_code is provided, look up the device code session so we
		// can show the requested scopes and client info on the consent page.
		if userCode := ctx.Query("user_code"); userCode != "" {
			userCode = strings.ToUpper(strings.TrimSpace(userCode))
			if dc, err := provider.Storage().GetDeviceCodeSessionByUserCode(ctx, userCode); err == nil {
				var scopes []string
				if jsonErr := json.Unmarshal([]byte(dc.Scopes), &scopes); jsonErr == nil {
					resp["scopes"] = scopes
				}
				resp["client_id"] = dc.ClientID
				if rec, err := provider.Storage().GetClientRecord(ctx, dc.ClientID); err == nil && rec.ClientName != "" {
					resp["client_name"] = rec.ClientName
				}
			}
		}

		ctx.JSON(http.StatusOK, resp)
	}
}

// handleDeviceVerifySubmit processes the device code verification submission (POST).
// It accepts either form-encoded or JSON request bodies and always returns JSON.
func handleDeviceVerifySubmit(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := ctx.GetString("User")
		if user == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": "error", "error": "Not authenticated"})
			ctx.Abort()
			return
		}

		// Accept CSRF token from form data or JSON body
		var userCode, action, csrfForm string
		if strings.Contains(ctx.GetHeader("Content-Type"), "application/json") {
			var body struct {
				UserCode  string `json:"user_code"`
				Action    string `json:"action"`
				CSRFToken string `json:"csrf_token"`
			}
			if err := ctx.ShouldBindJSON(&body); err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Invalid request body"})
				return
			}
			userCode = body.UserCode
			action = body.Action
			csrfForm = body.CSRFToken
		} else {
			userCode = ctx.PostForm("user_code")
			action = ctx.PostForm("action")
			csrfForm = ctx.PostForm("csrf_token")
		}

		// Validate CSRF token
		csrfCookie, err := ctx.Cookie("csrf_token")
		if err != nil || csrfCookie == "" || csrfForm == "" || csrfCookie != csrfForm {
			ctx.JSON(http.StatusForbidden, gin.H{"status": "error", "error": "CSRF validation failed"})
			return
		}
		// Clear the CSRF cookie after validation
		ctx.SetCookie("csrf_token", "", -1, "/api/v1.0/issuer/ns"+provider.Namespace+"/device", "", true, true)

		userID := ctx.GetString("UserId")
		groups := ctx.GetStringSlice("Groups")

		if userCode == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "No user code provided"})
			return
		}

		// Normalize user code
		userCode = strings.ToUpper(strings.TrimSpace(userCode))

		if action == "deny" {
			if err := provider.Storage().DenyDeviceCodeSession(ctx, userCode); err != nil {
				log.WithError(err).Warn("Embedded issuer: failed to deny device code")
			}
			ctx.JSON(http.StatusOK, gin.H{"status": "denied"})
			return
		}

		// Look up the device code
		dc, err := provider.Storage().GetDeviceCodeSessionByUserCode(ctx, userCode)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Invalid or expired user code"})
			return
		}

		if dc.Status != "pending" {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "This code has already been used"})
			return
		}

		if time.Now().After(dc.ExpiresAt) {
			ctx.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "This code has expired"})
			return
		}

		// For dynamically registered clients, enforce single-user binding.
		// The first user to approve a device code for this client becomes the
		// only user who can ever use it.  For statically registered clients
		// BindClientToUser is a no-op.
		if err := provider.Storage().BindClientToUser(ctx, dc.ClientID, user); err != nil {
			log.WithError(err).Warnf("Embedded issuer: user %s cannot use client %s (bound to different user)", user, dc.ClientID)
			ctx.JSON(http.StatusForbidden, gin.H{"status": "error", "error": "This client is registered to a different user"})
			return
		}

		// Calculate allowed scopes using per-namespace rules when available
		var allowedScopes []string
		var matchedGroups []string
		if len(provider.AuthzRules) > 0 {
			allowedScopes, matchedGroups = oa4mp.CalculateAllowedScopesWithRules(provider.AuthzRules, user, userID, groups)
		} else {
			allowedScopes, matchedGroups = oa4mp.CalculateAllowedScopes(user, userID, groups)
		}
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
			scope = cleanScopePath(scope)
			if isStandardScope(scope) || scopeAllowed(scope, allowedScopes) {
				grantedScopes = append(grantedScopes, scope)
			} else {
				grantedScopes = append(grantedScopes, collectNarrowerScopes(scope, allowedScopes)...)
			}
		}

		// Also enforce the client's configured scope allow-list: a device
		// client limited to certain scopes must not obtain broader scopes
		// even if the user's authorization rules would permit them.
		clientObj, clientErr := provider.Storage().GetClient(ctx, dc.ClientID)
		if clientErr != nil {
			log.WithError(clientErr).Warn("Embedded issuer: failed to load client for scope filtering")
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "Failed to load client"})
			return
		}
		clientScopes := clientObj.GetScopes()
		filteredScopes := make([]string, 0, len(grantedScopes))
		for _, scope := range grantedScopes {
			if scopeAllowed(scope, clientScopes) {
				filteredScopes = append(filteredScopes, scope)
			}
		}
		grantedScopes = filteredScopes

		issuerURL := IssuerURLForNamespace(provider.Namespace)
		session := DefaultOIDCSession(user, issuerURL, matchedGroups, grantedScopes)
		sessionData, _ := json.Marshal(session)

		if err := provider.Storage().ApproveDeviceCodeSession(ctx, userCode, user, grantedScopes, sessionData); err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to approve device code")
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "Failed to approve device code"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"status": "approved"})
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
	if !dc.Public {
		if err := bcrypt.CompareHashAndPassword(dc.Secret, []byte(clientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	// Verify client is authorized for the device_code grant type
	hasDeviceGrant := false
	for _, gt := range dc.GrantTypes {
		if gt == "urn:ietf:params:oauth:grant-type:device_code" {
			hasDeviceGrant = true
			break
		}
	}
	if !hasDeviceGrant {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "This client is not authorized for the device_code grant type",
		})
		return
	}

	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device_code required"})
		return
	}

	issuerURL := IssuerURLForNamespace(provider.Namespace)
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

	// Verify the device code was issued to the requesting client.
	// This prevents cross-client device code redemption where a different
	// client learns the device_code and redeems it.
	if request.GetClient().GetID() != clientID {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "The device code was issued to a different client",
		})
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

	// Grant the WLCG wildcard audience so that caches (and any
	// other WLCG service) accept the resulting token.
	ar.GrantAudience(WLCGAudienceAny)

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

	// Generate refresh token if offline_access was requested AND the client
	// is authorized for the refresh_token grant type. Without this check,
	// operators who omit "refresh_token" from grant_types cannot prevent
	// long-lived sessions.
	hasRefreshGrant := false
	for _, gt := range dc.GrantTypes {
		if gt == "refresh_token" {
			hasRefreshGrant = true
			break
		}
	}
	if hasRefreshGrant {
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
	}

	// Mark the device code as used after both access and refresh tokens
	// have been generated successfully. This prevents burning the code
	// if refresh token generation had failed above.
	_ = provider.storage.InvalidateDeviceCodeSession(rCtx, deviceCode)

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
		issuerURL := IssuerURLForNamespace(provider.Namespace)
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

		issuerURL := IssuerURLForNamespace(provider.Namespace)
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

// isLoopbackURI returns true if the parsed URL points to a loopback address
// (localhost, 127.0.0.1, or [::1]) per RFC 8252 §7.3.
func isLoopbackURI(u *url.URL) bool {
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// validateDynamicRedirectURIs checks that the supplied redirect URIs comply
// with the server's policy for dynamically registered clients:
//   - If Issuer.RedirectUris is configured, every URI must appear in that list.
//   - Otherwise, only loopback URIs (RFC 8252 §7.3) are allowed.
//
// Returns (offendingURI, reason) on failure, or ("", "") on success.
func validateDynamicRedirectURIs(uris []string) (string, string) {
	if len(uris) > maxRedirectURIs {
		return "<too many>", "Too many redirect_uris; maximum is 10"
	}
	for _, uri := range uris {
		if len(uri) > maxRedirectURILen {
			return uri[:64] + "...", "redirect_uri too long; maximum length is 2048 bytes"
		}
	}
	allowedURIs := param.Issuer_RedirectUris.GetStringSlice()
	if len(allowedURIs) > 0 {
		allowedSet := make(map[string]bool, len(allowedURIs))
		for _, uri := range allowedURIs {
			allowedSet[uri] = true
		}
		for _, uri := range uris {
			if !allowedSet[uri] {
				return uri, "Unregistered redirect_uri: " + uri
			}
		}
	} else {
		for _, uri := range uris {
			parsed, pErr := url.Parse(uri)
			if pErr != nil || !isLoopbackURI(parsed) {
				return uri, "Only loopback redirect URIs are allowed for dynamic clients when Issuer.RedirectUris is not configured"
			}
		}
	}
	return "", ""
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
		// Use the shared registry-level rate limiter to prevent attackers
		// from multiplying the per-IP limit by cycling through namespaces.
		clientIP := ctx.ClientIP()
		registry := GetRegistry(ctx)
		if registry != nil && !registry.RegistrationLimiter.Allow(clientIP) {
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many client registrations from this address; try again later",
			})
			return
		} else if registry == nil && !provider.RegistrationLimiter.Allow(clientIP) {
			// Fallback to per-provider limiter if registry is not in context
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

		if len(req.ClientName) > maxClientNameLen {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client_metadata",
				"error_description": "client_name too long; maximum length is 128 bytes",
			})
			return
		}

		// Validate redirect URIs against server policy.
		if badURI, reason := validateDynamicRedirectURIs(req.RedirectURIs); badURI != "" {
			ctx.JSON(http.StatusForbidden, gin.H{
				"error":             "invalid_redirect_uri",
				"error_description": reason,
			})
			return
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

		// Generate a registration access token (RFC 7592) so the client
		// can manage its own registration after creation.
		registrationAccessToken, err := generateSecureToken(32)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		hashedRAT, err := bcrypt.GenerateFromPassword([]byte(registrationAccessToken), bcrypt.DefaultCost)
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
			Audience:      fosite.Arguments{WLCGAudienceAny},
			Public:        false,
		}

		if err := provider.Storage().CreateDynamicClient(ctx, client, clientIP, hashedRAT, req.ClientName); err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to register client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		// Build the client configuration URI (RFC 7592 §3)
		serviceURI := ServiceURIForNamespace(IssuerURL(), provider.Namespace)
		registrationClientURI := serviceURI + "/oidc-cm/" + clientID

		ctx.JSON(http.StatusCreated, gin.H{
			"client_id":                 clientID,
			"client_secret":             clientSecret,
			"client_name":               req.ClientName,
			"redirect_uris":             req.RedirectURIs,
			"grant_types":               grantTypes,
			"response_types":            responseTypes,
			"scope":                     strings.Join(scopes, " "),
			"client_secret_expires_at":  0,
			"registration_access_token": registrationAccessToken,
			"registration_client_uri":   registrationClientURI,
		})
	}
}

// ---- RFC 7592: Client Configuration Endpoint ----

// extractRegistrationAccessToken extracts the Bearer token from the Authorization header.
func extractRegistrationAccessToken(ctx *gin.Context) string {
	auth := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// handleClientConfigurationRead implements GET on the client configuration
// endpoint (RFC 7592 §2.1). The client presents its registration access token
// and receives its current metadata.
func handleClientConfigurationRead(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")
		rat := extractRegistrationAccessToken(ctx)
		if rat == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Missing registration access token"})
			return
		}

		record, err := provider.Storage().ValidateRegistrationAccessToken(ctx, clientID, rat)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Invalid registration access token"})
			return
		}

		var redirectURIs []string
		var grantTypes []string
		var responseTypes []string
		var scopes []string
		_ = json.Unmarshal([]byte(record.RedirectURIs), &redirectURIs)
		_ = json.Unmarshal([]byte(record.GrantTypes), &grantTypes)
		_ = json.Unmarshal([]byte(record.ResponseTypes), &responseTypes)
		_ = json.Unmarshal([]byte(record.Scopes), &scopes)

		ctx.JSON(http.StatusOK, gin.H{
			"client_id":                clientID,
			"client_name":              record.ClientName,
			"redirect_uris":            redirectURIs,
			"grant_types":              grantTypes,
			"response_types":           responseTypes,
			"scope":                    strings.Join(scopes, " "),
			"client_secret_expires_at": 0,
			"registration_client_uri":  ServiceURIForNamespace(IssuerURL(), provider.Namespace) + "/oidc-cm/" + clientID,
		})
	}
}

// handleClientConfigurationUpdate implements PUT on the client configuration
// endpoint (RFC 7592 §2.2). Dynamically registered clients can update their
// redirect_uris and client_name.
func handleClientConfigurationUpdate(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")
		rat := extractRegistrationAccessToken(ctx)
		if rat == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Missing registration access token"})
			return
		}

		record, err := provider.Storage().ValidateRegistrationAccessToken(ctx, clientID, rat)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Invalid registration access token"})
			return
		}

		if !record.DynamicallyRegistered {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "invalid_request", "error_description": "Only dynamically registered clients may be updated via this endpoint"})
			return
		}

		var req struct {
			RedirectURIs *[]string `json:"redirect_uris"`
			ClientName   *string   `json:"client_name"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
			return
		}

		updates := make(map[string]interface{})

		if req.ClientName != nil && len(*req.ClientName) > maxClientNameLen {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client_metadata",
				"error_description": "client_name too long; maximum length is 128 bytes",
			})
			return
		}

		if req.RedirectURIs != nil {
			if badURI, reason := validateDynamicRedirectURIs(*req.RedirectURIs); badURI != "" {
				ctx.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_redirect_uri",
					"error_description": reason,
				})
				return
			}
			redirectJSON, _ := json.Marshal(*req.RedirectURIs)
			updates["redirect_uris"] = string(redirectJSON)
		}
		if req.ClientName != nil {
			updates["client_name"] = *req.ClientName
		}

		if len(updates) > 0 {
			if err := provider.Storage().UpdateDynamicClient(ctx, clientID, updates); err != nil {
				log.WithError(err).Warn("Embedded issuer: failed to update dynamic client")
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
		}

		// Re-read and return updated metadata
		updated, err := provider.Storage().GetClientRecord(ctx, clientID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		var redirectURIs []string
		var grantTypes []string
		var responseTypes []string
		var scopes []string
		_ = json.Unmarshal([]byte(updated.RedirectURIs), &redirectURIs)
		_ = json.Unmarshal([]byte(updated.GrantTypes), &grantTypes)
		_ = json.Unmarshal([]byte(updated.ResponseTypes), &responseTypes)
		_ = json.Unmarshal([]byte(updated.Scopes), &scopes)

		ctx.JSON(http.StatusOK, gin.H{
			"client_id":                clientID,
			"client_name":              updated.ClientName,
			"redirect_uris":            redirectURIs,
			"grant_types":              grantTypes,
			"response_types":           responseTypes,
			"scope":                    strings.Join(scopes, " "),
			"client_secret_expires_at": 0,
			"registration_client_uri":  ServiceURIForNamespace(IssuerURL(), provider.Namespace) + "/oidc-cm/" + clientID,
		})
	}
}

// handleClientConfigurationDelete implements DELETE on the client configuration
// endpoint (RFC 7592 §2.3). A dynamically registered client can delete itself.
func handleClientConfigurationDelete(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		clientID := ctx.Param("id")
		rat := extractRegistrationAccessToken(ctx)
		if rat == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Missing registration access token"})
			return
		}

		record, err := provider.Storage().ValidateRegistrationAccessToken(ctx, clientID, rat)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Invalid registration access token"})
			return
		}

		if !record.DynamicallyRegistered {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "invalid_request", "error_description": "Only dynamically registered clients may be deleted via this endpoint"})
			return
		}

		deleted, err := provider.Storage().DeleteClient(ctx, clientID)
		if err != nil || !deleted {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		log.Infof("Embedded issuer: client %s deleted via RFC 7592", clientID)
		ctx.Status(http.StatusNoContent)
	}
}

// renderDeviceResult renders the appropriate device flow result page.
// deviceViewURL returns the Next.js device verification page URL for the given namespace.
func deviceViewURL(namespace, userCode string) string {
	u := "/view/issuer/device?namespace=" + url.QueryEscape(namespace)
	if userCode != "" {
		u += "&user_code=" + url.QueryEscape(userCode)
	}
	return u
}

// Helpers

// runAdminMiddleware executes the provider's admin middleware chain.
// Returns true if the request should proceed, false if middleware aborted it.
func runAdminMiddleware(ctx *gin.Context, provider *OIDCProvider) bool {
	if len(provider.adminMiddleware) == 0 {
		ctx.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "Admin endpoints are not available (no admin middleware configured)",
		})
		return false
	}
	for _, mw := range provider.adminMiddleware {
		mw(ctx)
		if ctx.IsAborted() {
			return false
		}
	}
	return true
}

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
