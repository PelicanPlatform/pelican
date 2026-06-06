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

package transfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
)

// AuthMethodsResponse describes what credential acquisition flows the transfer
// server supports for a given issuer.
type AuthMethodsResponse struct {
	Issuer  string   `json:"issuer"`
	Methods []string `json:"methods"`
}

// TokenExchangeBootstrapRequest is the body for bootstrapping a credential
// via the RFC 8693 token-exchange flow.
type TokenExchangeBootstrapRequest struct {
	// SubjectToken is the token the user obtained (e.g. via device-code
	// flow) from the issuer.
	SubjectToken string `json:"subject_token" binding:"required"`
	// IssuerURL identifies the OAuth2 issuer that minted the subject token.
	IssuerURL string `json:"issuer_url" binding:"required"`
	// Name is a human-readable label for the resulting credential.
	Name string `json:"name" binding:"required"`
	// Scopes is an optional space-separated list of scopes to request
	// on the exchanged token. If provided, the issuer computes the
	// intersection of these scopes with the subject token's grants.
	Scopes string `json:"scopes,omitempty"`
}

// AuthCodeBootstrapRequest starts an authorization-code credential bootstrap session.
type AuthCodeBootstrapRequest struct {
	// IssuerURL identifies the OAuth2 issuer for the authorization code flow.
	IssuerURL string `json:"issuer_url" binding:"required"`
	// Name is a human-readable label for the resulting credential.
	Name string `json:"name" binding:"required"`
	// Scopes is an optional space-separated list of scopes to request.
	// If empty, defaults to "offline_access".
	Scopes string `json:"scopes,omitempty"`
}

// AuthCodeBootstrapResponse is returned when a new auth-code session is created.
type AuthCodeBootstrapResponse struct {
	// SessionID is a unique identifier for this bootstrap session.
	SessionID string `json:"session_id"`
	// AuthorizationURL is the URL the user should visit to authorize.
	AuthorizationURL string `json:"authorization_url"`
}

// AuthCodeBootstrapStatus is returned when polling for an auth-code session.
type AuthCodeBootstrapStatus struct {
	SessionID    string              `json:"session_id"`
	Status       string              `json:"status"` // "pending", "complete", "error"
	CredentialID string              `json:"credential_id,omitempty"`
	Error        string              `json:"error,omitempty"`
	Credential   *CredentialResponse `json:"credential,omitempty"`
}

// bootstrapSession tracks an in-flight authorization-code bootstrap session.
type bootstrapSession struct {
	SessionID string
	Owner     ownerIdentity
	IssuerURL string
	Name      string
	Scopes    string // space-separated scopes requested by the user
	StartCode string // opaque code for the short redirect URL (separate from SessionID)
	AuthURL   string // full issuer authorization URL (stored so the start redirect can use it)
	State     string // CSRF state parameter
	Status    string // "pending", "complete", "error"
	CredID    string
	Error     string
	CreatedAt time.Time
}

// bootstrapSessionStore is a simple in-memory store for active bootstrap sessions.
// Sessions are short-lived (a few minutes) and don't need persistence.
type bootstrapSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*bootstrapSession
}

var globalBootstrapStore = &bootstrapSessionStore{
	sessions: make(map[string]*bootstrapSession),
}

// issuerMetadataCache provides a TTL cache for OIDC issuer metadata to avoid
// fetching .well-known/openid-configuration on every request.
type issuerMetadataCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedIssuerMetadata
}

type cachedIssuerMetadata struct {
	metadata  *config.OauthIssuer
	expiresAt time.Time
}

var globalIssuerCache = &issuerMetadataCache{
	entries: make(map[string]*cachedIssuerMetadata),
}

const issuerCacheTTL = 5 * time.Minute

// callbackStatePrefix is prepended to the OAuth2 state parameter so the
// shared /api/callback dispatcher can route the response to the transfer
// bootstrap handler.
const callbackStatePrefix = "xfer:"

// SharedCallbackPath is the unified OAuth2 callback endpoint that multiple
// modules can share. The state parameter's prefix determines which handler
// processes the callback.
const SharedCallbackPath = "/api/callback"

func (c *issuerMetadataCache) get(issuerURL string) (*config.OauthIssuer, error) {
	c.mu.RLock()
	entry, ok := c.entries[issuerURL]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.metadata, nil
	}

	meta, err := config.GetIssuerMetadata(issuerURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.entries[issuerURL] = &cachedIssuerMetadata{
		metadata:  meta,
		expiresAt: time.Now().Add(issuerCacheTTL),
	}
	c.mu.Unlock()

	return meta, nil
}

func (s *bootstrapSessionStore) put(session *bootstrapSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = session
}

func (s *bootstrapSessionStore) get(sessionID string) (*bootstrapSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	return sess, ok
}

func (s *bootstrapSessionStore) getByState(state string) (*bootstrapSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.State == state {
			return sess, true
		}
	}
	return nil, false
}

func (s *bootstrapSessionStore) getByStartCode(code string) (*bootstrapSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.StartCode == code {
			return sess, true
		}
	}
	return nil, false
}

func (s *bootstrapSessionStore) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// cleanupExpiredSessions removes sessions older than 10 minutes.
func (s *bootstrapSessionStore) cleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for id, sess := range s.sessions {
		if sess.CreatedAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

// generateState creates a random state parameter for OAuth2 CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateStartCode creates a random opaque code for the short redirect URL.
// This is deliberately separate from the session ID so that someone with
// access to the user's terminal output cannot use it to poll for the
// credential result.
func generateStartCode() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// findOAuthClientForGrant looks up an OAuth client registered for the given
// issuer that supports the specified grant type. When requestedScopes is
// non-empty, clients whose scopes column covers all requested scopes are
// preferred. Clients with no scope information are returned as a fallback,
// sorted after those with known matching scopes.
func findOAuthClientForGrant(db *gorm.DB, issuerURL, requiredGrant string, requestedScopes []string) (*TransferOAuthClient, error) {
	var clients []TransferOAuthClient
	if err := db.Where("issuer_url = ?", issuerURL).Find(&clients).Error; err != nil {
		return nil, err
	}

	var withScopes, withoutScopes []*TransferOAuthClient
	for i := range clients {
		hasGrant := false
		for _, gt := range strings.Fields(clients[i].GrantTypes) {
			if gt == requiredGrant {
				hasGrant = true
				break
			}
		}
		if !hasGrant {
			continue
		}

		if clients[i].Scopes == "" {
			withoutScopes = append(withoutScopes, &clients[i])
			continue
		}

		// If we have requested scopes, check coverage
		if len(requestedScopes) > 0 {
			clientScopes := strings.Fields(clients[i].Scopes)
			if scopesContainAll(clientScopes, requestedScopes) {
				withScopes = append(withScopes, &clients[i])
			}
		} else {
			// No requested scopes — prefer clients with known scopes
			withScopes = append(withScopes, &clients[i])
		}
	}

	// Prefer clients with matching/known scopes over those without
	if len(withScopes) > 0 {
		return withScopes[0], nil
	}
	if len(withoutScopes) > 0 {
		return withoutScopes[0], nil
	}
	return nil, gorm.ErrRecordNotFound
}

// scopesContainAll returns true if the haystack set contains every scope in needles.
func scopesContainAll(haystack, needles []string) bool {
	set := make(map[string]struct{}, len(haystack))
	for _, s := range haystack {
		set[s] = struct{}{}
	}
	for _, s := range needles {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// handleGetAuthMethods handles GET /api/v1.0/transfer/auth-methods
// This endpoint is intentionally unauthenticated so the CLI can discover
// supported flows before authenticating.
func handleGetAuthMethods(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		issuerURL := c.Query("issuer")
		if issuerURL == "" {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "issuer query parameter is required",
			})
			return
		}

		// Query issuer OIDC metadata to see what grant types it supports
		issuerMeta, err := globalIssuerCache.get(issuerURL)
		if err != nil {
			log.Debugf("Failed to get issuer metadata for %s: %v", issuerURL, err)
			c.JSON(http.StatusBadGateway, ErrorResponse{
				Code:  "ISSUER_UNREACHABLE",
				Error: "Failed to retrieve issuer metadata: " + err.Error(),
			})
			return
		}

		var methods []string

		// token_exchange is supported if the issuer supports it and we have a
		// registered client with that grant type
		for _, gt := range issuerMeta.GrantTypes {
			if gt == "urn:ietf:params:oauth:grant-type:token-exchange" {
				if _, err := findOAuthClientForGrant(db, issuerURL, gt, nil); err == nil {
					methods = append(methods, "token_exchange")
				}
				break
			}
		}

		// authorization_code is supported if the issuer has an auth endpoint
		// and we have a registered client with that grant type
		if issuerMeta.AuthURL != "" {
			if _, err := findOAuthClientForGrant(db, issuerURL, "authorization_code", nil); err == nil {
				methods = append(methods, "authorization_code")
			}
		}

		// device_code is always available (the CLI can register directly with
		// the issuer) and is the fallback
		if issuerMeta.DeviceAuthURL != "" {
			methods = append(methods, "device_code")
		}

		c.JSON(http.StatusOK, AuthMethodsResponse{
			Issuer:  issuerURL,
			Methods: methods,
		})
	}
}

// handleTokenExchangeBootstrap handles POST /api/v1.0/transfer/credentials/bootstrap/token-exchange
// The user has already obtained a subject_token from the issuer and sends
// it here; the transfer server exchanges it via the issuer's token endpoint
// using its registered OAuth client and creates a credential.
func handleTokenExchangeBootstrap(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var req TokenExchangeBootstrapRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Invalid request body: " + err.Error(),
			})
			return
		}

		// Find an OAuth client for this issuer that supports token exchange.
		// Use the requested scopes (if any) for scope-aware matching.
		requestedScopes := strings.Fields(req.Scopes)
		oauthClient, err := findOAuthClientForGrant(db, req.IssuerURL, "urn:ietf:params:oauth:grant-type:token-exchange", requestedScopes)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusBadRequest, ErrorResponse{
					Code:  "NO_OAUTH_CLIENT",
					Error: "No OAuth client registered for issuer: " + req.IssuerURL,
				})
			} else {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Code:  "INTERNAL",
					Error: "Failed to look up OAuth client",
				})
			}
			return
		}

		// Decrypt the client credentials
		clientID, err := decryptSecret(oauthClient.EncryptedClientID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to decrypt client credentials",
			})
			return
		}
		clientSecret, err := decryptSecret(oauthClient.EncryptedClientSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to decrypt client credentials",
			})
			return
		}

		// Get the issuer token endpoint
		issuerMeta, err := globalIssuerCache.get(req.IssuerURL)
		if err != nil {
			c.JSON(http.StatusBadGateway, ErrorResponse{
				Code:  "ISSUER_UNREACHABLE",
				Error: "Failed to retrieve issuer metadata",
			})
			return
		}

		// Perform RFC 8693 token exchange
		// Inject the Pelican HTTP transport so the exchange uses the server's TLS config.
		tokenExchangeCtx := context.WithValue(c.Request.Context(), pelican_oauth2.HTTPClient, &http.Client{
			Transport: config.GetTransport(),
		})
		exchangedToken, err := performTokenExchange(tokenExchangeCtx, issuerMeta.TokenURL, clientID, clientSecret, req.SubjectToken, req.Scopes)
		if err != nil {
			log.Errorf("Token exchange failed for issuer %s: %v", req.IssuerURL, err)
			c.JSON(http.StatusBadGateway, ErrorResponse{
				Code:  "TOKEN_EXCHANGE_FAILED",
				Error: "Token exchange with issuer failed: " + err.Error(),
			})
			return
		}

		// Create the credential. Determine the effective scopes: use the
		// client's registered scopes if available, else the request scopes.
		credScopes := req.Scopes
		if oauthClient.Scopes != "" {
			credScopes = oauthClient.Scopes
		}

		cred, err := createCredentialFromToken(db, owner, req.Name, req.IssuerURL,
			exchangedToken.AccessToken, exchangedToken.RefreshToken, credScopes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to store credential: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusCreated, credentialToResponse(cred))
	}
}

// handleAuthCodeBootstrapStart handles POST /api/v1.0/transfer/credentials/bootstrap/authcode
// It initiates an authorization code flow: generates a short URL the user can
// visit (which the server then redirects to the full issuer authorization URL).
// The session ID is returned for polling but is NOT embedded in the short URL,
// preventing someone with terminal access from stealing it.
func handleAuthCodeBootstrapStart(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var req AuthCodeBootstrapRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Invalid request body: " + err.Error(),
			})
			return
		}

		// Find an OAuth client for this issuer that supports authorization_code
		requestedScopes := strings.Fields(req.Scopes)
		oauthClient, err := findOAuthClientForGrant(db, req.IssuerURL, "authorization_code", requestedScopes)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusBadRequest, ErrorResponse{
					Code:  "NO_OAUTH_CLIENT",
					Error: "No OAuth client registered for issuer: " + req.IssuerURL,
				})
			} else {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Code:  "INTERNAL",
					Error: "Failed to look up OAuth client",
				})
			}
			return
		}

		clientID, err := decryptSecret(oauthClient.EncryptedClientID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to decrypt client credentials",
			})
			return
		}

		issuerMeta, err := globalIssuerCache.get(req.IssuerURL)
		if err != nil {
			c.JSON(http.StatusBadGateway, ErrorResponse{
				Code:  "ISSUER_UNREACHABLE",
				Error: "Failed to retrieve issuer metadata",
			})
			return
		}

		state, err := generateState()
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to generate CSRF state",
			})
			return
		}

		startCode, err := generateStartCode()
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to generate start code",
			})
			return
		}

		// Use the requested scopes, or fall back to offline_access
		scopes := req.Scopes
		if scopes == "" {
			scopes = "offline_access"
		}

		// Build the full issuer authorization URL (stored in session for the
		// start-redirect handler to use).
		serverBase := param.Server_ExternalWebUrl.GetString()
		redirectURI := serverBase + SharedCallbackPath

		authURL, err := url.Parse(issuerMeta.AuthURL)
		if err != nil {
			c.JSON(http.StatusBadGateway, ErrorResponse{
				Code:  "ISSUER_UNREACHABLE",
				Error: "Invalid authorization endpoint in issuer metadata",
			})
			return
		}
		q := authURL.Query()
		q.Set("response_type", "code")
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		// Prefix the state so the shared /api/callback dispatcher routes it here
		q.Set("state", callbackStatePrefix+state)
		q.Set("scope", scopes)
		authURL.RawQuery = q.Encode()

		sessionID := uuid.New().String()
		session := &bootstrapSession{
			SessionID: sessionID,
			Owner:     owner,
			IssuerURL: req.IssuerURL,
			Name:      req.Name,
			Scopes:    scopes,
			StartCode: startCode,
			AuthURL:   authURL.String(),
			State:     state,
			Status:    "pending",
			CreatedAt: time.Now(),
		}
		globalBootstrapStore.put(session)

		// Return a short URL that the server will redirect to the issuer.
		// This avoids exposing the full issuer URL (with meta-characters) in
		// the terminal and does NOT contain the session ID.
		shortURL := serverBase + SharedCallbackPath + "/start/" + startCode

		c.JSON(http.StatusOK, AuthCodeBootstrapResponse{
			SessionID:        sessionID,
			AuthorizationURL: shortURL,
		})
	}
}

// redirectToBootstrapResult redirects the user's browser to the Next.js page
// that displays the bootstrap flow result.
func redirectToBootstrapResult(c *gin.Context, status, message string) {
	serverBase := param.Server_ExternalWebUrl.GetString()
	destURL, _ := url.Parse(serverBase + "/transfer/bootstrap/callback")
	q := destURL.Query()
	q.Set("status", status)
	if message != "" {
		q.Set("message", message)
	}
	destURL.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, destURL.String())
}

// handleStartRedirect handles GET /api/callback/start/:code
// When the CLI initiates an auth-code bootstrap, it receives a short URL
// containing an opaque start code (not the session ID). The user visits this
// URL in a browser, and the server redirects to the full issuer authorization
// URL stored in the session.
func handleStartRedirect() gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Param("code")
		sess, ok := globalBootstrapStore.getByStartCode(code)
		if !ok || sess.Status != "pending" {
			redirectToBootstrapResult(c, "error", "Unknown or expired bootstrap session")
			return
		}
		c.Redirect(http.StatusFound, sess.AuthURL)
	}
}

// HandleSharedCallback handles GET /api/callback
// This is a unified OAuth2 callback endpoint shared across modules. Each
// module encodes a prefix in the state parameter to identify itself. For
// transfer bootstrap callbacks the prefix is "xfer:".
func HandleSharedCallback(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		state := c.Query("state")

		if strings.HasPrefix(state, callbackStatePrefix) {
			actualState := strings.TrimPrefix(state, callbackStatePrefix)
			processAuthCodeCallback(c, db, actualState)
			return
		}

		// Unknown state prefix — no handler registered for it
		redirectToBootstrapResult(c, "error", "Unknown callback type")
	}
}

// processAuthCodeCallback is the internal implementation of the auth-code
// bootstrap callback. It is called by the shared /api/callback dispatcher
// after stripping the state prefix.
func processAuthCodeCallback(c *gin.Context, db *gorm.DB, state string) {
	code := c.Query("code")

	if state == "" || code == "" {
		// Check for error response from the issuer
		errCode := c.Query("error")
		errDesc := c.DefaultQuery("error_description", "Authorization was denied")
		if errCode != "" && state != "" {
			if sess, ok := globalBootstrapStore.getByState(state); ok {
				sess.Status = "error"
				sess.Error = errDesc
			}
		}
		if errCode != "" {
			redirectToBootstrapResult(c, "error", errDesc)
		} else {
			redirectToBootstrapResult(c, "error", "Missing state or code parameter")
		}
		return
	}

	sess, ok := globalBootstrapStore.getByState(state)
	if !ok {
		redirectToBootstrapResult(c, "error", "Unknown or expired session")
		return
	}

	// Find an OAuth client for this issuer that supports authorization_code.
	// Use scope-aware matching with the session's requested scopes.
	requestedScopes := strings.Fields(sess.Scopes)
	oauthClient, err := findOAuthClientForGrant(db, sess.IssuerURL, "authorization_code", requestedScopes)
	if err != nil {
		sess.Status = "error"
		sess.Error = "OAuth client not found for issuer"
		redirectToBootstrapResult(c, "error", "OAuth client not found for issuer")
		return
	}

	clientID, err := decryptSecret(oauthClient.EncryptedClientID)
	if err != nil {
		sess.Status = "error"
		sess.Error = "Failed to decrypt credentials"
		redirectToBootstrapResult(c, "error", "Internal error")
		return
	}
	clientSecret, err := decryptSecret(oauthClient.EncryptedClientSecret)
	if err != nil {
		sess.Status = "error"
		sess.Error = "Failed to decrypt credentials"
		redirectToBootstrapResult(c, "error", "Internal error")
		return
	}

	issuerMeta, err := globalIssuerCache.get(sess.IssuerURL)
	if err != nil {
		sess.Status = "error"
		sess.Error = "Failed to contact issuer"
		redirectToBootstrapResult(c, "error", "Failed to contact issuer")
		return
	}

	serverBase := param.Server_ExternalWebUrl.GetString()
	redirectURI := serverBase + SharedCallbackPath

	// Inject the Pelican HTTP transport so the token exchange uses the
	// server's TLS configuration (e.g. TLSSkipVerify in dev/test).
	tokenCtx := context.WithValue(c.Request.Context(), pelican_oauth2.HTTPClient, &http.Client{
		Transport: config.GetTransport(),
	})
	token, err := exchangeCodeForToken(tokenCtx, issuerMeta.TokenURL, clientID, clientSecret, code, redirectURI)
	if err != nil {
		sess.Status = "error"
		sess.Error = "Token exchange failed: " + err.Error()
		log.Errorf("Auth code token exchange failed: %v", err)
		redirectToBootstrapResult(c, "error", "Token exchange with issuer failed")
		return
	}

	// Determine the effective scopes for the credential. Use the client's
	// registered scopes if available; fall back to the session-requested scopes.
	credScopes := sess.Scopes
	if oauthClient.Scopes != "" {
		credScopes = oauthClient.Scopes
	}

	cred, err := createCredentialFromToken(db, sess.Owner, sess.Name, sess.IssuerURL,
		token.AccessToken, token.RefreshToken, credScopes)
	if err != nil {
		sess.Status = "error"
		sess.Error = "Failed to store credential"
		log.Errorf("Failed to create credential from auth code: %v", err)
		redirectToBootstrapResult(c, "error", "Failed to store credential")
		return
	}

	sess.Status = "complete"
	sess.CredID = cred.ID

	redirectToBootstrapResult(c, "success", "Credential created successfully")
}

// handleAuthCodeBootstrapPoll handles GET /api/v1.0/transfer/credentials/bootstrap/authcode/:session_id
// The CLI polls this to check whether the authorization code flow has completed.
func handleAuthCodeBootstrapPoll(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		sessionID := c.Param("session_id")
		sess, ok := globalBootstrapStore.get(sessionID)
		if !ok {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Code:  "NOT_FOUND",
				Error: "Bootstrap session not found or expired",
			})
			return
		}

		// Verify ownership
		if sess.Owner.UserID != owner.UserID {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Code:  "NOT_FOUND",
				Error: "Bootstrap session not found",
			})
			return
		}

		resp := AuthCodeBootstrapStatus{
			SessionID: sessionID,
			Status:    sess.Status,
			Error:     sess.Error,
		}

		if sess.Status == "complete" {
			resp.CredentialID = sess.CredID
			// Include the credential response
			var cred TransferCredential
			if err := db.Where("id = ?", sess.CredID).First(&cred).Error; err == nil {
				resp.Credential = credentialToResponse(&cred)
			}
			// Clean up the session
			globalBootstrapStore.delete(sessionID)
		}

		c.JSON(http.StatusOK, resp)
	}
}

// performTokenExchange performs an RFC 8693 token exchange against the given
// token endpoint using the provided client credentials and subject token.
// If requestedScopes is non-empty, it is sent as the "scope" parameter so the
// issuer computes the intersection with the subject token's grants.
func performTokenExchange(ctx context.Context, tokenURL, clientID, clientSecret, subjectToken, requestedScopes string) (*tokenExchangeResult, error) {
	v := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	if requestedScopes != "" {
		v.Set("scope", requestedScopes)
	}

	token, err := pelican_oauth2.RetrieveToken(ctx, clientID, clientSecret, tokenURL, v)
	if err != nil {
		return nil, errors.Wrap(err, "token exchange request failed")
	}

	return &tokenExchangeResult{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

type tokenExchangeResult struct {
	AccessToken  string
	RefreshToken string
}

// exchangeCodeForToken exchanges an authorization code for tokens.
func exchangeCodeForToken(ctx context.Context, tokenURL, clientID, clientSecret, code, redirectURI string) (*tokenExchangeResult, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	token, err := pelican_oauth2.RetrieveToken(ctx, clientID, clientSecret, tokenURL, v)
	if err != nil {
		return nil, errors.Wrap(err, "authorization code exchange failed")
	}

	return &tokenExchangeResult{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

// createCredentialFromToken creates a new TransferCredential with the given
// token information, encrypting the tokens before storage.
//
// TODO: The encryption approach (config.EncryptString / config.DecryptString)
// should be replaced with a centralized encryption helper in the transfer
// module. The target design uses a master secret encrypted by the server's
// issuer keys (any known key can decrypt) and a bootstrap secret derived from
// that master key. This work exists on a separate branch. For now we use the
// config encryption/decryption functions and centralize access through
// encryptSecret / decryptSecret helpers (below) so only one call site needs
// to change when the other branch merges.
func createCredentialFromToken(db *gorm.DB, owner ownerIdentity, name, issuerURL, accessToken, refreshToken, scopes string) (*TransferCredential, error) {
	encAccessToken, err := encryptSecret(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt access token")
	}

	var encRefreshToken *string
	if refreshToken != "" {
		enc, err := encryptSecret(refreshToken)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encrypt refresh token")
		}
		encRefreshToken = &enc
	}

	// Generate a unique name if the provided one conflicts
	credName := name
	var existing TransferCredential
	if err := db.Where("user_id = ? AND name = ?",
		owner.UserID, credName).First(&existing).Error; err == nil {
		// Name exists — append a suffix
		credName = credName + "-" + time.Now().Format("20060102-150405")
	}

	cred := TransferCredential{
		ID:                    uuid.New().String(),
		UserID:                owner.UserID,
		Name:                  credName,
		CredentialType:        "bearer",
		EncryptedAccessToken:  encAccessToken,
		EncryptedRefreshToken: encRefreshToken,
		Scopes:                scopes,
		TokenIssuer:           issuerURL,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := db.Create(&cred).Error; err != nil {
		return nil, errors.Wrap(err, "database insert failed")
	}

	return &cred, nil
}

// encryptSecret encrypts a secret value for storage in the database.
// TODO: Replace with master-secret-based encryption once the separate branch
// lands. For now delegates to config.EncryptString.
func encryptSecret(plaintext string) (string, error) {
	return config.EncryptString(plaintext)
}

// decryptSecret decrypts a secret value retrieved from the database.
// TODO: Replace with master-secret-based decryption once the separate branch
// lands. For now delegates to config.DecryptString.
func decryptSecret(ciphertext string) (string, error) {
	plaintext, _, err := config.DecryptString(ciphertext)
	return plaintext, err
}

// LaunchBootstrapSessionCleanup starts a goroutine that periodically cleans up
// expired bootstrap sessions.
func LaunchBootstrapSessionCleanup(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				globalBootstrapStore.cleanupExpiredSessions()
			}
		}
	})
}

// trimTrailingSlash is a helper that normalizes URLs.
func trimTrailingSlash(s string) string {
	return strings.TrimRight(s, "/")
}
