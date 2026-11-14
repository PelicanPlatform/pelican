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
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/ory/fosite"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/web_ui"
)

// externalSigningKeys caches the signing keys of every trusted external
// issuer, shared by all of this server's namespace issuers. Keys are
// refreshed every 15 minutes, or sooner (at most once a minute) when a token
// names a key the cache lacks.
var externalSigningKeys = newExternalKeyCache(fetchIssuerJWKS, 15*time.Minute, time.Minute)

// fetchIssuerJWKS downloads an issuer's signing keys through OIDC discovery.
func fetchIssuerJWKS(ctx context.Context, issuer string) (jwk.Set, error) {
	jwksURL, err := token.LookupIssuerJwksUrl(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return jwk.Fetch(ctx, jwksURL.String(), jwk.WithHTTPClient(&http.Client{Transport: config.GetTransport()}))
}

// loadExternalTokenIssuers reads and validates
// Issuer.TokenExchangeTrustedIssuers. It is cheap enough to call on every
// exchange, so configuration changes apply without a restart.
func loadExternalTokenIssuers() ([]ExternalTokenIssuer, error) {
	var entries []ExternalTokenIssuer
	if err := param.Issuer_TokenExchangeTrustedIssuers.Decode(&entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	groupSourceIssuer := ""
	if database.ConfiguredGroupSource() == database.GroupSourceOIDC {
		groupSourceIssuer = param.OIDC_Issuer.GetString()
	}
	return normalizeExternalIssuers(entries, IssuerURL(), groupSourceIssuer, param.Issuer_OIDCGroupClaim.GetString())
}

// ValidateExternalTokenIssuers checks Issuer.TokenExchangeTrustedIssuers so
// that a mistake stops the server at startup rather than surfacing on the
// first exchange.
func ValidateExternalTokenIssuers() error {
	_, err := loadExternalTokenIssuers()
	return err
}

// externalIssuerForSubjectToken returns the trust configuration covering the
// subject token's issuer, or nil when the token is not from a configured
// external issuer (in particular, when this server minted it).
func externalIssuerForSubjectToken(subjectToken string) (*ExternalTokenIssuer, error) {
	iss := unverifiedIssuer(subjectToken)
	if iss == "" || urlAtOrBelow(iss, IssuerURL()) {
		return nil, nil
	}
	entries, err := loadExternalTokenIssuers()
	if err != nil {
		return nil, err
	}
	return matchExternalIssuer(entries, iss), nil
}

// writeTokenError sends an RFC 6749 section 5.2 error from the token endpoint.
func writeTokenError(ctx *gin.Context, status int, code, description string) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.JSON(status, gin.H{"error": code, "error_description": description})
}

// handleExternalTokenExchange completes an RFC 8693 exchange whose
// subject_token was minted by a trusted external issuer, such as the Keycloak
// realm behind a JupyterHub.
//
// The external token establishes only who the user is. The user must already
// have a Pelican account linked to that identity, and the scopes granted are
// computed from Pelican's own authorization templates and collection ACLs by
// the code browser login uses, then narrowed to the requested scope. An
// exchange therefore never yields more access than signing in would.
func handleExternalTokenExchange(ctx *gin.Context, provider *OIDCProvider, client *fosite.DefaultClient, entry *ExternalTokenIssuer, subjectToken, subjectTokenType string) {
	r := ctx.Request
	rCtx := r.Context()
	clientID := client.GetID()

	if !slices.Contains(entry.AllowedClients, clientID) {
		writeTokenError(ctx, http.StatusBadRequest, "unauthorized_client", "This client may not exchange tokens issued by "+entry.Issuer)
		return
	}
	if !slices.Contains(entry.SubjectTokenTypes, subjectTokenType) {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_request", "subject_token_type "+subjectTokenType+" is not accepted for tokens issued by "+entry.Issuer)
		return
	}
	if requestedType := r.FormValue("requested_token_type"); requestedType != "" && requestedType != tokenTypeAccessToken {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_request", "Only access tokens can be issued")
		return
	}
	if r.FormValue("actor_token") != "" {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_request", "actor_token is not supported")
		return
	}
	if r.FormValue("resource") != "" {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_target", "The resource parameter is not supported")
		return
	}
	if audience := r.FormValue("audience"); audience != "" && audience != WLCGAudienceAny {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_target", "Exchanged tokens carry only the audience "+WLCGAudienceAny)
		return
	}
	requested := strings.Fields(r.FormValue("scope"))
	if len(requested) == 0 {
		// Unlike a same-issuer exchange there is no earlier grant to
		// inherit, and defaulting to everything the user may do would hand
		// applications far more than they need.
		writeTokenError(ctx, http.StatusBadRequest, "invalid_scope", "scope is required when exchanging a token from another issuer")
		return
	}

	subject, err := validateExternalSubjectToken(rCtx, subjectToken, entry, externalSigningKeys, time.Now(), token.ClockSkewLeeway)
	if err != nil {
		var rejection *exchangeRejection
		if errors.As(err, &rejection) {
			log.Debugf("Embedded issuer: rejected a subject_token from %s presented by client %s: %s", entry.Issuer, clientID, rejection.reason)
			writeTokenError(ctx, http.StatusBadRequest, "invalid_grant", rejection.reason)
		} else {
			log.WithError(err).Warn("Embedded issuer: could not verify an external subject_token")
			writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Could not obtain the signing keys of "+entry.Issuer)
		}
		return
	}

	if entry.SingleUse {
		key := subjectTokenReplayKey(provider.Namespace, subject.Issuer, subject.JTI)
		if err := provider.storage.ConsumeSubjectTokenJTI(rCtx, key, subject.ExpiresAt.Add(token.ClockSkewLeeway)); err != nil {
			if errors.Is(err, fosite.ErrJTIKnown) {
				writeTokenError(ctx, http.StatusBadRequest, "invalid_grant", "This subject_token has already been exchanged")
			} else {
				log.WithError(err).Warn("Embedded issuer: failed to record an exchanged subject_token")
				writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to record the exchange")
			}
			return
		}
	}

	db := database.ServerDatabase
	if db == nil {
		db = provider.storage.db
	}
	user, err := database.GetUserByIdentity(db, subject.Subject, subject.IdentityIssuer)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeTokenError(ctx, http.StatusBadRequest, "invalid_grant", "No Pelican account is linked to this identity; sign in to this server's web interface once through "+subject.IdentityIssuer+", or ask an administrator to link the identity")
		} else {
			log.WithError(err).Warn("Embedded issuer: failed to look up the account behind an external subject_token")
			writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to look up the account")
		}
		return
	}
	if user.Status != database.UserStatusActive {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_grant", "The Pelican account linked to this identity is not active")
		return
	}
	// The exchange cannot show the acceptable use policy, so it must
	// already have been accepted where it could be.
	_, aupVersion, err := web_ui.CurrentAUPVersion()
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to determine the current acceptable use policy")
		writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to check the acceptable use policy")
		return
	}
	if aupVersion != "" && user.AUPVersion != aupVersion {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_grant", "The account has not accepted the current acceptable use policy; sign in to this server's web interface to review it")
		return
	}

	// A group claim from the issuer users sign in with is mirrored exactly
	// as at login. Then every membership that still confers access counts,
	// whether recorded in Pelican or mirrored from the identity provider.
	if entry.AssertGroups && subject.GroupsAsserted {
		web_ui.RecordAssertedGroups(database.GroupSourceOIDC, user.ID, user.Username, subject.Groups)
	}
	groups, err := database.GroupNamesForGranting(db, user.ID)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to look up group memberships")
		writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to look up group memberships")
		return
	}
	if entry.AssertGroups {
		groups = oa4mp.MergeGroups(groups, subject.Groups)
	}

	allowed, matchedGroups, serverDB := provider.userAllowedScopes(user.Username, user.ID, groups)
	granted := grantRequestedScopes(requested, allowed, client.GetScopes(), serverDB, user.ID, groups)
	if len(granted) == 0 {
		writeTokenError(ctx, http.StatusBadRequest, "invalid_scope", "None of the requested scopes may be granted to this user through this client")
		return
	}

	session := DefaultOIDCSession(user.Username, provider.Issuer(), matchedGroups, granted)
	// RFC 8693 section 4.1: record which client acted on the user's behalf.
	session.JWTClaims.Extra["act"] = map[string]interface{}{"sub": clientID}
	session.SetExpiresAt(fosite.AccessToken, time.Now().Add(provider.config.AccessTokenLifespan))
	ar := fosite.NewAccessRequest(session)
	ar.Client = client
	ar.GrantedScope = granted
	ar.RequestedScope = requested
	ar.GrantAudience(WLCGAudienceAny)

	accessToken, accessSignature, err := provider.strategy.CoreStrategy.GenerateAccessToken(rCtx, ar)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to generate an access token for an external token exchange")
		writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}
	if err := provider.storage.CreateAccessTokenSession(rCtx, accessSignature, ar); err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to store an access token for an external token exchange")
		writeTokenError(ctx, http.StatusInternalServerError, "server_error", "Failed to store access token")
		return
	}
	_ = provider.storage.TouchClientLastUsed(rCtx, clientID)

	result := gin.H{
		"access_token":      accessToken,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        int(provider.config.AccessTokenLifespan.Seconds()),
		"scope":             strings.Join(granted, " "),
	}
	if entry.AllowRefreshTokens && slices.Contains(client.GetGrantTypes(), "refresh_token") && slices.Contains(granted, "offline_access") {
		ar.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().Add(provider.config.RefreshTokenLifespan))
		refreshToken, refreshSignature, err := provider.strategy.CoreStrategy.GenerateRefreshToken(rCtx, ar)
		if err == nil {
			err = provider.storage.CreateRefreshTokenSession(rCtx, refreshSignature, accessSignature, ar)
		}
		if err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to issue a refresh token for an external token exchange")
		} else {
			result["refresh_token"] = refreshToken
		}
	}

	log.Infof("Embedded issuer: client %s exchanged a token from %s (identity from %s) for user %s; granted %q", clientID, entry.Issuer, subject.IdentityIssuer, user.Username, strings.Join(granted, " "))
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.JSON(http.StatusOK, result)
}
