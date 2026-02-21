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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
)

// hkdfPurposeIDPHMAC is the HKDF info string used to derive the HMAC
// signing key for fosite's opaque token strategy from the master key.
const hkdfPurposeIDPHMAC = "pelican-idp-hmac-v1"

// OIDCProvider manages the embedded OAuth2/OIDC issuer.
type OIDCProvider struct {
	oauth2     fosite.OAuth2Provider
	storage    *OIDCStorage
	config     *fosite.Config
	strategy   *compose.CommonStrategy
	privateKey crypto.Signer

	// DeviceCodeHandler handles RFC 8628 device authorization grant.
	DeviceCodeHandler *DeviceCodeHandler

	// RegistrationLimiter enforces per-IP rate limiting on the dynamic
	// client registration endpoint.
	RegistrationLimiter *registrationRateLimiter
}

// NewOIDCProvider creates a new embedded OIDC provider.
// It reuses the Pelican server's signing key from config.GetIssuerPrivateJWK().
func NewOIDCProvider(db *gorm.DB, issuerURL string, refreshGracePeriod time.Duration) (*OIDCProvider, error) {
	storage := NewOIDCStorage(db)
	storage.RefreshTokenGracePeriod = refreshGracePeriod

	// Use Pelican's existing private signing key
	privateKey, kid, err := getOrCreateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenURL := issuerURL + "/api/v1.0/issuer/token"

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     7 * 24 * time.Hour,
		AuthorizeCodeLifespan:    10 * time.Minute,
		IDTokenLifespan:          time.Hour,
		TokenURL:                 tokenURL,
		AccessTokenIssuer:        issuerURL,
		ScopeStrategy:            sciTokensScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		JWTScopeClaimKey:         jwt.JWTScopeFieldString,
	}

	// Load (or generate) the encrypted master key and derive the HMAC
	// sub-key via HKDF so the raw secret is never stored in the DB.
	masterKey, err := database.LoadOrCreateMasterKey(db)
	if err != nil {
		return nil, fmt.Errorf("failed to load or create master key: %w", err)
	}
	hmacSubKey, err := database.DeriveSubKey(masterKey, hkdfPurposeIDPHMAC, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive HMAC sub-key: %w", err)
	}
	fositeConfig.GlobalSecret = hmacSubKey

	// Wrap the raw private key in a jose.JSONWebKey so that fosite includes
	// the key ID (kid) in the JWT header. Without this, the origin's auth
	// handler cannot match the JWT to a key in the JWKS (lestrrat-go/jwx
	// requires kid match by default).
	sigAlg := signingAlgorithmForKey(privateKey)
	signingJWK := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     kid,
		Algorithm: sigAlg,
		Use:       "sig",
	}

	keyGetter := func(_ context.Context) (interface{}, error) {
		return signingJWK, nil
	}

	hmacStrategy := compose.NewOAuth2HMACStrategy(fositeConfig)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fositeConfig)

	strategy := &compose.CommonStrategy{
		CoreStrategy:               jwtStrategy,
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fositeConfig),
	}

	oauth2Provider := compose.Compose(
		fositeConfig,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)

	deviceHandler := NewDeviceCodeHandler(storage, fositeConfig)

	// Rate limit: 5 registrations burst, refill at 1/minute (~= 0.0167/s).
	regLimiter := newRegistrationRateLimiter(1.0/60.0, 5)

	return &OIDCProvider{
		oauth2:              oauth2Provider,
		storage:             storage,
		config:              fositeConfig,
		strategy:            strategy,
		privateKey:          privateKey,
		DeviceCodeHandler:   deviceHandler,
		RegistrationLimiter: regLimiter,
	}, nil
}

// Provider returns the underlying fosite OAuth2Provider.
func (p *OIDCProvider) Provider() fosite.OAuth2Provider {
	return p.oauth2
}

// Storage returns the OIDC storage.
func (p *OIDCProvider) Storage() *OIDCStorage {
	return p.storage
}

// Config returns the fosite config.
func (p *OIDCProvider) Config() *fosite.Config {
	return p.config
}

// PrivateKey returns the private key used for signing (RSA or ECDSA).
func (p *OIDCProvider) PrivateKey() crypto.Signer {
	return p.privateKey
}

// StartCleanup launches a background goroutine via the provided errgroup
// that periodically:
//   - Remove dynamically registered clients that were never used
//     (controlled by unusedClientMaxAge).
//   - Remove dynamically registered clients that were previously used but
//     have been idle for too long (controlled by staleClientMaxAge).
//   - Delete expired token sessions (access tokens, refresh tokens, auth
//     codes, PKCE requests, OpenID sessions).
//   - Delete expired or consumed device codes.
//   - Delete expired JWT assertion replay-prevention entries.
//   - Evict stale entries from the in-memory registration rate limiter.
//
// The goroutine exits when ctx is cancelled and is tracked by egrp so
// callers (including tests) can wait for a clean shutdown.
func (p *OIDCProvider) StartCleanup(ctx context.Context, egrp *errgroup.Group, unusedClientMaxAge, staleClientMaxAge time.Duration) {
	egrp.Go(func() error {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n, err := p.storage.DeleteUnusedDynamicClients(ctx, unusedClientMaxAge)
				if err != nil {
					log.WithError(err).Warn("Embedded issuer: failed to clean up unused dynamic clients")
				} else if n > 0 {
					log.Infof("Embedded issuer: deleted %d unused dynamically registered client(s)", n)
				}
				n, err = p.storage.DeleteStaleDynamicClients(ctx, staleClientMaxAge)
				if err != nil {
					log.WithError(err).Warn("Embedded issuer: failed to clean up stale dynamic clients")
				} else if n > 0 {
					log.Infof("Embedded issuer: deleted %d stale dynamically registered client(s)", n)
				}
				n, err = p.storage.DeleteExpiredTokenSessions(ctx)
				if err != nil {
					log.WithError(err).Warn("Embedded issuer: failed to clean up expired token sessions")
				} else if n > 0 {
					log.Infof("Embedded issuer: deleted %d expired token session(s)", n)
				}
				n, err = p.storage.DeleteExpiredDeviceCodes(ctx)
				if err != nil {
					log.WithError(err).Warn("Embedded issuer: failed to clean up expired device codes")
				} else if n > 0 {
					log.Infof("Embedded issuer: deleted %d expired/used device code(s)", n)
				}
				n, err = p.storage.DeleteExpiredJWTAssertions(ctx)
				if err != nil {
					log.WithError(err).Warn("Embedded issuer: failed to clean up expired JWT assertions")
				} else if n > 0 {
					log.Infof("Embedded issuer: deleted %d expired JWT assertion(s)", n)
				}
				p.RegistrationLimiter.Cleanup(1 * time.Hour)
			case <-ctx.Done():
				log.Info("Embedded issuer: cleanup goroutine stopped")
				return nil
			}
		}
	})
}

// WLCGSession is a combined session that satisfies both fosite's JWTSessionContainer
// (required for JWT access tokens) and the OpenID Connect session interface
// (required for ID tokens). It carries WLCG-specific claims like groups and scopes.
type WLCGSession struct {
	// JWTClaims are used for access token JWT claims
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	// IDTokenClaimsField are used for ID token claims
	IDTokenClaimsField *jwt.IDTokenClaims `json:"id_token_claims"`
	// Headers for both JWT types
	JWTHeaders *jwt.Headers                   `json:"jwt_headers"`
	ExpiresAt  map[fosite.TokenType]time.Time `json:"expires_at"`
	Username   string                         `json:"username"`
	Subject    string                         `json:"subject"`
}

// GetJWTClaims implements oauth2.JWTSessionContainer for access tokens.
func (s *WLCGSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
func (s *WLCGSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeaders == nil {
		s.JWTHeaders = &jwt.Headers{}
	}
	return s.JWTHeaders
}

// IDTokenClaims returns the ID token claims for OpenID Connect.
func (s *WLCGSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDTokenClaimsField == nil {
		s.IDTokenClaimsField = &jwt.IDTokenClaims{}
	}
	return s.IDTokenClaimsField
}

// IDTokenHeaders returns the ID token headers.
func (s *WLCGSession) IDTokenHeaders() *jwt.Headers {
	return s.GetJWTHeader()
}

func (s *WLCGSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *WLCGSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	if _, ok := s.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *WLCGSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *WLCGSession) SetSubject(subject string) {
	s.Subject = subject
}

func (s *WLCGSession) GetSubject() string {
	if s == nil {
		return ""
	}
	return s.Subject
}

func (s *WLCGSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}

// GetExtraClaims implements fosite.ExtraClaimsSession.
func (s *WLCGSession) GetExtraClaims() map[string]interface{} {
	if s == nil {
		return nil
	}
	return s.Clone().(*WLCGSession).GetJWTClaims().WithScopeField(jwt.JWTScopeFieldString).ToMapClaims()
}

// DefaultOIDCSession creates a new WLCG-compliant OIDC session with both
// JWT access token claims and ID token claims.
func DefaultOIDCSession(subject string, issuer string, groups []string, scopes []string) *WLCGSession {
	now := time.Now()
	extra := map[string]interface{}{}

	if len(groups) > 0 {
		extra["wlcg.groups"] = groups
	}
	// Add the WLCG profile version claim
	extra["wlcg.ver"] = "1.0"

	return &WLCGSession{
		JWTClaims: &jwt.JWTClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  now,
			ExpiresAt: now.Add(1 * time.Hour),
			Scope:     scopes,
			Extra:     extra,
		},
		IDTokenClaimsField: &jwt.IDTokenClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  now,
			ExpiresAt: now.Add(1 * time.Hour),
			Extra:     extra,
		},
		JWTHeaders: &jwt.Headers{},
		Subject:    subject,
	}
}

// EnsureClient registers a default client if absent.
// secret should be the plaintext secret; it will be bcrypt-hashed before storage.
func (p *OIDCProvider) EnsureClient(ctx context.Context, clientID, secret string, redirectURIs []string) error {
	_, err := p.storage.GetClient(ctx, clientID)
	if err == nil {
		return nil // already exists
	}
	if !errors.Is(err, fosite.ErrNotFound) {
		return err
	}

	// Hash the secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash client secret: %w", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  redirectURIs,
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes: fosite.Arguments{"code", "token", "id_token"},
		Scopes:        fosite.Arguments{"openid", "offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
		Public:        false,
	}

	log.Infof("Registering default OIDC client: %s", clientID)
	return p.storage.CreateClient(ctx, client)
}

// getOrCreateSigningKey retrieves the Pelican server's private signing key.
// It supports both RSA and ECDSA keys.
func getOrCreateSigningKey() (crypto.Signer, string, error) {
	privateJWK, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get issuer private JWK: %w", err)
	}

	kid := privateJWK.KeyID()

	var rawKey interface{}
	if err := privateJWK.Raw(&rawKey); err != nil {
		return nil, "", fmt.Errorf("failed to extract raw key from JWK: %w", err)
	}

	switch k := rawKey.(type) {
	case *rsa.PrivateKey:
		return k, kid, nil
	case *ecdsa.PrivateKey:
		return k, kid, nil
	default:
		return nil, "", fmt.Errorf("unsupported issuer private key type: %T", rawKey)
	}
}

// signingAlgorithmForKey returns the JWA algorithm name for the given key type.
func signingAlgorithmForKey(key crypto.Signer) string {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P384():
			return "ES384"
		case elliptic.P521():
			return "ES512"
		default:
			return "ES256"
		}
	default:
		return "RS256"
	}
}

// signingAlgorithm returns the JWA algorithm name for the provider's key type.
func (p *OIDCProvider) signingAlgorithm() string {
	return signingAlgorithmForKey(p.privateKey)
}

// PublicJWKS returns the JWKS representation of the signing public key.
func (p *OIDCProvider) PublicJWKS() ([]byte, error) {
	pubKey := p.privateKey.Public()
	key, err := jwk.FromRaw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, p.signingAlgorithm()); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}
	kid := IssuerURL()
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}

	return json.MarshalIndent(set, "", "  ")
}
