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

// This file is the self-contained core of external-issuer token exchange:
// the Issuer.TokenExchangeTrustedIssuers configuration, verification of a
// subject_token minted by one of those issuers, a cache of their signing
// keys, and the description of granted scopes as RFC 9396
// authorization_details. It imports only the standard library and jwx so it
// can be unit-tested in isolation; the handlers that tie it to accounts,
// groups and scopes are in external_exchange_handler.go and
// access_handler.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// RFC 8693 token type identifiers.
const (
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"
)

// ClaimRequirement demands that a token claim carry a value (for an array
// claim, contain it). It has the same shape as the entries of
// Issuer.OIDCAuthenticationRequirements.
type ClaimRequirement struct {
	Claim string `mapstructure:"Claim"`
	Value string `mapstructure:"Value"`
}

// ExternalTokenIssuer is one entry of Issuer.TokenExchangeTrustedIssuers: an
// external OIDC issuer, such as a Keycloak realm, whose tokens this issuer
// accepts as an RFC 8693 subject_token. The external token only establishes
// who the user is; what the exchanged token may do is computed from
// Pelican's own policy, exactly as for a browser login.
type ExternalTokenIssuer struct {
	// Issuer must equal the token's iss claim exactly. Its signing keys
	// are found through OIDC discovery.
	Issuer string `mapstructure:"Issuer"`
	// Audiences lists values at least one of which must appear in the
	// token's aud claim. Required: only a token minted for this server may
	// be exchanged here.
	Audiences []string `mapstructure:"Audiences"`
	// AllowedClients lists the IDs of this issuer's clients that may
	// present tokens from Issuer. Required.
	AllowedClients []string `mapstructure:"AllowedClients"`
	// SubjectClaim names the claim that identifies the user; together with
	// IdentityIssuer it must match an identity already linked to a Pelican
	// account. Defaults to "sub".
	SubjectClaim string `mapstructure:"SubjectClaim"`
	// IdentityIssuer is the issuer whose identities SubjectClaim carries, and
	// defaults to Issuer. A broker that relays the identity of an upstream
	// provider this server also signs users in with, such as a Keycloak realm
	// brokering CILogon, sets it to that provider: accounts are then found by
	// the relayed subject, which trusts the broker to vouch for that
	// provider's identities. SubjectClaim must then name the relayed claim,
	// and RequiredClaims must tie the token to a login through the provider.
	IdentityIssuer string `mapstructure:"IdentityIssuer"`
	// RequiredClaims lists values the token must carry, such as the azp of
	// the client the token was issued to.
	RequiredClaims []ClaimRequirement `mapstructure:"RequiredClaims"`
	// AssertGroups treats the token's group claim as a fresh assertion of
	// group membership. Only the issuer users sign in with may do this, and
	// only while Issuer.GroupSource is "oidc".
	AssertGroups bool `mapstructure:"AssertGroups"`
	// GroupClaim names the group claim. Defaults to Issuer.OIDCGroupClaim.
	GroupClaim string `mapstructure:"GroupClaim"`
	// SubjectTokenTypes lists the accepted subject_token_type values.
	// Defaults to the access_token and jwt types.
	SubjectTokenTypes []string `mapstructure:"SubjectTokenTypes"`
	// MaxTokenAge, when set, refuses tokens issued longer ago than this.
	MaxTokenAge time.Duration `mapstructure:"MaxTokenAge"`
	// SingleUse refuses a token whose jti was already exchanged at this
	// namespace's issuer, and any token without a jti.
	SingleUse bool `mapstructure:"SingleUse"`
	// AllowRefreshTokens lets a client holding the refresh_token grant
	// receive a refresh token when it requests offline_access. A refreshed
	// token keeps the scopes granted at exchange time, so re-exchanging,
	// which re-evaluates the user's current access, is preferred.
	AllowRefreshTokens bool `mapstructure:"AllowRefreshTokens"`
}

// normalizeExternalIssuers validates Issuer.TokenExchangeTrustedIssuers and
// fills in defaults.
//
// ownIssuerBase is this server's external web URL. Tokens this server minted
// are already exchangeable through the same-issuer path, so no entry may name
// an issuer at or beneath it. groupSourceIssuer is the issuer users sign in
// with when Issuer.GroupSource is "oidc", and empty otherwise; it is the only
// issuer allowed to assert groups.
func normalizeExternalIssuers(entries []ExternalTokenIssuer, ownIssuerBase, groupSourceIssuer, defaultGroupClaim string) ([]ExternalTokenIssuer, error) {
	normalized := make([]ExternalTokenIssuer, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		where := fmt.Sprintf("Issuer.TokenExchangeTrustedIssuers[%d]", i)
		issuerURL, err := url.Parse(entry.Issuer)
		if entry.Issuer == "" || err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
			return nil, fmt.Errorf("%s: Issuer %q must be an https URL", where, entry.Issuer)
		}
		if seen[entry.Issuer] {
			return nil, fmt.Errorf("%s: issuer %q is listed more than once", where, entry.Issuer)
		}
		seen[entry.Issuer] = true
		if ownIssuerBase != "" && urlAtOrBelow(entry.Issuer, ownIssuerBase) {
			return nil, fmt.Errorf("%s: %q is this server's own issuer, whose tokens are exchangeable without being listed", where, entry.Issuer)
		}
		if entry.Audiences = nonEmptyStrings(entry.Audiences); len(entry.Audiences) == 0 {
			return nil, fmt.Errorf("%s: Audiences must list at least one value the token's aud claim has to carry", where)
		}
		if entry.AllowedClients = nonEmptyStrings(entry.AllowedClients); len(entry.AllowedClients) == 0 {
			return nil, fmt.Errorf("%s: AllowedClients must list the clients permitted to present these tokens", where)
		}
		if entry.IdentityIssuer == "" {
			entry.IdentityIssuer = entry.Issuer
		} else if entry.IdentityIssuer != entry.Issuer {
			if err := checkRelayedIdentity(entry, ownIssuerBase); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
		}
		if entry.SubjectClaim == "" {
			entry.SubjectClaim = jwt.SubjectKey
		}
		for j, requirement := range entry.RequiredClaims {
			if requirement.Claim == "" {
				return nil, fmt.Errorf("%s: RequiredClaims[%d] names no claim", where, j)
			}
		}
		if len(entry.SubjectTokenTypes) == 0 {
			entry.SubjectTokenTypes = []string{tokenTypeAccessToken, tokenTypeJWT}
		}
		for _, tokenType := range entry.SubjectTokenTypes {
			if tokenType != tokenTypeAccessToken && tokenType != tokenTypeJWT && tokenType != tokenTypeIDToken {
				return nil, fmt.Errorf("%s: unsupported subject token type %q", where, tokenType)
			}
		}
		if entry.AssertGroups {
			if groupSourceIssuer == "" || strings.TrimSuffix(entry.Issuer, "/") != strings.TrimSuffix(groupSourceIssuer, "/") {
				return nil, fmt.Errorf("%s: AssertGroups is allowed only for the issuer users sign in with (OIDC.Issuer) while Issuer.GroupSource is \"oidc\"", where)
			}
			if entry.GroupClaim == "" {
				entry.GroupClaim = defaultGroupClaim
			}
			if entry.GroupClaim == "" {
				entry.GroupClaim = "groups"
			}
		}
		if entry.MaxTokenAge < 0 {
			return nil, fmt.Errorf("%s: MaxTokenAge must not be negative", where)
		}
		normalized = append(normalized, entry)
	}
	return normalized, nil
}

// checkRelayedIdentity validates an entry whose tokens relay the identity of
// another provider, that is, whose IdentityIssuer differs from its Issuer.
func checkRelayedIdentity(entry ExternalTokenIssuer, ownIssuerBase string) error {
	identityURL, err := url.Parse(entry.IdentityIssuer)
	if err != nil || identityURL.Scheme != "https" || identityURL.Host == "" {
		return fmt.Errorf("IdentityIssuer %q must be an https URL", entry.IdentityIssuer)
	}
	if ownIssuerBase != "" && urlAtOrBelow(entry.IdentityIssuer, ownIssuerBase) {
		return fmt.Errorf("IdentityIssuer %q is this server's own issuer, whose identities no broker may assert", entry.IdentityIssuer)
	}
	if entry.SubjectClaim == "" || entry.SubjectClaim == jwt.SubjectKey {
		return fmt.Errorf("SubjectClaim must name the claim relaying the subject from %s; the broker's own sub is not one of its identities", entry.IdentityIssuer)
	}
	if len(entry.RequiredClaims) == 0 {
		return fmt.Errorf("RequiredClaims must tie relayed identities to a login through %s, for example with Keycloak's identity_provider claim", entry.IdentityIssuer)
	}
	if entry.AssertGroups {
		return fmt.Errorf("AssertGroups cannot be combined with a relayed identity; groups then come from Pelican's records")
	}
	return nil
}

// urlAtOrBelow reports whether candidate is base or a path beneath it.
func urlAtOrBelow(candidate, base string) bool {
	candidate = strings.TrimSuffix(candidate, "/")
	base = strings.TrimSuffix(base, "/")
	return candidate == base || strings.HasPrefix(candidate, base+"/")
}

func nonEmptyStrings(values []string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

// matchExternalIssuer returns the entry trusting iss, or nil.
func matchExternalIssuer(entries []ExternalTokenIssuer, iss string) *ExternalTokenIssuer {
	for i := range entries {
		if entries[i].Issuer == iss {
			return &entries[i]
		}
	}
	return nil
}

// unverifiedIssuer reads a JWT's iss claim WITHOUT verifying anything. Its
// only use is choosing which trust configuration, if any, the token is then
// fully verified against; nothing it returns may be trusted.
func unverifiedIssuer(raw string) string {
	tok, err := jwt.ParseString(raw, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return ""
	}
	return tok.Issuer()
}

// exchangeRejection is an exchange failure the presenter caused: a token that
// is malformed, expired, meant for another audience, and so on. It is
// reported to the client as invalid_grant; any other error is a server fault.
type exchangeRejection struct {
	reason string
}

func (e *exchangeRejection) Error() string { return e.reason }

func rejectf(format string, args ...any) error {
	return &exchangeRejection{reason: fmt.Sprintf(format, args...)}
}

// externalSubject is what a verified external token contributes to an
// exchange: who the user is and, for an issuer allowed to assert them, the
// user's groups.
type externalSubject struct {
	Issuer  string
	Subject string
	// IdentityIssuer is the issuer the account is looked up under: the
	// entry's IdentityIssuer, which is Issuer unless the identity is relayed.
	IdentityIssuer string
	// Groups holds the token's group claim and GroupsAsserted whether the
	// token carried one at all: a missing claim is not an assertion that
	// the user belongs to no groups. Both are set only for an entry with
	// AssertGroups.
	Groups         []string
	GroupsAsserted bool
	JTI            string
	ExpiresAt      time.Time
}

// externalSigningAlgs are the algorithms an external token may be signed
// with. Symmetric algorithms and "none" are never acceptable: the keys come
// from a public JWKS.
var externalSigningAlgs = map[jwa.SignatureAlgorithm]bool{
	jwa.RS256: true, jwa.RS384: true, jwa.RS512: true,
	jwa.PS256: true, jwa.PS384: true, jwa.PS512: true,
	jwa.ES256: true, jwa.ES384: true, jwa.ES512: true,
	jwa.EdDSA: true,
}

// signingKeySource yields the keys that may verify a token from issuer whose
// header names kid.
type signingKeySource interface {
	keysFor(ctx context.Context, issuer, kid string) (jwk.Set, error)
}

// validateExternalSubjectToken verifies a subject_token minted by the
// external issuer entry describes and returns who it identifies. Errors of
// type *exchangeRejection are the presenter's fault; any other error (such as
// failing to fetch the issuer's keys) is the server's.
func validateExternalSubjectToken(ctx context.Context, raw string, entry *ExternalTokenIssuer, keys signingKeySource, now time.Time, skew time.Duration) (*externalSubject, error) {
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, rejectf("subject_token is not a signed JWT")
	}
	signatures := msg.Signatures()
	if len(signatures) != 1 {
		return nil, rejectf("subject_token must carry exactly one signature")
	}
	headers := signatures[0].ProtectedHeaders()
	if alg := headers.Algorithm(); !externalSigningAlgs[alg] {
		return nil, rejectf("subject_token is signed with %q, which is not accepted", alg)
	}

	set, err := keys.keysFor(ctx, entry.Issuer, headers.KeyID())
	if err != nil {
		return nil, fmt.Errorf("failed to obtain the signing keys of %s: %w", entry.Issuer, err)
	}
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithRequireKid(true)),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, rejectf("subject_token signature does not verify against the keys of %s", entry.Issuer)
	}

	if err := jwt.Validate(tok,
		jwt.WithIssuer(entry.Issuer),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithAcceptableSkew(skew),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
	); err != nil {
		return nil, rejectf("subject_token is not valid now: %v", err)
	}
	if !containsAny(tok.Audience(), entry.Audiences) {
		return nil, rejectf("subject_token was not issued for this server: its aud %v names none of %v", tok.Audience(), entry.Audiences)
	}
	if entry.MaxTokenAge > 0 {
		issuedAt := tok.IssuedAt()
		if issuedAt.IsZero() {
			return nil, rejectf("subject_token has no iat claim, so its age cannot be checked")
		}
		if age := now.Sub(issuedAt); age > entry.MaxTokenAge+skew {
			return nil, rejectf("subject_token was issued %s ago, longer than the %s allowed", age.Round(time.Second), entry.MaxTokenAge)
		}
	}
	for _, requirement := range entry.RequiredClaims {
		value, ok := tok.Get(requirement.Claim)
		if !ok || !claimHasValue(value, requirement.Value) {
			return nil, rejectf("subject_token does not carry %s=%q", requirement.Claim, requirement.Value)
		}
	}

	subject, err := stringClaim(tok, entry.SubjectClaim)
	if err != nil {
		return nil, err
	}
	result := &externalSubject{
		Issuer:         entry.Issuer,
		Subject:        subject,
		IdentityIssuer: entry.IdentityIssuer,
		JTI:            tok.JwtID(),
		ExpiresAt:      tok.Expiration(),
	}
	if entry.SingleUse && result.JTI == "" {
		return nil, rejectf("subject_token has no jti claim, which single-use exchange requires")
	}
	if entry.AssertGroups {
		if value, ok := tok.Get(entry.GroupClaim); ok {
			result.Groups = parseGroupClaim(value)
			result.GroupsAsserted = true
		}
	}
	return result, nil
}

// stringClaim reads a claim identifying the user. Numeric identifiers (such
// as GitHub's) are accepted when they are exact integers, as at login.
func stringClaim(tok jwt.Token, claim string) (string, error) {
	if claim == jwt.SubjectKey {
		if subject := tok.Subject(); subject != "" {
			return subject, nil
		}
		return "", rejectf("subject_token has no sub claim")
	}
	value, ok := tok.Get(claim)
	if !ok {
		return "", rejectf("subject_token has no %s claim", claim)
	}
	switch v := value.(type) {
	case string:
		if v != "" {
			return v, nil
		}
	case float64:
		if v >= 0 && v <= 1<<53 && v == math.Trunc(v) {
			return strconv.FormatInt(int64(v), 10), nil
		}
	}
	return "", rejectf("subject_token's %s claim is not a usable identifier", claim)
}

// claimHasValue reports whether a claim equals want or, for an array claim,
// contains it.
func claimHasValue(value interface{}, want string) bool {
	switch v := value.(type) {
	case string:
		return v == want
	case []string:
		return slices.Contains(v, want)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case bool:
		return strconv.FormatBool(v) == want
	}
	return false
}

// parseGroupClaim reads a group claim the way browser login does: either a
// comma-separated string or an array of strings.
func parseGroupClaim(value interface{}) []string {
	var raw []string
	switch v := value.(type) {
	case string:
		raw = strings.Split(v, ",")
	case []string:
		raw = v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	groups := make([]string, 0, len(raw))
	for _, group := range raw {
		if group = strings.TrimSpace(group); group != "" && !slices.Contains(groups, group) {
			groups = append(groups, group)
		}
	}
	return groups
}

func containsAny(have, want []string) bool {
	for _, w := range want {
		if slices.Contains(have, w) {
			return true
		}
	}
	return false
}

// subjectTokenReplayKey is the replay-table key recording that a token was
// exchanged at one namespace's issuer. Hashing keeps the key short and apart
// from the client-assertion JTIs stored in the same table.
func subjectTokenReplayKey(namespace, issuer, jti string) string {
	sum := sha256.Sum256([]byte(namespace + "\x00" + issuer + "\x00" + jti))
	return "token-exchange:" + hex.EncodeToString(sum[:])
}

// externalKeyCache caches the signing keys of external issuers. Keys are
// refetched once they are older than ttl, or sooner when a token names a key
// the cache lacks, which is how a rotation at the issuer is picked up. Either
// way, an issuer is contacted at most once per minRefetch, whatever tokens
// arrive, and stale keys are never used once the issuer cannot be reached.
type externalKeyCache struct {
	fetch      func(ctx context.Context, issuer string) (jwk.Set, error)
	ttl        time.Duration
	minRefetch time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]externalKeyEntry
}

type externalKeyEntry struct {
	set         jwk.Set   // nil until a fetch succeeds
	fetchedAt   time.Time // last successful fetch
	attemptedAt time.Time // last fetch attempt, successful or not
	err         error     // error of the last attempt, if it failed
}

func newExternalKeyCache(fetch func(ctx context.Context, issuer string) (jwk.Set, error), ttl, minRefetch time.Duration) *externalKeyCache {
	return &externalKeyCache{
		fetch:      fetch,
		ttl:        ttl,
		minRefetch: minRefetch,
		now:        time.Now,
		entries:    map[string]externalKeyEntry{},
	}
}

func (c *externalKeyCache) keysFor(ctx context.Context, issuer, kid string) (jwk.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	entry := c.entries[issuer]
	fresh := entry.set != nil && now.Sub(entry.fetchedAt) < c.ttl
	if fresh {
		if _, ok := entry.set.LookupKeyID(kid); ok || kid == "" {
			return entry.set, nil
		}
	}
	// The keys are missing or stale, or the token names a key we lack (a
	// rotation, or a forgery). Refetch, but not more than once per
	// minRefetch.
	if !entry.attemptedAt.IsZero() && now.Sub(entry.attemptedAt) < c.minRefetch {
		if fresh {
			return entry.set, nil
		}
		if entry.err != nil {
			return nil, entry.err
		}
	}
	set, err := c.fetch(ctx, issuer)
	entry.attemptedAt = now
	entry.err = err
	if err == nil {
		entry.set = publicSigningKeys(set)
		entry.fetchedAt = now
	}
	c.entries[issuer] = entry
	if entry.set != nil && now.Sub(entry.fetchedAt) < c.ttl {
		return entry.set, nil
	}
	return nil, err
}

// publicSigningKeys keeps only the asymmetric public keys of set that may be
// used for signatures.
func publicSigningKeys(set jwk.Set) jwk.Set {
	kept := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		switch key.KeyType() {
		case jwa.RSA, jwa.EC, jwa.OKP:
		default:
			continue
		}
		if usage := key.KeyUsage(); usage != "" && usage != string(jwk.ForSignature) {
			continue
		}
		public, err := key.PublicKey()
		if err != nil {
			continue
		}
		_ = kept.AddKey(public)
	}
	return kept
}

// authorizationDetail is one RFC 9396 authorization_details entry, here
// describing access the caller holds rather than access requested.
type authorizationDetail struct {
	Type       string   `json:"type"`
	Locations  []string `json:"locations,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
	Actions    []string `json:"actions"`
}

const (
	// authorizationDetailStorage describes data access beneath a path.
	authorizationDetailStorage = "pelican_storage"
	// authorizationDetailCollection describes rights over a collection record.
	authorizationDetailCollection = "pelican_collection"
)

var (
	storageScopeActions = map[string]string{
		"storage.read":   "read",
		"storage.create": "create",
		"storage.modify": "modify",
	}
	collectionScopeActions = map[string]string{
		"collection.read":   "read",
		"collection.modify": "modify",
		"collection.delete": "delete",
	}
	actionRank = map[string]int{"read": 0, "create": 1, "modify": 2, "delete": 3}
)

// describeGrantedAccess turns scopes into authorization_details: one
// pelican_storage entry per path, listing the storage actions allowed there,
// and one pelican_collection entry per collection ID. location maps an
// issuer-relative scope path to what an application should be shown, such
// as a pelican:// URL. Scopes that name nothing specific (openid, the
// collection.read:/ baseline, and so on) are left out.
func describeGrantedAccess(scopes []string, location func(scopePath string) string) []authorizationDetail {
	storage := map[string][]string{}
	collections := map[string][]string{}
	for _, scope := range scopes {
		name, arg, ok := strings.Cut(scope, ":")
		if !ok || arg == "" {
			continue
		}
		if action, ok := storageScopeActions[name]; ok {
			scopePath := path.Clean("/" + arg)
			storage[scopePath] = withAction(storage[scopePath], action)
		} else if action, ok := collectionScopeActions[name]; ok && !strings.HasPrefix(arg, "/") {
			collections[arg] = withAction(collections[arg], action)
		}
	}
	details := make([]authorizationDetail, 0, len(storage)+len(collections))
	for _, scopePath := range slices.Sorted(maps.Keys(storage)) {
		details = append(details, authorizationDetail{
			Type:      authorizationDetailStorage,
			Locations: []string{location(scopePath)},
			Actions:   storage[scopePath],
		})
	}
	for _, id := range slices.Sorted(maps.Keys(collections)) {
		details = append(details, authorizationDetail{
			Type:       authorizationDetailCollection,
			Identifier: id,
			Actions:    collections[id],
		})
	}
	return details
}

func withAction(actions []string, action string) []string {
	if slices.Contains(actions, action) {
		return actions
	}
	actions = append(actions, action)
	slices.SortFunc(actions, func(a, b string) int { return actionRank[a] - actionRank[b] })
	return actions
}
