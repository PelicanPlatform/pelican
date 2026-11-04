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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testExternalIssuer = "https://keycloak.example.org/realms/ndp"
	testOwnIssuer      = "https://origin.example.org:8444"
)

var testNow = time.Date(2026, 10, 27, 16, 0, 0, 0, time.UTC)

type testIssuerKey struct {
	private jwk.Key
	public  jwk.Set
}

func newTestIssuerKey(t *testing.T, kid string) *testIssuerKey {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	private, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.KeyIDKey, kid))
	require.NoError(t, private.Set(jwk.AlgorithmKey, jwa.ES256))
	public, err := private.PublicKey()
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(public))
	return &testIssuerKey{private: private, public: set}
}

func buildToken(t *testing.T, claims map[string]interface{}) jwt.Token {
	t.Helper()
	tok := jwt.New()
	for name, value := range claims {
		require.NoError(t, tok.Set(name, value))
	}
	return tok
}

func (k *testIssuerKey) sign(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	signed, err := jwt.Sign(buildToken(t, claims), jwt.WithKey(jwa.ES256, k.private))
	require.NoError(t, err)
	return string(signed)
}

// staticKeys serves key's public keys as the issuer's JWKS.
func staticKeys(key *testIssuerKey) *externalKeyCache {
	return newExternalKeyCache(func(context.Context, string) (jwk.Set, error) {
		return key.public, nil
	}, time.Hour, time.Minute)
}

// validClaims are what a Keycloak access token retargeted at Pelican through
// standard token exchange carries.
func validClaims() map[string]interface{} {
	return map[string]interface{}{
		jwt.IssuerKey:     testExternalIssuer,
		jwt.SubjectKey:    "3f1c2a9e-user",
		jwt.AudienceKey:   []string{"pelican-origin"},
		jwt.IssuedAtKey:   testNow.Add(-time.Minute),
		jwt.ExpirationKey: testNow.Add(4 * time.Minute),
		jwt.JwtIDKey:      "jti-1",
		"azp":             "ndp-jupyterhub",
		"groups":          []string{"/climate", "staff"},
	}
}

func testEntry(t *testing.T, mutate func(*ExternalTokenIssuer)) *ExternalTokenIssuer {
	t.Helper()
	entry := ExternalTokenIssuer{
		Issuer:         testExternalIssuer,
		Audiences:      []string{"pelican-origin"},
		AllowedClients: []string{"ndp-jupyterhub"},
		RequiredClaims: []ClaimRequirement{{Claim: "azp", Value: "ndp-jupyterhub"}},
		AssertGroups:   true,
		MaxTokenAge:    10 * time.Minute,
		SingleUse:      true,
	}
	if mutate != nil {
		mutate(&entry)
	}
	normalized, err := normalizeExternalIssuers([]ExternalTokenIssuer{entry}, testOwnIssuer, testExternalIssuer, "groups")
	require.NoError(t, err)
	return &normalized[0]
}

func TestNormalizeExternalIssuers(t *testing.T) {
	valid := func() ExternalTokenIssuer {
		return ExternalTokenIssuer{
			Issuer:         testExternalIssuer,
			Audiences:      []string{"pelican-origin"},
			AllowedClients: []string{"ndp-jupyterhub"},
		}
	}

	t.Run("fills defaults", func(t *testing.T) {
		entry := valid()
		entry.AssertGroups = true
		normalized, err := normalizeExternalIssuers([]ExternalTokenIssuer{entry}, testOwnIssuer, testExternalIssuer+"/", "")
		require.NoError(t, err)
		require.Len(t, normalized, 1)
		assert.Equal(t, "sub", normalized[0].SubjectClaim)
		assert.Equal(t, []string{tokenTypeAccessToken, tokenTypeJWT}, normalized[0].SubjectTokenTypes)
		assert.Equal(t, "groups", normalized[0].GroupClaim)
		assert.Equal(t, testExternalIssuer, normalized[0].IdentityIssuer)
	})

	t.Run("rejects duplicates", func(t *testing.T) {
		_, err := normalizeExternalIssuers([]ExternalTokenIssuer{valid(), valid()}, testOwnIssuer, "", "")
		assert.ErrorContains(t, err, "more than once")
	})

	tests := []struct {
		name              string
		mutate            func(*ExternalTokenIssuer)
		groupSourceIssuer string
		want              string
	}{
		{"plain http issuer", func(e *ExternalTokenIssuer) { e.Issuer = "http://keycloak.example.org/realms/ndp" }, "", "https URL"},
		{"no audiences", func(e *ExternalTokenIssuer) { e.Audiences = []string{" "} }, "", "Audiences"},
		{"no allowed clients", func(e *ExternalTokenIssuer) { e.AllowedClients = nil }, "", "AllowedClients"},
		{"this server's own issuer", func(e *ExternalTokenIssuer) { e.Issuer = testOwnIssuer + "/api/v1.0/issuer/ns/ndp" }, "", "own issuer"},
		{"groups from an issuer users do not sign in with", func(e *ExternalTokenIssuer) { e.AssertGroups = true }, "https://cilogon.org", "AssertGroups"},
		{"groups without an oidc group source", func(e *ExternalTokenIssuer) { e.AssertGroups = true }, "", "AssertGroups"},
		{"unsupported token type", func(e *ExternalTokenIssuer) {
			e.SubjectTokenTypes = []string{"urn:ietf:params:oauth:token-type:saml2"}
		}, "", "unsupported subject token type"},
		{"negative age", func(e *ExternalTokenIssuer) { e.MaxTokenAge = -time.Second }, "", "MaxTokenAge"},
		{"unnamed required claim", func(e *ExternalTokenIssuer) { e.RequiredClaims = []ClaimRequirement{{Value: "x"}} }, "", "RequiredClaims"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := valid()
			tt.mutate(&entry)
			_, err := normalizeExternalIssuers([]ExternalTokenIssuer{entry}, testOwnIssuer, tt.groupSourceIssuer, "")
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestValidateExternalSubjectTokenAccepts(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	subject, err := validateExternalSubjectToken(context.Background(), key.sign(t, validClaims()), testEntry(t, nil), staticKeys(key), testNow, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, testExternalIssuer, subject.Issuer)
	assert.Equal(t, "3f1c2a9e-user", subject.Subject)
	assert.Equal(t, []string{"/climate", "staff"}, subject.Groups)
	assert.True(t, subject.GroupsAsserted)
	assert.Equal(t, "jti-1", subject.JTI)
	assert.True(t, subject.ExpiresAt.Equal(testNow.Add(4*time.Minute)))
}

func hmacSignedToken(t *testing.T, kid string, claims map[string]interface{}) string {
	t.Helper()
	secret, err := jwk.FromRaw([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	require.NoError(t, secret.Set(jwk.KeyIDKey, kid))
	signed, err := jwt.Sign(buildToken(t, claims), jwt.WithKey(jwa.HS256, secret))
	require.NoError(t, err)
	return string(signed)
}

func unsignedToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(buildToken(t, claims))
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"kc-1"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func TestValidateExternalSubjectTokenRejects(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	forger := newTestIssuerKey(t, "kc-1") // claims the issuer's key ID
	with := func(change func(map[string]interface{})) string {
		claims := validClaims()
		change(claims)
		return key.sign(t, claims)
	}

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"meant for another audience", with(func(c map[string]interface{}) { c[jwt.AudienceKey] = []string{"some-other-app"} }), "not issued for this server"},
		{"different issuer", with(func(c map[string]interface{}) { c[jwt.IssuerKey] = "https://evil.example.org/realms/ndp" }), "iss"},
		{"expired", with(func(c map[string]interface{}) { c[jwt.ExpirationKey] = testNow.Add(-2 * time.Minute) }), "exp"},
		{"no expiry", with(func(c map[string]interface{}) { delete(c, jwt.ExpirationKey) }), "exp"},
		{"not yet valid", with(func(c map[string]interface{}) { c[jwt.NotBeforeKey] = testNow.Add(5 * time.Minute) }), "nbf"},
		{"too old", with(func(c map[string]interface{}) { c[jwt.IssuedAtKey] = testNow.Add(-20 * time.Minute) }), "issued"},
		{"issued to another client", with(func(c map[string]interface{}) { c["azp"] = "some-other-client" }), "azp"},
		{"no jti under single use", with(func(c map[string]interface{}) { delete(c, jwt.JwtIDKey) }), "jti"},
		{"no subject", with(func(c map[string]interface{}) { delete(c, jwt.SubjectKey) }), "sub"},
		{"forged signature", forger.sign(t, validClaims()), "does not verify"},
		{"symmetric algorithm", hmacSignedToken(t, "kc-1", validClaims()), "not accepted"},
		{"unsigned", unsignedToken(t, validClaims()), "subject_token"},
		{"not a JWT", "not-a-token", "not a signed JWT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateExternalSubjectToken(context.Background(), tt.token, testEntry(t, nil), staticKeys(key), testNow, time.Minute)
			require.Error(t, err)
			var rejection *exchangeRejection
			require.True(t, errors.As(err, &rejection), "want an invalid_grant rejection, got %v", err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestValidateExternalSubjectTokenGroups(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")

	t.Run("ignored unless the issuer may assert groups", func(t *testing.T) {
		entry := testEntry(t, func(e *ExternalTokenIssuer) { e.AssertGroups = false })
		subject, err := validateExternalSubjectToken(context.Background(), key.sign(t, validClaims()), entry, staticKeys(key), testNow, time.Minute)
		require.NoError(t, err)
		assert.Nil(t, subject.Groups)
		assert.False(t, subject.GroupsAsserted)
	})

	t.Run("a missing claim asserts nothing", func(t *testing.T) {
		claims := validClaims()
		delete(claims, "groups")
		subject, err := validateExternalSubjectToken(context.Background(), key.sign(t, claims), testEntry(t, nil), staticKeys(key), testNow, time.Minute)
		require.NoError(t, err)
		assert.False(t, subject.GroupsAsserted)
	})

	t.Run("comma-separated string", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b"}, parseGroupClaim("a, b,,a"))
	})
}

func TestValidateExternalSubjectTokenNumericSubject(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	claims := validClaims()
	claims["uid"] = 12345
	entry := testEntry(t, func(e *ExternalTokenIssuer) { e.SubjectClaim = "uid" })
	subject, err := validateExternalSubjectToken(context.Background(), key.sign(t, claims), entry, staticKeys(key), testNow, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "12345", subject.Subject)
}

func TestValidateExternalSubjectTokenKeyFetchFailureIsServerError(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	unreachable := newExternalKeyCache(func(context.Context, string) (jwk.Set, error) {
		return nil, errors.New("connection refused")
	}, time.Hour, time.Minute)
	_, err := validateExternalSubjectToken(context.Background(), key.sign(t, validClaims()), testEntry(t, nil), unreachable, testNow, time.Minute)
	require.Error(t, err)
	var rejection *exchangeRejection
	assert.False(t, errors.As(err, &rejection), "an unreachable issuer is not the client's fault")
}

func TestExternalKeyCache(t *testing.T) {
	ctx := context.Background()
	first := newTestIssuerKey(t, "kc-1")
	second := newTestIssuerKey(t, "kc-2")
	rotated := jwk.NewSet()
	for _, set := range []jwk.Set{first.public, second.public} {
		key, ok := set.Key(0)
		require.True(t, ok)
		require.NoError(t, rotated.AddKey(key))
	}

	served := first.public
	unreachable := false
	fetches := 0
	cache := newExternalKeyCache(func(context.Context, string) (jwk.Set, error) {
		fetches++
		if unreachable {
			return nil, errors.New("issuer unreachable")
		}
		return served, nil
	}, time.Hour, time.Minute)
	now := testNow
	cache.now = func() time.Time { return now }

	_, err := cache.keysFor(ctx, testExternalIssuer, "kc-1")
	require.NoError(t, err)
	_, err = cache.keysFor(ctx, testExternalIssuer, "kc-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetches, "a known key is served from the cache")

	served = rotated
	set, err := cache.keysFor(ctx, testExternalIssuer, "kc-2")
	require.NoError(t, err)
	assert.Equal(t, 1, fetches, "unknown key IDs do not refetch more than once per minRefetch")
	_, found := set.LookupKeyID("kc-2")
	assert.False(t, found)

	now = now.Add(2 * time.Minute)
	set, err = cache.keysFor(ctx, testExternalIssuer, "kc-2")
	require.NoError(t, err)
	assert.Equal(t, 2, fetches)
	_, found = set.LookupKeyID("kc-2")
	assert.True(t, found, "a rotated-in key is picked up")

	unreachable = true
	now = now.Add(2 * time.Minute)
	set, err = cache.keysFor(ctx, testExternalIssuer, "kc-3")
	require.NoError(t, err, "a failed refetch for an unknown key keeps the fresh keys")
	assert.Equal(t, 2, set.Len())
	assert.Equal(t, 3, fetches)

	now = now.Add(2 * time.Hour)
	_, err = cache.keysFor(ctx, testExternalIssuer, "kc-1")
	require.Error(t, err, "stale keys are not used once the issuer cannot be reached")
	_, err = cache.keysFor(ctx, testExternalIssuer, "kc-1")
	require.Error(t, err)
	assert.Equal(t, 4, fetches, "a failing issuer is not retried more than once per minRefetch")
}

func TestPublicSigningKeysDropsUnusableKeys(t *testing.T) {
	set := jwk.NewSet()
	signing, ok := newTestIssuerKey(t, "sig").public.Key(0)
	require.True(t, ok)
	require.NoError(t, set.AddKey(signing))

	secret, err := jwk.FromRaw([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	require.NoError(t, secret.Set(jwk.KeyIDKey, "hmac"))
	require.NoError(t, set.AddKey(secret))

	encryption, ok := newTestIssuerKey(t, "enc").public.Key(0)
	require.True(t, ok)
	require.NoError(t, encryption.Set(jwk.KeyUsageKey, jwk.ForEncryption))
	require.NoError(t, set.AddKey(encryption))

	kept := publicSigningKeys(set)
	assert.Equal(t, 1, kept.Len())
	_, found := kept.LookupKeyID("sig")
	assert.True(t, found)
}

func TestUnverifiedIssuer(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	assert.Equal(t, testExternalIssuer, unverifiedIssuer(key.sign(t, validClaims())))
	assert.Equal(t, "", unverifiedIssuer("an-opaque-refresh-token"))
}

func TestMatchExternalIssuer(t *testing.T) {
	entries := []ExternalTokenIssuer{*testEntry(t, nil)}
	assert.NotNil(t, matchExternalIssuer(entries, testExternalIssuer))
	assert.Nil(t, matchExternalIssuer(entries, testExternalIssuer+"/"), "issuers must match exactly")
	assert.Nil(t, matchExternalIssuer(entries, "https://other.example.org"))
}

func TestSubjectTokenReplayKey(t *testing.T) {
	key := subjectTokenReplayKey("/ndp", testExternalIssuer, "jti-1")
	assert.Equal(t, key, subjectTokenReplayKey("/ndp", testExternalIssuer, "jti-1"))
	assert.NotEqual(t, key, subjectTokenReplayKey("/other", testExternalIssuer, "jti-1"))
	assert.NotEqual(t, key, subjectTokenReplayKey("/ndp", "https://other.example.org", "jti-1"))
	assert.NotEqual(t, key, subjectTokenReplayKey("/ndp", testExternalIssuer, "jti-2"))
	assert.LessOrEqual(t, len(key), 100)
}

func TestDescribeGrantedAccess(t *testing.T) {
	scopes := []string{
		"openid", "pelican.transfer", "collection.read:/", "collection.create:/",
		"storage.read:/climate",
		"storage.modify:/climate/alice", "storage.create:/climate/alice", "storage.read:/climate/alice",
		"storage.read:/",
		"collection.read:abc123", "collection.modify:abc123",
	}
	details := describeGrantedAccess(scopes, func(scopePath string) string {
		return "pelican://osg-htc.org/ndp" + scopePath
	})
	assert.Equal(t, []authorizationDetail{
		{Type: authorizationDetailStorage, Locations: []string{"pelican://osg-htc.org/ndp/"}, Actions: []string{"read"}},
		{Type: authorizationDetailStorage, Locations: []string{"pelican://osg-htc.org/ndp/climate"}, Actions: []string{"read"}},
		{Type: authorizationDetailStorage, Locations: []string{"pelican://osg-htc.org/ndp/climate/alice"}, Actions: []string{"read", "create", "modify"}},
		{Type: authorizationDetailCollection, Identifier: "abc123", Actions: []string{"read", "modify"}},
	}, details)

	encoded, err := json.Marshal(details[3])
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"pelican_collection","identifier":"abc123","actions":["read","modify"]}`, string(encoded))
}

const testUpstreamIssuer = "https://cilogon.org"

// relayEntry trusts a Keycloak realm that brokers CILogon logins and relays
// the CILogon subject in an upstream_sub claim, for an origin whose own web
// login also uses CILogon.
func relayEntry(t *testing.T) *ExternalTokenIssuer {
	t.Helper()
	normalized, err := normalizeExternalIssuers([]ExternalTokenIssuer{{
		Issuer:         testExternalIssuer,
		IdentityIssuer: testUpstreamIssuer,
		SubjectClaim:   "upstream_sub",
		Audiences:      []string{"pelican-origin"},
		AllowedClients: []string{"ndp-jupyterhub"},
		RequiredClaims: []ClaimRequirement{
			{Claim: "azp", Value: "ndp-jupyterhub"},
			{Claim: "identity_provider", Value: "cilogon"},
		},
	}}, testOwnIssuer, testUpstreamIssuer, "groups")
	require.NoError(t, err)
	return &normalized[0]
}

func relayClaims() map[string]interface{} {
	claims := validClaims()
	claims["upstream_sub"] = "http://cilogon.org/serverA/users/12345"
	claims["identity_provider"] = "cilogon"
	return claims
}

func TestValidateExternalSubjectTokenRelayedIdentity(t *testing.T) {
	key := newTestIssuerKey(t, "kc-1")
	validate := func(claims map[string]interface{}) (*externalSubject, error) {
		return validateExternalSubjectToken(context.Background(), key.sign(t, claims), relayEntry(t), staticKeys(key), testNow, time.Minute)
	}

	t.Run("maps the relayed upstream identity", func(t *testing.T) {
		subject, err := validate(relayClaims())
		require.NoError(t, err)
		assert.Equal(t, testExternalIssuer, subject.Issuer, "the token is still verified as the broker's")
		assert.Equal(t, testUpstreamIssuer, subject.IdentityIssuer)
		assert.Equal(t, "http://cilogon.org/serverA/users/12345", subject.Subject)
		assert.False(t, subject.GroupsAsserted, "relayed tokens never assert groups")
	})

	t.Run("a login through another provider is refused", func(t *testing.T) {
		claims := relayClaims()
		claims["identity_provider"] = "github"
		_, err := validate(claims)
		var rejection *exchangeRejection
		require.True(t, errors.As(err, &rejection))
		assert.ErrorContains(t, err, "identity_provider")
	})

	t.Run("a broker-local account without a relayed subject is refused", func(t *testing.T) {
		claims := relayClaims()
		delete(claims, "upstream_sub")
		_, err := validate(claims)
		var rejection *exchangeRejection
		require.True(t, errors.As(err, &rejection))
		assert.ErrorContains(t, err, "upstream_sub")
	})
}

func TestNormalizeRelayedIdentity(t *testing.T) {
	relay := func() ExternalTokenIssuer {
		return ExternalTokenIssuer{
			Issuer:         testExternalIssuer,
			IdentityIssuer: testUpstreamIssuer,
			SubjectClaim:   "upstream_sub",
			Audiences:      []string{"pelican-origin"},
			AllowedClients: []string{"ndp-jupyterhub"},
			RequiredClaims: []ClaimRequirement{{Claim: "identity_provider", Value: "cilogon"}},
		}
	}

	t.Run("accepted when bound to the upstream login", func(t *testing.T) {
		normalized, err := normalizeExternalIssuers([]ExternalTokenIssuer{relay()}, testOwnIssuer, testUpstreamIssuer, "")
		require.NoError(t, err)
		assert.Equal(t, testUpstreamIssuer, normalized[0].IdentityIssuer)
	})

	tests := []struct {
		name   string
		mutate func(*ExternalTokenIssuer)
		want   string
	}{
		{"broker's own subject by default", func(e *ExternalTokenIssuer) { e.SubjectClaim = "" }, "SubjectClaim"},
		{"broker's own subject named", func(e *ExternalTokenIssuer) { e.SubjectClaim = "sub" }, "SubjectClaim"},
		{"no binding to the upstream login", func(e *ExternalTokenIssuer) { e.RequiredClaims = nil }, "RequiredClaims"},
		{"plain http", func(e *ExternalTokenIssuer) { e.IdentityIssuer = "http://cilogon.org" }, "https URL"},
		{"this server's own identities", func(e *ExternalTokenIssuer) { e.IdentityIssuer = testOwnIssuer }, "own issuer"},
		{"relayed groups", func(e *ExternalTokenIssuer) { e.AssertGroups = true }, "AssertGroups"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := relay()
			tt.mutate(&entry)
			_, err := normalizeExternalIssuers([]ExternalTokenIssuer{entry}, testOwnIssuer, testUpstreamIssuer, "")
			assert.ErrorContains(t, err, tt.want)
		})
	}
}
