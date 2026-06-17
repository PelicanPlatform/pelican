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

package lotman

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestGetBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("from-authorization-header", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer abc.def.ghi")
		ctx.Request = req
		assert.Equal(t, "abc.def.ghi", getBearerToken(ctx))
	})

	t.Run("from-authz-query", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		req, _ := http.NewRequest(http.MethodGet, "/?authz=Bearer%20zzz", nil)
		ctx.Request = req
		// Query value is URL-decoded by url.Values, then we strip "Bearer ".
		assert.Equal(t, "zzz", getBearerToken(ctx))
	})

	// Concern #3: the login cookie must NOT be silently re-interpreted as
	// a bearer token. This is the regression test for the cookie/JWT
	// confusion bug.
	t.Run("does-not-fall-back-to-login-cookie", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "login", Value: "should-not-be-used"})
		ctx.Request = req
		assert.Equal(t, "", getBearerToken(ctx),
			"login cookie must not be re-interpreted as a bearer token")
	})

	t.Run("nothing-present", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		ctx.Request = req
		assert.Equal(t, "", getBearerToken(ctx))
	})
}

func TestScopesContain(t *testing.T) {
	scopes := []string{"a", "b", token_scopes.Lot_Read.String()}
	assert.True(t, scopesContain(scopes, token_scopes.Lot_Read))
	assert.False(t, scopesContain(scopes, token_scopes.Lot_Modify))
	assert.False(t, scopesContain(nil, token_scopes.Lot_Read))
	assert.False(t, scopesContain([]string{}, token_scopes.Lot_Read))
}

func TestExtractScopes(t *testing.T) {
	t.Run("string-scope", func(t *testing.T) {
		tok, err := jwt.NewBuilder().Claim("scope", "lot.read lot.modify").Build()
		require.NoError(t, err)
		got, err := extractScopes(tok)
		require.NoError(t, err)
		assert.Equal(t, []string{"lot.read", "lot.modify"}, got)
	})

	t.Run("missing-scope", func(t *testing.T) {
		tok, err := jwt.NewBuilder().Build()
		require.NoError(t, err)
		_, err = extractScopes(tok)
		require.Error(t, err)
	})

	t.Run("non-string-scope", func(t *testing.T) {
		tok, err := jwt.NewBuilder().Claim("scope", 42).Build()
		require.NoError(t, err)
		_, err = extractScopes(tok)
		require.Error(t, err)
	})
}

func TestVerifyTokenSignedByAnyIssuer(t *testing.T) {
	// Spin up a tiny issuer that publishes openid-configuration + JWKS.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv, err := jwk.FromRaw(rsaKey)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.RS256))
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "sig"))
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pub))

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_, _ = w.Write([]byte(`{"jwks_uri": "` + base + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := json.Marshal(jwks)
		_, _ = w.Write(raw)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mintToken := func(scope string) string {
		tok, err := jwt.NewBuilder().
			Issuer(srv.URL).
			Subject("test").
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(time.Hour)).
			Claim("scope", scope).
			Build()
		require.NoError(t, err)
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv))
		require.NoError(t, err)
		return string(signed)
	}

	t.Run("accepts-token-from-listed-issuer", func(t *testing.T) {
		signed := mintToken(token_scopes.Lot_Read.String())
		ok, parsed, err := verifyTokenSignedByAnyIssuer(signed, []string{srv.URL})
		require.NoError(t, err)
		require.True(t, ok)
		require.NotNil(t, parsed)
		assert.Equal(t, srv.URL, (*parsed).Issuer())
	})

	t.Run("rejects-token-when-issuer-not-listed", func(t *testing.T) {
		signed := mintToken(token_scopes.Lot_Read.String())
		// Use a URL that does not serve the JWKS so the lookup fails.
		bogus, _ := url.Parse(srv.URL)
		bogus.Host = "127.0.0.1:1" // unlikely to be reachable
		ok, _, err := verifyTokenSignedByAnyIssuer(signed, []string{bogus.String()})
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("rejects-malformed-token", func(t *testing.T) {
		ok, _, err := verifyTokenSignedByAnyIssuer("not-a-jwt", []string{srv.URL})
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("empty-caller-list", func(t *testing.T) {
		signed := mintToken(token_scopes.Lot_Read.String())
		ok, _, err := verifyTokenSignedByAnyIssuer(signed, nil)
		require.Error(t, err)
		require.False(t, ok)
	})
}

func TestNormalizeWindow(t *testing.T) {
	t.Run("zero-from-becomes-now", func(t *testing.T) {
		before := time.Now().UnixMilli()
		from, to := normalizeWindow(0, 0)
		after := time.Now().UnixMilli()
		assert.GreaterOrEqual(t, from, before)
		assert.LessOrEqual(t, from, after)
		assert.Equal(t, from+1, to)
	})

	t.Run("explicit-from-zero-to", func(t *testing.T) {
		from, to := normalizeWindow(1000, 0)
		assert.Equal(t, int64(1000), from)
		assert.Equal(t, int64(1001), to)
	})

	t.Run("to-already-greater-than-from", func(t *testing.T) {
		from, to := normalizeWindow(100, 200)
		assert.Equal(t, int64(100), from)
		assert.Equal(t, int64(200), to)
	})

	t.Run("to-equal-to-from-bumped", func(t *testing.T) {
		from, to := normalizeWindow(500, 500)
		assert.Equal(t, int64(500), from)
		assert.Equal(t, int64(501), to)
	})

	t.Run("to-less-than-from-bumped", func(t *testing.T) {
		from, to := normalizeWindow(500, 100)
		assert.Equal(t, int64(500), from)
		assert.Equal(t, int64(501), to)
	})
}

func TestValidatePatchedMPA(t *testing.T) {
	mk := func(c, e, d int64) *MPA {
		mpa := &MPA{}
		if c != 0 {
			mpa.CreationTime = &Int64FromFloat{Value: c}
		}
		if e != 0 {
			mpa.ExpirationTime = &Int64FromFloat{Value: e}
		}
		if d != 0 {
			mpa.DeletionTime = &Int64FromFloat{Value: d}
		}
		return mpa
	}

	t.Run("nil-existing-fully-specified-patch", func(t *testing.T) {
		require.NoError(t, validatePatchedMPA(nil, mk(100, 200, 300)))
	})

	t.Run("creation-ge-expiration", func(t *testing.T) {
		require.Error(t, validatePatchedMPA(nil, mk(200, 200, 300)))
		require.Error(t, validatePatchedMPA(nil, mk(300, 200, 400)))
	})

	t.Run("expiration-gt-deletion", func(t *testing.T) {
		require.Error(t, validatePatchedMPA(nil, mk(100, 400, 200)))
	})

	t.Run("partial-patch-uses-existing", func(t *testing.T) {
		// existing has expiration=200, deletion=300; patch only updates
		// creation. Result must still pass.
		err := validatePatchedMPA(mk(0, 200, 300), mk(150, 0, 0))
		assert.NoError(t, err)

		// Same existing, but patch creation past expiration -> reject.
		err = validatePatchedMPA(mk(0, 200, 300), mk(250, 0, 0))
		assert.Error(t, err)
	})

	t.Run("partial-patch-detects-inverted-ordering", func(t *testing.T) {
		// existing has deletion=200; patch sets expiration=300 which
		// would invert ordering against existing deletion.
		err := validatePatchedMPA(mk(100, 0, 200), mk(0, 300, 0))
		assert.Error(t, err)
	})

	t.Run("empty-patched-mpa-is-noop", func(t *testing.T) {
		require.NoError(t, validatePatchedMPA(mk(100, 200, 300), &MPA{}))
	})
}

func TestComputeReservationStatus(t *testing.T) {
	now := int64(1_000_000_000)
	mk := func(c, e, d int64) *Lot {
		return &Lot{MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: c},
			ExpirationTime: &Int64FromFloat{Value: e},
			DeletionTime:   &Int64FromFloat{Value: d},
		}}
	}

	assert.Equal(t, ReservationStatusActive, computeReservationStatus(mk(100, now+100, now+200), now))
	assert.Equal(t, ReservationStatusPending, computeReservationStatus(mk(now+10, now+100, now+200), now))
	assert.Equal(t, ReservationStatusExpired, computeReservationStatus(mk(100, now-10, now+100), now))
	assert.Equal(t, ReservationStatusDeleted, computeReservationStatus(mk(100, now-100, now-10), now))
	assert.Equal(t, ReservationStatusUnknown, computeReservationStatus(&Lot{}, now))
}

func TestLotToReservation(t *testing.T) {
	ded := float64(10)
	opp := float64(20)
	lot := &Lot{
		LotName: "abc",
		Owner:   "https://issuer.example",
		Parents: []string{"root"},
		Paths:   []LotPath{{Path: "/foo", Recursive: true}},
		MPA: &MPA{
			DedicatedGB:     &ded,
			OpportunisticGB: &opp,
			MaxNumObjects:   &Int64FromFloat{Value: 99},
			CreationTime:    &Int64FromFloat{Value: 100},
			ExpirationTime:  &Int64FromFloat{Value: 200},
			DeletionTime:    &Int64FromFloat{Value: 300},
		},
	}
	r := lotToReservation(lot, 150)
	assert.Equal(t, "abc", r.ReservationID)
	assert.Equal(t, "https://issuer.example", r.Owner)
	assert.Equal(t, []string{"root"}, r.Parents)
	assert.Equal(t, []LotPathView{{Path: "/foo", Recursive: true}}, r.Paths)
	assert.Equal(t, ReservationStatusActive, r.Status)
	require.NotNil(t, r.DedicatedGB)
	assert.Equal(t, float64(10), *r.DedicatedGB)
	require.NotNil(t, r.OpportunisticGB)
	assert.Equal(t, float64(20), *r.OpportunisticGB)
	require.NotNil(t, r.MaxNumObjects)
	assert.Equal(t, int64(99), *r.MaxNumObjects)
	assert.Equal(t, int64(100), r.CreationTimeMs)
	assert.Equal(t, int64(200), r.ExpirationTimeMs)
	assert.Equal(t, int64(300), r.DeletionTimeMs)
}
