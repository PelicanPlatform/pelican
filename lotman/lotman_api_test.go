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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// setupLotsAPI brings up a real lotman instance plus a gin engine wired to
// /api/v1.0/lots/* and returns the engine, an admin login cookie and a
// teardown closure. The lotman config is the embedded yamlMockup, which
// pre-creates lots "test-1" and "test-2" with two paths.
//
// The login cookie is signed by the test-issuer key so web_ui.GetUserGroups
// validates it as a real user; the user "lots-admin" is added to
// Server.UIAdminUsers so CheckAdmin returns true.
func setupLotsAPI(t *testing.T) (*gin.Engine, *http.Cookie, func()) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	// Always restore config state at end-of-test, even if a sub-test panics or
	// returns early. This must run BEFORE the lotman teardown closure (Cleanup
	// stack is LIFO) so that nothing tries to use the in-test config after we
	// reset it.
	t.Cleanup(server_utils.ResetTestState)
	gin.SetMode(gin.TestMode)

	disc := getMockDiscoveryHost()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(disc.URL))

	tmp := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(tmp, "issuer-keys")))
	extURL := "https://lots-test.example"
	require.NoError(t, param.Server_ExternalWebUrl.Set(extURL))
	require.NoError(t, param.Server_UIAdminUsers.Set([]string{"lots-admin"}))

	success, lotCleanup := setupLotmanFromConf(t, true, "LotsAPI", disc.URL, nil)
	require.True(t, success, "InitLotman must succeed")

	// IssuerKeysDirectory was reset by setupLotmanFromConf.
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(tmp, "issuer-keys")))
	require.NoError(t, param.Server_ExternalWebUrl.Set(extURL))
	require.NoError(t, param.Server_UIAdminUsers.Set([]string{"lots-admin"}))

	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err, "issuer JWKS must initialize")

	cfg := token.NewWLCGToken()
	cfg.Lifetime = 1 * time.Hour
	cfg.Issuer = extURL
	cfg.AddAudiences(extURL)
	cfg.Subject = "lots-admin"
	cfg.AddScopes(token_scopes.WebUi_Access)
	cfg.Claims = map[string]string{
		"user_id":  "lots-admin",
		"oidc_sub": "lots-admin",
		"oidc_iss": extURL,
	}
	tok, err := cfg.CreateToken()
	require.NoError(t, err)

	cookie := &http.Cookie{Name: "login", Value: tok}

	engine := gin.New()
	require.NoError(t, RegisterLotsAPI(engine.Group("/")))

	teardown := func() {
		lotCleanup()
		disc.Close()
	}
	return engine, cookie, teardown
}

func doRequest(t *testing.T, eng *gin.Engine, method, target string, cookie *http.Cookie, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(raw)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, target, bodyReader)
	require.NoError(t, err)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	return rec
}

func TestLotsAPI_Unauthorized(t *testing.T) {
	eng, _, teardown := setupLotsAPI(t)
	defer teardown()

	rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	rec = doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/test-1", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	rec = doRequest(t, eng, http.MethodDelete, "/api/v1.0/lots/test-1", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
}

func TestLotsAPI_AdminCookie_Reads(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	t.Run("list", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp LotListResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp.Lots, "test-1")
		assert.Contains(t, resp.Lots, "test-2")
		assert.Contains(t, resp.Lots, "root")
	})

	t.Run("list with owner filter", func(t *testing.T) {
		// Look up test-1's actual owner so we can assert the filter
		// returns it (and not lots with a different owner).
		test1, err := GetLot("test-1", false)
		require.NoError(t, err)
		require.NotEmpty(t, test1.Owner, "fixture must have an owner")
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots?owner="+test1.Owner, cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp LotListResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Contains(t, resp.Lots, "test-1")

		// A bogus owner should produce an empty list, not 500/etc.
		rec = doRequest(t, eng, http.MethodGet, "/api/v1.0/lots?owner=https://nobody.example", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var empty LotListResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&empty))
		assert.Empty(t, empty.Lots)
	})

	t.Run("get one", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/test-1", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resv Reservation
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resv))
		assert.Equal(t, "test-1", resv.ReservationID)
	})

	t.Run("get children", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/test-1/children", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp LotChildrenResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "test-1", resp.LotName)
		assert.Contains(t, resp.Children, "test-2")
	})

	t.Run("policy", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/test-1/policy", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var pol LotPolicyResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&pol))
		assert.NotEmpty(t, pol.DedicatedGB.LotName)
	})

	t.Run("usage", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/test-1/usage", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var usage LotUsageResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&usage))
		_ = usage
	})

	t.Run("by-path", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/by-path?path=/test-1", cookie, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resvs []Reservation
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resvs))
		require.NotEmpty(t, resvs)
	})

	t.Run("capacity is public", func(t *testing.T) {
		rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/by-path/capacity?path=/test-1", nil, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var ac AvailableCapacityResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&ac))
		_ = ac
	})
}

// TestLotsAPI_CreateLot_AdminCookie verifies the headline behaviour: a
// caller can POST to /api/v1.0/lots WITHOUT supplying a lot_name and gets
// back a Reservation with a newly-minted UUID reservation_id. The created
// lot's Owner must match what a JWT-path create at the same path would
// produce (i.e. the namespace issuer URL or, when no namespace is
// registered, the federation issuer URL fallback).
func TestLotsAPI_CreateLot_AdminCookie(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	now := time.Now().UnixMilli()
	expiration := time.Now().Add(24 * time.Hour).UnixMilli()
	deletion := time.Now().Add(48 * time.Hour).UnixMilli()
	ded := float64(10)

	// No lot_name supplied: the server must mint a UUID and return it.
	t.Run("uuid-minted", func(t *testing.T) {
		body := CreateLotRequest{
			Paths: []LotPathInput{{Path: "/test-1/auto", Recursive: true}},
			ManagementPolicyAttrs: &MPAInput{
				DedicatedGB:      &ded,
				CreationTimeMs:   &now,
				ExpirationTimeMs: &expiration,
				DeletionTimeMs:   &deletion,
			},
		}
		rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots", cookie, body)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var resv Reservation
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resv))
		require.NotEmpty(t, resv.ReservationID, "reservation_id must be returned")
		_, err := uuid.Parse(resv.ReservationID)
		assert.NoError(t, err, "reservation_id must be a valid UUID, got %q", resv.ReservationID)
		assert.Equal(t, ReservationStatusActive, resv.Status)
		require.NotNil(t, resv.DedicatedGB)
		assert.Equal(t, float64(10), *resv.DedicatedGB)
		assert.NotEmpty(t, resv.Owner, "Owner must be populated by the server")
		assert.NotEmpty(t, resv.Parents, "Parents must be derived from the path")

		// The lot must be retrievable under the returned reservation id
		// AND its Owner must match the response (concern 4).
		lot, err := GetLot(resv.ReservationID, false)
		require.NoError(t, err)
		assert.Equal(t, resv.Owner, lot.Owner)
	})

	// Caller-supplied lot_name is honored (back-compat for callers who
	// have an existing identifier scheme).
	t.Run("explicit-name", func(t *testing.T) {
		body := CreateLotRequest{
			LotName: "explicit-name-lot",
			Paths:   []LotPathInput{{Path: "/test-1/explicit", Recursive: true}},
			ManagementPolicyAttrs: &MPAInput{
				DedicatedGB:      &ded,
				CreationTimeMs:   &now,
				ExpirationTimeMs: &expiration,
				DeletionTimeMs:   &deletion,
			},
		}
		rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots", cookie, body)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var resv Reservation
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resv))
		assert.Equal(t, "explicit-name-lot", resv.ReservationID)
	})

	// MPA defaults are applied when omitted (DedicatedGB is supplied
	// because the fixture's root lot has a bounded quota and forbids
	// unbounded children).
	t.Run("mpa-defaults-applied", func(t *testing.T) {
		body := CreateLotRequest{
			Paths:                 []LotPathInput{{Path: "/test-1/defaults", Recursive: true}},
			ManagementPolicyAttrs: &MPAInput{DedicatedGB: &ded},
		}
		rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots", cookie, body)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var resv Reservation
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resv))
		assert.NotZero(t, resv.CreationTimeMs)
		assert.Greater(t, resv.ExpirationTimeMs, resv.CreationTimeMs)
		assert.GreaterOrEqual(t, resv.DeletionTimeMs, resv.ExpirationTimeMs)
	})

	// Bad MPA (creation >= expiration) is rejected with 400 BEFORE
	// touching lotman.
	t.Run("bad-mpa-rejected", func(t *testing.T) {
		creation := int64(200)
		exp := int64(100)
		del := int64(300)
		body := CreateLotRequest{
			Paths: []LotPathInput{{Path: "/test-1/bad", Recursive: true}},
			ManagementPolicyAttrs: &MPAInput{
				DedicatedGB:      &ded,
				CreationTimeMs:   &creation,
				ExpirationTimeMs: &exp,
				DeletionTimeMs:   &del,
			},
		}
		rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots", cookie, body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	// Missing paths is rejected by binding.
	t.Run("missing-paths-rejected", func(t *testing.T) {
		body := map[string]any{} // no "paths" key at all
		rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots", cookie, body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})
}

func TestLotsAPI_AdminCookie_Modify(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	ded := float64(50)
	maxObj := int64(84)
	body := PatchLotRequest{
		ManagementPolicyAttrs: &MPAInput{
			DedicatedGB:   &ded,
			MaxNumObjects: &maxObj,
		},
	}
	rec := doRequest(t, eng, http.MethodPatch, "/api/v1.0/lots/test-1", cookie, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	lot, err := GetLot("test-1", true)
	require.NoError(t, err)
	require.NotNil(t, lot.MPA)
	require.NotNil(t, lot.MPA.DedicatedGB)
	assert.Equal(t, float64(50), *lot.MPA.DedicatedGB)
	assert.Equal(t, int64(84), lot.MPA.MaxNumObjects.Value)

	// Empty body -> 400.
	rec = doRequest(t, eng, http.MethodPatch, "/api/v1.0/lots/test-1", cookie, PatchLotRequest{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Patch that would invert MPA ordering (expiration moved past deletion)
	// must be rejected by the API BEFORE reaching lotman.
	t.Run("rejects-bad-ordering", func(t *testing.T) {
		// Move expiration after the existing deletion timestamp.
		existing, err := GetLot("test-1", false)
		require.NoError(t, err)
		require.NotNil(t, existing.MPA)
		require.NotNil(t, existing.MPA.DeletionTime)
		newExp := existing.MPA.DeletionTime.Value + 1000
		body := PatchLotRequest{
			ManagementPolicyAttrs: &MPAInput{
				ExpirationTimeMs: &newExp,
			},
		}
		rec := doRequest(t, eng, http.MethodPatch, "/api/v1.0/lots/test-1", cookie, body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})
}

func TestLotsAPI_AdminCookie_Reclaim(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	body := ReclaimLotRequest{Reason: "unit test"}
	rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots/test-2/reclaim", cookie, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp ReclaimLotResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "test-2", resp.LotName)
	assert.NotZero(t, resp.ReclaimedAtMs)
	assert.Equal(t, "unit test", resp.Reason)
	// Status enum is one of the documented values.
	assert.Contains(t, []ReclaimStatus{ReclaimStatusReclaimed, ReclaimStatusAlreadyReclaimed}, resp.Status)
}

// TestLotsAPI_Reclaim_IgnoresClientTimestamp verifies that a client-supplied
// reclaimed_at_ms in the request body is silently ignored: the server is the
// only entity that stamps the reclamation time. Backdating / future-dating
// would be audit-trail tampering (review concern #2).
func TestLotsAPI_Reclaim_IgnoresClientTimestamp(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	// Send an arbitrary (and clearly-bogus) timestamp claim.
	rawBody := map[string]any{
		"reason":        "tampering attempt",
		"reclaimedAtMs": int64(0), // year 1970
	}
	before := time.Now().UnixMilli()
	rec := doRequest(t, eng, http.MethodPost, "/api/v1.0/lots/test-2/reclaim", cookie, rawBody)
	after := time.Now().UnixMilli()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp ReclaimLotResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.GreaterOrEqual(t, resp.ReclaimedAtMs, before, "server must use its own clock")
	assert.LessOrEqual(t, resp.ReclaimedAtMs, after, "server must use its own clock")
	assert.NotEqual(t, int64(0), resp.ReclaimedAtMs, "client zero must be ignored")
}

func TestLotsAPI_AdminCookie_Delete(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	rec := doRequest(t, eng, http.MethodDelete, "/api/v1.0/lots/test-1", cookie, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	all, err := ListAllLots()
	require.NoError(t, err)
	for _, name := range all {
		if name == "test-1" || name == "test-2" {
			t.Fatalf("expected %s to have been deleted, but lot list is %v", name, all)
		}
	}
}

func TestLotsAPI_NotFoundAndBadRequest(t *testing.T) {
	eng, cookie, teardown := setupLotsAPI(t)
	defer teardown()

	// by-path missing the required path query param.
	rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots/by-path", cookie, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// Capacity for a path covered by the synthetic "default" lot returns
	// 200 (we fall back to root) -- this matches the documented behaviour
	// for paths not tracked by any explicit lot.
	rec = doRequest(t, eng, http.MethodGet, fmt.Sprintf("/api/v1.0/lots/by-path/capacity?path=%s", "/nonexistent"), nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// Verify that a non-admin login cookie is rejected with 401 (not silently
// re-interpreted as a federation bearer token). Concern #3: cookie auth
// and bearer auth must be independent paths.
func TestLotsAPI_NonAdminCookieRejected(t *testing.T) {
	eng, _, teardown := setupLotsAPI(t)
	defer teardown()

	cfg := token.NewWLCGToken()
	cfg.Lifetime = 1 * time.Hour
	cfg.Issuer = param.Server_ExternalWebUrl.GetString()
	cfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	cfg.Subject = "non-admin"
	cfg.AddScopes(token_scopes.WebUi_Access)
	cfg.Claims = map[string]string{"user_id": "non-admin"}
	tok, err := cfg.CreateToken()
	require.NoError(t, err)
	cookie := &http.Cookie{Name: "login", Value: tok}

	// The cookie path rejects the user (not an admin); the bearer path
	// MUST NOT pick up the login cookie as a fallback bearer token, so
	// the result is 401 -- not 403 -- because no bearer credential was
	// presented at all.
	rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots", cookie, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
}

func TestLotsAPI_ErrorBodyShape(t *testing.T) {
	eng, _, teardown := setupLotsAPI(t)
	defer teardown()

	rec := doRequest(t, eng, http.MethodGet, "/api/v1.0/lots", nil, nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var resp server_structs.SimpleApiResp
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, server_structs.RespFailed, resp.Status)
	assert.NotEmpty(t, resp.Msg)
	// Error messages must not leak internal lotman/DB details. We assert
	// that the message does not contain the raw lotman C error markers.
	assert.NotContains(t, resp.Msg, "Failure on call to")
	assert.NotContains(t, resp.Msg, "lotman_")
}

// TestLotsAPI_BearerToken_RejectsArbitraryToken verifies that an
// Authorization: Bearer header carrying a token that is NOT signed by an
// authorized caller of the lot results in 403 -- and that, importantly,
// the request is processed via the BEARER path (not the cookie path),
// proving the two paths are independent.
func TestLotsAPI_BearerToken_RejectsArbitraryToken(t *testing.T) {
	eng, _, teardown := setupLotsAPI(t)
	defer teardown()

	// Mint a token signed by the local issuer key (which is NOT an
	// authorized caller of any lot in our fixture, since the lot owners
	// all point at disc.URL).
	cfg := token.NewWLCGToken()
	cfg.Lifetime = 1 * time.Hour
	cfg.Issuer = param.Server_ExternalWebUrl.GetString()
	cfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	cfg.Subject = "bogus"
	cfg.AddScopes(token_scopes.Lot_Read)
	tok, err := cfg.CreateToken()
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "/api/v1.0/lots/test-1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}
