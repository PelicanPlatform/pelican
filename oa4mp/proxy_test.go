package oa4mp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func setupOA4MPProxyTest(t *testing.T) *http.Cookie {
	gin.SetMode(gin.TestMode)
	server_utils.ResetTestState()
	transport = nil
	onceTransport = sync.Once{}
	compiledAuthzRules = nil
	t.Cleanup(func() {
		server_utils.ResetTestState()
		transport = nil
		onceTransport = sync.Once{}
		compiledAuthzRules = nil
	})

	require.NoError(t, param.ConfigDir.Set(t.TempDir()))
	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(context.Background(), server_structs.OriginType))
	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, database.ServerDatabase.AutoMigrate(&database.Collection{}, &database.CollectionACL{}))

	loginCookieTokenCfg := token.NewWLCGToken()
	loginCookieTokenCfg.Lifetime = 30 * time.Minute
	loginCookieTokenCfg.Issuer = param.Server_ExternalWebUrl.GetString()
	loginCookieTokenCfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	loginCookieTokenCfg.Subject = "user"
	loginCookieTokenCfg.AddScopes(token_scopes.WebUi_Access)
	loginCookieTokenCfg.Claims = map[string]string{
		"user_id": "user-id-1",
	}

	tok, err := loginCookieTokenCfg.CreateToken()
	require.NoError(t, err)

	return &http.Cookie{Name: "login", Value: tok}
}

func TestOA4MPProxyForcesFreshLoginWithoutLoginAttemptMarker(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	loginCookie := setupOA4MPProxyTest(t)

	router := gin.New()
	router.GET("/api/v1.0/issuer/authorize", oa4mpProxy)

	req, err := http.NewRequest(http.MethodGet, "/api/v1.0/issuer/authorize?client_id=test-client", nil)
	require.NoError(t, err)
	req.AddCookie(loginCookie)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusTemporaryRedirect, recorder.Code)
	assert.Equal(t, "/api/v1.0/auth/oauth/login?nextUrl=%2Fapi%2Fv1.0%2Fissuer%2Fauthorize%3Fclient_id%3Dtest-client%26fromLogin%3Dtrue", recorder.Header().Get("Location"))

	cookies := recorder.Result().Cookies()
	require.NotEmpty(t, cookies)
	assert.Equal(t, "login", cookies[0].Name)
	assert.Greater(t, time.Now(), cookies[0].Expires)
}

func TestOA4MPProxyStripsLoginAttemptMarkerBeforeProxying(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	loginCookie := setupOA4MPProxyTest(t)

	var proxiedPath string
	var proxiedQuery string
	var proxiedUserHeader string
	transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		proxiedPath = req.URL.Path
		proxiedQuery = req.URL.RawQuery
		proxiedUserHeader = req.Header.Get("X-Pelican-User")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	router := gin.New()
	router.GET("/api/v1.0/issuer/authorize", oa4mpProxy)

	req, err := http.NewRequest(http.MethodGet, "/api/v1.0/issuer/authorize?client_id=test-client&fromLogin=true", nil)
	require.NoError(t, err)
	req.AddCookie(loginCookie)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "/scitokens-server/authorize", proxiedPath)
	assert.Equal(t, "client_id=test-client", proxiedQuery)
	assert.NotEmpty(t, proxiedUserHeader)
}
