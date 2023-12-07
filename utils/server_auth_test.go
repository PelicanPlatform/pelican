package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// MockAuthChecker is the mock implementation of AuthChecker.
type MockAuthChecker struct {
	FederationCheckFunc func(ctx *gin.Context, token string, scopes []string) error
	DirectorCheckFunc   func(ctx *gin.Context, token string, scopes []string) error
	IssuerCheckFunc     func(ctx *gin.Context, token string, scopes []string) error
}

func (m *MockAuthChecker) FederationCheck(ctx *gin.Context, token string, scopes []string) error {
	return m.FederationCheckFunc(ctx, token, scopes)
}

func (m *MockAuthChecker) DirectorCheck(ctx *gin.Context, token string, scopes []string) error {
	return m.DirectorCheckFunc(ctx, token, scopes)
}

func (m *MockAuthChecker) IssuerCheck(ctx *gin.Context, token string, scopes []string) error {
	return m.IssuerCheckFunc(ctx, token, scopes)
}

// Helper function to create a gin context with different token sources
func createContextWithToken(cookieToken, headerToken, queryToken string) *gin.Context {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	if cookieToken != "" {
		r.AddCookie(&http.Cookie{Name: "login", Value: cookieToken})
	}
	if headerToken != "" {
		r.Header.Add("Authorization", "Bearer "+headerToken)
	}
	if queryToken != "" {
		q := r.URL.Query()
		q.Add("authz", queryToken)
		r.URL.RawQuery = q.Encode()
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = r

	return ctx
}

func TestCheckAnyAuth(t *testing.T) {
	// Use a mock instance of authChecker to simplify testing
	originalAuthChecker := authChecker
	defer func() { authChecker = originalAuthChecker }()

	// Create the mock for varioud checkers
	mock := &MockAuthChecker{
		FederationCheckFunc: func(ctx *gin.Context, token string, scopes []string) error {
			if token != "" {
				ctx.Set("User", "Federation")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
		DirectorCheckFunc: func(ctx *gin.Context, token string, scopes []string) error {
			if token != "" {
				ctx.Set("User", "Director")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
		IssuerCheckFunc: func(ctx *gin.Context, token string, scopes []string) error {
			if token != "" {
				ctx.Set("User", "Issuer")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
	}

	authChecker = mock

	// Batch-create test cases, see "name" section for the purpose of each test case
	tests := []struct {
		name       string
		setupMock  func()
		tokenSetup func() *gin.Context
		authOption AuthOption
		want       bool
	}{
		{
			name: "valid-token-from-cookie-source",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{Federation},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("valid-cookie-token", "", "")
			},
			want: true,
		},
		{
			name: "valid-token-from-header-source",
			authOption: AuthOption{
				Sources: []TokenSource{Header},
				Issuers: []TokenIssuer{Federation},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "valid-header-token", "")
			},
			want: true,
		},
		{
			name: "valid-token-from-authz-query-parameter",
			authOption: AuthOption{
				Sources: []TokenSource{Authz},
				Issuers: []TokenIssuer{Federation},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "", "valid-query-token")
			},
			want: true,
		},
		{
			name: "no-token-present",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie, Header, Authz},
				Issuers: []TokenIssuer{},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "", "")
			},
			want: false,
		},
		{
			name: "get-first-available-token-from-multiple-sources",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie, Header, Authz},
				Issuers: []TokenIssuer{Federation},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Token is not from cookie: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("valid-cookie", "valid-header", "valid-authz")
			},
			want: true,
		},
		{
			name: "valid-token-with-single-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{Federation},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Token is not from cookie: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("valid-cookie", "", "")
			},
			want: true,
		},
		{
			name: "invalid-token-with-single-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{Federation},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("invalid-cookie", "", "")
			},
			want: false,
		},
		{
			name: "valid-token-with-multiple-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{Federation, Director, Issuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-federation" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.DirectorCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-director" {
						ctx.Set("User", "Director")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.IssuerCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-issuer" {
						ctx.Set("User", "Issuer")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("for-issuer", "", "")
			},
			want: true,
		},
		{
			name: "invalid-token-with-multiple-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{Federation, Director, Issuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-federation" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.DirectorCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-director" {
						ctx.Set("User", "Director")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.IssuerCheckFunc = func(ctx *gin.Context, token string, scopes []string) error {
					if token == "for-issuer" {
						ctx.Set("User", "Issuer")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("for-nobody", "", "")
			},
			want: false,
		},
	}

	// Batch-run the test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupMock != nil {
				// We might have different mocks to the checker function,
				// so we have this flexibility by calling setupmock if there is such function
				tc.setupMock()
			}
			require.NotNil(t, tc.tokenSetup, "tokenSetup function can't be nil")

			ctx := tc.tokenSetup()

			if got := CheckAnyAuth(ctx, tc.authOption); got != tc.want {
				t.Errorf("CheckAnyAuth() = %v, want %v", got, tc.want)
			}
		})
	}

}
