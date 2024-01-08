package web_ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestAdminAuthHandler(t *testing.T) {
	// Initialize Gin and set it to test mode
	gin.SetMode(gin.TestMode)

	// Define test cases
	testCases := []struct {
		name          string
		setupUserFunc func(*gin.Context) // Function to setup user and admin list
		expectedCode  int                // Expected HTTP status code
		expectedError string             // Expected error message
	}{
		{
			name: "user-not-logged-in",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "")
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: "Login required to view this page",
		},
		{
			name: "general-admin-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{})
				ctx.Set("User", "admin")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "specific-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "admin1")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "non-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-empty",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{})
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-multiple-users",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Registry.AdminUsers", []string{"admin1", "admin2", "admin3"})
				ctx.Set("User", "admin2")
			},
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			tc.setupUserFunc(ctx)

			AdminAuthHandler(ctx)

			assert.Equal(t, tc.expectedCode, w.Code)
			if tc.expectedError != "" {
				assert.Contains(t, w.Body.String(), tc.expectedError)
			}
			viper.Reset()
		})
	}
}
