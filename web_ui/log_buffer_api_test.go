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

package web_ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestLogReadAuthHandler pins who may read the server's logs. The buffer this
// gate protects holds recent log lines from every subsystem, so admitting the
// wrong caller discloses far more than the log-viewer page itself; the
// dedicated pelican.log_read scope exists so an operator can grant log access
// without granting administration, and it must not work in reverse.
func TestLogReadAuthHandler(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name          string
		setupUserFunc func(*gin.Context)
		expectedCode  int
		expectedError string
	}{
		{
			name: "anonymous-caller-rejected",
			setupUserFunc: func(ctx *gin.Context) {
				ctx.Set("User", "")
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: "Login required to view server logs",
		},
		{
			name: "authenticated-user-without-scope-rejected",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1"}))
				ctx.Set("User", "someone")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You do not have permission to read server logs",
		},
		{
			name: "admin-admitted-without-an-explicit-grant",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1"}))
				ctx.Set("User", "admin1")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "admin-group-member-admitted",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				require.NoError(t, param.Server_AdminGroups.Set([]string{"pelican-admins"}))
				ctx.Set("User", "user1")
				ctx.Set("Groups", []string{"pelican-admins"})
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "non-admin-group-member-rejected",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				require.NoError(t, param.Server_AdminGroups.Set([]string{"pelican-admins"}))
				ctx.Set("User", "user1")
				ctx.Set("Groups", []string{"pelican-users"})
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You do not have permission to read server logs",
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.Default()
			router.GET("/test",
				func(ctx *gin.Context) { tc.setupUserFunc(ctx) },
				LogReadAuthHandler,
				func(ctx *gin.Context) { ctx.AbortWithStatus(http.StatusOK) },
			)
			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code)
			if tc.expectedError != "" {
				assert.Contains(t, w.Body.String(), tc.expectedError)
			}
			server_utils.ResetTestState()
		})
	}
}

func TestParseCount(t *testing.T) {
	t.Parallel()

	t.Run("valid values", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want int
		}{
			{"0", 0},
			{"1", 1},
			{"100", 100},
			{"10000", 10000},
		} {
			got, err := parseCount(tc.in)
			require.NoError(t, err, "input %q", tc.in)
			assert.Equal(t, tc.want, got, "input %q", tc.in)
		}
	})

	t.Run("rejects invalid values", func(t *testing.T) {
		// parseCount is strict: partly-numeric input ("100abc"), negatives,
		// and non-numbers are all rejected rather than silently truncated.
		for _, in := range []string{"", "100abc", "abc", "-1", "-100", "1.5", " 100", "0x10"} {
			_, err := parseCount(in)
			assert.Error(t, err, "input %q should be rejected", in)
		}
	})
}

func TestLogTailCursorRoundTrip(t *testing.T) {
	t.Parallel()

	// The empty cursor is the "give me everything" sentinel and maps to seq 0.
	got, err := parseLogTailCursor("")
	require.NoError(t, err)
	assert.Equal(t, int64(0), got)
	assert.Equal(t, "", logTailCursor(0))

	for _, seq := range []int64{1, 42, 1 << 20, 1<<63 - 1} {
		encoded := logTailCursor(seq)
		assert.NotEmpty(t, encoded, "seq %d should encode to a non-empty cursor", seq)
		decoded, err := parseLogTailCursor(encoded)
		require.NoError(t, err, "seq %d", seq)
		assert.Equal(t, seq, decoded, "seq %d should round-trip", seq)
	}

	_, err = parseLogTailCursor("not-valid-base64!!")
	assert.Error(t, err)
}
