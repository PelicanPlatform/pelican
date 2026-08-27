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

package transfer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestBootstrapCallbackRequiresBrowserCookie verifies the auth-code callback is
// bound to the browser that started the flow: it is rejected without the
// browser-binding cookie or with a wrong value, and only proceeds past that gate
// when the cookie matches the session.
func TestBootstrapCallbackRequiresBrowserCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&TransferOAuthClient{}))

	newSession := func(state string) *bootstrapSession {
		s := &bootstrapSession{
			SessionID: "sid-" + state,
			Owner:     ownerIdentity{UserID: "u1"},
			IssuerURL: "https://issuer.example",
			Name:      "cred",
			Scopes:    "offline_access",
			State:     state,
			status:    "pending",
			CreatedAt: time.Now(),
		}
		s.setBrowserToken("correct-token-" + state)
		globalBootstrapStore.put(s)
		return s
	}

	call := func(state, cookieVal string) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet,
			SharedCallbackPath+"?state="+callbackStatePrefix+state+"&code=authz-code", nil)
		if cookieVal != "" {
			req.AddCookie(&http.Cookie{Name: bootstrapFlowCookie, Value: cookieVal})
		}
		c.Request = req
		HandleSharedCallback(db)(c)
	}

	t.Run("no cookie is rejected", func(t *testing.T) {
		s := newSession("state-nocookie")
		call("state-nocookie", "")
		status, _, msg := s.result()
		assert.Equal(t, "error", status)
		assert.Contains(t, msg, "mismatch")
	})

	t.Run("wrong cookie is rejected", func(t *testing.T) {
		s := newSession("state-wrong")
		call("state-wrong", "not-the-token")
		status, _, msg := s.result()
		assert.Equal(t, "error", status)
		assert.Contains(t, msg, "mismatch")
	})

	t.Run("matching cookie passes the browser gate", func(t *testing.T) {
		s := newSession("state-ok")
		call("state-ok", "correct-token-state-ok")
		status, _, msg := s.result()
		// It proceeds past the cookie check and then fails later because no OAuth
		// client is registered — proving the gate itself was satisfied.
		assert.Equal(t, "error", status)
		assert.NotContains(t, msg, "mismatch")
		assert.Contains(t, msg, "OAuth client")
	})
}
