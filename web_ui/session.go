/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"sync"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

var (
	sessionHandler     gin.HandlerFunc // A global session handler for web UI. Do not directly access this variable. Use GetSessionHandler() instead
	sessionHandlerOnce = sync.Once{}
	sessionSetupErr    error
)

func setupSession() {
	sessionSecretByte, err := config.LoadSessionSecret()
	if err != nil {
		sessionSetupErr = errors.Wrap(err, "failed to get session secrets")
		return
	}

	store := cookie.NewStore(sessionSecretByte)
	sessionHandler = sessions.Sessions("pelican-session", store)
}

// Setup and return the session handler for web UI APIs.
// Calling mutiple times will only set up the handler once
func GetSessionHandler() (gin.HandlerFunc, error) {
	sessionHandlerOnce.Do(setupSession)
	if sessionSetupErr != nil {
		return nil, sessionSetupErr
	} else {
		return sessionHandler, nil
	}
}
