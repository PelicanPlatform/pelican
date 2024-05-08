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

package config

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	adapter "github.com/gwatts/gin-adapter"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	// Global CSRF handler that shares the same auth key
	csrfHanlder     gin.HandlerFunc
	onceCSRFHanlder sync.Once
)

func setupCSRFHandler() {
	csrfKey, err := LoadSessionSecret()
	if err != nil {
		log.Error("Error loading session secret, abort setting up CSRF handler:", err)
		return
	}
	CSRF := csrf.Protect(csrfKey,
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte(`{"message": "CSRF token invalid"}`))
			if err != nil {
				log.Error("Error writing error message back as response")
			}
		})),
	)
	csrfHanlder = adapter.Wrap(CSRF)
}

func GetCSRFHandler() (gin.HandlerFunc, error) {
	onceCSRFHanlder.Do(func() {
		setupCSRFHandler()
	})
	if csrfHanlder == nil {
		return nil, errors.New("Error setting up the CSRF handler")
	}
	return csrfHanlder, nil
}
