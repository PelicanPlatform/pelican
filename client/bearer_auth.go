/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

package client

import (
	"fmt"
	"io"
	"net/http"

	"github.com/studio-b12/gowebdav"
)

// BasicAuth structure holds our credentials, this is the authorizer
type bearerAuth struct {
	token string
}

// BearerAuthenticator is an Authenticator for BearerAuth
type bearerAuthenticator struct {
	token string
}

// NewAuthenticator creates a new BearerAuthenticator
func (b *bearerAuth) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &bearerAuthenticator{token: b.token}, body
}

// AddAuthenticator is not needed in this case (but required to have in gowebdav)
func (b *bearerAuth) AddAuthenticator(key string, fn gowebdav.AuthFactory) {
	// Not needed for BearerAuth
}

// Authorize the current request
func (b *bearerAuthenticator) Authorize(c *http.Client, rq *http.Request, path string) error {
	rq.Header.Add("Authorization", "Bearer "+b.token) //set the header with the token
	return nil
}

// Verify verifies the authentication
func (b *bearerAuthenticator) Verify(c *http.Client, rs *http.Response, path string) (redo bool, err error) {
	if rs.StatusCode == 401 {
		err := fmt.Errorf("Authorize: %s, %v", path, rs.StatusCode)
		return true, err
	}
	return
}

// Close cleans up all resources
func (b *bearerAuthenticator) Close() error {
	return nil
}

// Clone creates a Copy of itself
func (b *bearerAuthenticator) Clone() gowebdav.Authenticator {
	// no copy due to read only access
	return b
}
