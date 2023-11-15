package client

import (
	//"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
)

// BasicAuth structure holds our credentials, this is the authorizer
type BearerAuth struct {
	token string
}

// BearerAuthenticator is an Authenticator for BearerAuth
type BearerAuthenticator struct {
	token string
}

// NewAuthenticator creates a new BearerAuthenticator
func (b *BearerAuth) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &BearerAuthenticator{token: b.token}, body
}

// AddAuthenticator is not needed in this case (but required to have in gowebdav)
func (b *BearerAuth) AddAuthenticator(key string, fn gowebdav.AuthFactory) {
	// Not needed for BearerAuth
}

// Authorize the current request
func (b *BearerAuthenticator) Authorize(c *http.Client, rq *http.Request, path string) error {
	rq.Header.Add("Authorization", "Bearer "+b.token) //set the header with the token
	return nil
}

// Verify verifies the authentication
func (b *BearerAuthenticator) Verify(c *http.Client, rs *http.Response, path string) (redo bool, err error) {
	if rs.StatusCode == 401 {
		//err = NewPathError("Authorize", path, rs.StatusCode)
		log.Errorf("Authorize: %s, %v", path, rs.StatusCode)
	}
	return
}

// Close cleans up all resources
func (b *BearerAuthenticator) Close() error {
	return nil
}

// Clone creates a Copy of itself
func (b *BearerAuthenticator) Clone() gowebdav.Authenticator {
	// no copy due to read only access
	return b
}

// // String toString
// func (b *BearerAuth) String() string {
// 	return fmt.Sprintf("BasicAuth login: %s", b.user)
// }
