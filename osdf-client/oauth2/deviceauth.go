//
// This package is derived from the following PR:
// https://github.com/golang/oauth2/pull/578/files
// as of 24 November 2022
//
// The CLA is signed so that means the license should be
// the BSD 3-clause license (see https://github.com/golang/oauth2/blob/master/LICENSE
// for license text and copyright notice).  For completeness, the license is
// duplicated below
//

/*
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context/ctxhttp"
	oauth2_upstream "golang.org/x/oauth2"
	log "github.com/sirupsen/logrus"
)

const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = "access_denied"
	errExpiredToken         = "expired_token"
	errInvalidScope         = "invalid_scope"
)

type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
	raw                     map[string]interface{}
}

type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint Endpoint

	// Scope specifies optional requested permissions.
	Scopes []string
}

type Endpoint struct {
	AuthURL       string
	DeviceAuthURL string
	TokenURL      string
}

func retrieveDeviceAuth(ctx context.Context, c *Config, v url.Values) (*DeviceAuth, error) {
	req, err := http.NewRequest("POST", c.Endpoint.DeviceAuthURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := ctxhttp.Do(ctx, nil, req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot auth device: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &oauth2_upstream.RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	da := &DeviceAuth{}
	err = json.Unmarshal(body, &da)
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(body, &da.raw)

	// Azure AD supplies verification_url instead of verification_uri
	if da.VerificationURI == "" {
		da.VerificationURI, _ = da.raw["verification_url"].(string)
	}

	return da, nil
}

func parseError(err error) string {
	e, ok := err.(*oauth2_upstream.RetrieveError)
	if ok {
		eResp := make(map[string]string)
		_ = json.Unmarshal(e.Body, &eResp)
		return eResp["error"]
	}
	return ""
}


// AuthDevice returns a device auth struct which contains a device code
// and authorization information provided for users to enter on another device.
func (c *Config) AuthDevice(ctx context.Context) (*DeviceAuth, error) {
	v := url.Values{
		"client_id": {c.ClientID},
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	return retrieveDeviceAuth(ctx, c, v)
}

// Adopted from internal/token.go; to be removed once DeviceFlow support is upstreamed
func newTokenRequest(tokenURL, clientID, clientSecret string, v url.Values) (*http.Request, error) {
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	return req, nil
}

var HTTPClient ContextKey
type ContextKey struct{}
func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}
func RetrieveToken(ctx context.Context, clientID, clientSecret, tokenURL string, v url.Values) (*oauth2_upstream.Token, error) {
	req, err := newTokenRequest(tokenURL, clientID, clientSecret, v)
	if err != nil {
		return nil, err
	}
	token, err := doTokenRoundTrip(ctx, req)
	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	if token != nil && token.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	return token, err
}

type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    int            `json:"expires_in"`
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (*oauth2_upstream.Token, error) {
	r, err := ctxhttp.Do(ctx, ContextClient(ctx), req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	log.Debugf("Token round trip response code: %v", r.StatusCode)
	log.Debugf("Token round trip body: %s", body)
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &oauth2_upstream.RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	var token *oauth2_upstream.Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		token = &oauth2_upstream.Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
		}
		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			return nil, err
		}
		token = &oauth2_upstream.Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       time.Now().Add(time.Duration(tj.ExpiresIn) * time.Second),
		}
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}

// Poll does a polling to exchange an device code for a token.
func (c *Config) Poll(ctx context.Context, da *DeviceAuth) (*oauth2_upstream.Token, error) {
	v := url.Values{
		"client_id":   {c.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}

	// If no interval was provided, the client MUST use a reasonable default polling interval.
	// See https://tools.ietf.org/html/draft-ietf-oauth-device-flow-07#section-3.5
	interval := da.Interval
	if interval == 0 {
		interval = 5
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		log.Debugf("After sleep of %v seconds, attempting to retrieve token.", interval)
		tok, err := RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
		if err == nil {
			return tok, nil
		}

		errTyp := parseError(err)
		switch errTyp {
		case errAccessDenied, errExpiredToken, errInvalidScope:
			return tok, errors.New("oauth2: " + errTyp)

		case errSlowDown:
			interval += 1
			log.Debugf("Remote server requested we slow down; set poll interval to %v seconds", interval)
		case errAuthorizationPending:
			log.Debugf("Remote server responded that our authorization is pending")

		default:
			return tok, err
		}
	}
}
