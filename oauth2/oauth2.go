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

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// VerificationURLHandler is called with the address a user must visit to
// approve a device-flow authorization request, and the code they must enter
// once there.
//
// verificationURL is the issuer's verification_uri_complete when it supplied
// one, in which case the URL already carries the code and userCode is empty;
// otherwise it is verification_uri and userCode is the code to enter there.
// The handler is called only when the issuer named a URL at all.
//
// It runs on the goroutine driving the flow, before polling begins, so a
// handler that blocks delays the user's own approval.
//
// An installed handler REPLACES Pelican's own announcement rather than adding
// to it: while one is installed the URL is not written to stderr.  An embedder
// installs a handler precisely because the terminal is not where its user is
// looking -- a page, a desktop notification, a GUI -- and printing there
// anyway is at best noise in a log the user never reads.  The consequence is
// that the handler is the ONLY way the user learns where to approve, so one
// that drops the URL silently leaves the flow with nothing to show, and it
// polls until it expires.
type VerificationURLHandler func(verificationURL, userCode string)

var verificationURLHandler atomic.Pointer[VerificationURLHandler]

// SetVerificationURLHandler installs handler as the process-wide destination
// for device-flow verification URLs, replacing any previous one.  A nil
// handler removes the current one.
//
// This exists so that a program embedding Pelican can bring the URL to its
// user by whatever means suits it -- opening a browser, raising a desktop
// notification, showing it in a GUI -- without reimplementing the flow.  Every
// step AcquireToken performs around the announcement is unexported: deciding
// whether a cached token would have done (client.tokenIsAcceptable), dynamic
// client registration (client.registerClient), scope construction (trimPath),
// refresh (client.refreshTokenEntry), and local minting (client.generateToken).
// An embedder that copied them to reach the URL would drift from them, and the
// first consequence is that Pelican judges the token the copy obtained
// unacceptable and opens a second device flow -- so the user approves twice.
//
// Installing a handler also lifts AcquireToken's terminal requirement, which
// exists so that a flow is never started with no way to tell the user where to
// approve it.  A handler is another such way, so an embedder with no terminal
// -- a program under a service manager, or one whose output is redirected --
// can acquire a token where it previously could not.
//
// It is safe to call at any time, including while a flow is in progress.
func SetVerificationURLHandler(handler VerificationURLHandler) {
	if handler == nil {
		verificationURLHandler.Store(nil)
		return
	}
	verificationURLHandler.Store(&handler)
}

func deviceCodeSupported(grantTypes *[]string) bool {
	for _, grant := range *grantTypes {
		if grant == "urn:ietf:params:oauth:grant-type:device_code" {
			return true
		}
	}
	return false
}

// Trim the path to a maximum number of components:
//   trimPath("/a/b/c", 0) -> "/"
//   trimPath("/a/b/c", 1) -> "/a"
//   trimPath("/a/b/c", 2) -> "/a/b"
//   trimPath("/a/b/c", 3) -> "/a/b/c"
//   trimPath("/a/b/c", 4) -> "/a/b/c"

func trimPath(pathName string, maxDepth int) string {
	if maxDepth < 0 {
		return "/"
	}
	// Ensure we have no double `/`
	pathName = path.Clean(pathName)
	pathComponents := strings.Split(pathName, "/")

	// Ensure we don't slice past the end of the array
	maxLength := maxDepth + 1
	if maxLength > len(pathComponents) {
		maxLength = len(pathComponents)
	}

	return "/" + path.Join(pathComponents[0:maxLength]...)
}

// announceVerification tells the user where to approve the pending device-flow
// authorization request: through the installed VerificationURLHandler if there
// is one, and otherwise by writing the instructions to w.
//
// Which URL the user needs depends on the issuer.  A verification_uri_complete
// already carries the user code, so it suffices on its own; a plain
// verification_uri has to be paired with the code the user then types there.
//
// Exactly one of the two announcements happens, so an embedder that has
// somewhere better to put the URL does not also spray it across a terminal
// nobody is watching.  A response naming no URL at all is the exception: there
// is nothing to hand a handler, so the printed output remains as the only
// record that a flow was attempted.
func announceVerification(w io.Writer, deviceAuth *DeviceAuth) {
	// A verification_uri_complete carries the code already; a plain
	// verification_uri needs it alongside.
	verificationURL, userCode := deviceAuth.VerificationURIComplete, ""
	complete := verificationURL != ""
	if !complete {
		verificationURL, userCode = deviceAuth.VerificationURI, deviceAuth.UserCode
	}

	if verificationURL != "" {
		if handler := verificationURLHandler.Load(); handler != nil {
			(*handler)(verificationURL, userCode)
			return
		}
	}

	if complete {
		fmt.Fprintln(w, "To approve credentials for this operation, please navigate to the following URL and approve the request:")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, verificationURL)
		return
	}
	fmt.Fprintln(w, "To approve credentials for this operation, please navigate to the following URL:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, verificationURL)
	fmt.Fprintln(w, "\nand enter the following code")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, userCode)
}

// verificationTargetAvailable reports whether there is anywhere to send the
// verification URL a device flow is about to produce.
//
// A device flow is worthless if nobody ever sees that URL, which is what the
// terminal requirement has always been about: a program with no terminal had
// no way to tell its user where to approve, so failing early beat polling for
// an approval that could never come.
//
// An installed VerificationURLHandler is an embedder saying it has somewhere
// else to put the URL -- a page, a desktop notification, a GUI -- so it meets
// that requirement without a terminal, and it is exactly the case the handler
// exists for. A program that opens a browser for its user is often started
// from a terminal nobody is watching, and under a service manager it may have
// no terminal at all; refusing there would make the handler unusable in the
// situation it was added to serve.
func verificationTargetAvailable() bool {
	if verificationURLHandler.Load() != nil {
		return true
	}
	if len(os.Getenv(config.GetPreferredPrefix().String()+"_SKIP_TERMINAL_CHECK")) > 0 {
		return true
	}
	// Stat fails on a closed or exotic descriptor, which is not a terminal
	// either; the previous form dereferenced the nil FileInfo that comes back
	// with the error.
	fileInfo, err := os.Stdout.Stat()
	return err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0
}

func AcquireToken(issuerUrl string, entry *config.PrefixEntry, dirResp server_structs.DirectorResponse, osdfPath string, opts config.TokenGenerationOpts) (*config.TokenEntry, error) {
	if !verificationTargetAvailable() {
		return nil, errors.New("This program must be run in a terminal to acquire a new token")
	}

	issuerInfo, err := config.GetIssuerMetadata(issuerUrl)
	if err != nil {
		return nil, err
	}

	if !deviceCodeSupported(&issuerInfo.GrantTypes) {
		return nil, fmt.Errorf("issuer at %s for prefix %s does not support device flow", issuerUrl, entry.Prefix)
	}

	// Determine the path to include in the scope that we request.
	// It needs to be relative to some base path. Start with the prefix.
	pathCleaned := path.Clean(osdfPath)[len(entry.Prefix):]

	// The credential generation/issuer objects provide various hints and guidance about how
	// to best create the OAuth2 credential
	if len(dirResp.XPelTokGenHdr.Issuers) != 0 {
		if len(dirResp.XPelTokGenHdr.BasePaths) > 0 {
			pathCleaned = path.Clean(osdfPath)[len(dirResp.XPelTokGenHdr.BasePaths[0]):]
		}
	}

	// If the initial path was exactly some base path,
	// then the path in the scope that we request should be "/".
	if pathCleaned == "" {
		pathCleaned = "/"
	}

	// Always have the requested token refer to a directory, not some file.
	pathCleaned = path.Dir(pathCleaned)

	// Potentially increase the coarseness of the token
	if !opts.Operation.IsEnabled(config.TokenSharedWrite) && !opts.Operation.IsEnabled(config.TokenSharedRead) && dirResp.XPelTokGenHdr.MaxScopeDepth > 0 {
		pathCleaned = trimPath(pathCleaned, (int)((dirResp.XPelTokGenHdr.MaxScopeDepth)))
	}

	storageScopes := []string{}
	if opts.Operation.IsEnabled(config.TokenWrite) || opts.Operation.IsEnabled(config.TokenSharedWrite) {
		storageScopes = append(storageScopes, "storage.create:"+pathCleaned)
	}
	if opts.Operation.IsEnabled(config.TokenDelete) {
		storageScopes = append(storageScopes, "storage.modify:"+pathCleaned)
	}
	if opts.Operation.IsEnabled(config.TokenRead) || opts.Operation.IsEnabled(config.TokenSharedRead) || opts.Operation.IsEnabled(config.TokenList) {
		storageScopes = append(storageScopes, "storage.read:"+pathCleaned)
	}
	storageScope := strings.Join(storageScopes, " ")
	log.Debugln("Requesting a credential with the following scope:", storageScope)

	oauth2Config := Config{
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		Endpoint: Endpoint{
			AuthURL:       issuerInfo.AuthURL,
			TokenURL:      issuerInfo.TokenURL,
			DeviceAuthURL: issuerInfo.DeviceAuthURL,
		},
		Scopes: []string{"wlcg", "offline_access", storageScope},
	}

	client := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(context.Background(), HTTPClient, client)
	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to perform device code flow with URL %s", issuerInfo.DeviceAuthURL)
	}

	announceVerification(os.Stderr, deviceAuth)

	upstream_token, err := oauth2Config.Poll(ctx, deviceAuth)
	if err != nil {
		return nil, err
	}

	token := config.TokenEntry{
		Expiration:   upstream_token.Expiry.Unix(),
		AccessToken:  upstream_token.AccessToken,
		RefreshToken: upstream_token.RefreshToken,
	}
	return &token, nil
}

// PingClient performs a lightweight client_credentials grant against the token
// endpoint to check whether the given client credentials are still recognised
// by the issuer.
//
// Returns ErrUnknownClient if the server responds with 401 invalid_client,
// nil if the client is known (the expected 400 unauthorized_client response),
// or nil for any other error (best-effort; servers that don't implement the
// ping pattern are silently ignored).
func PingClient(tokenURL, clientID, clientSecret string, transport http.RoundTripper) error {
	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil // best-effort
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))

	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil // network error — best-effort
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error == "invalid_client" {
			return ErrUnknownClient
		}
	}
	return nil
}
