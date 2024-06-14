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
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	config "github.com/pelicanplatform/pelican/config"
	namespaces "github.com/pelicanplatform/pelican/namespaces"
)

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

func AcquireToken(issuerUrl string, entry *config.PrefixEntry, credentialGen *namespaces.CredentialGeneration, osdfPath string, opts config.TokenGenerationOpts) (*config.TokenEntry, error) {

	if fileInfo, _ := os.Stdout.Stat(); (len(os.Getenv(config.GetPreferredPrefix().String()+"_SKIP_TERMINAL_CHECK")) == 0) && ((fileInfo.Mode() & os.ModeCharDevice) == 0) {
		return nil, errors.New("This program must be run in a terminal to acquire a new token")
	}

	issuerInfo, err := config.GetIssuerMetadata(issuerUrl)
	if err != nil {
		return nil, err
	}

	if !deviceCodeSupported(&issuerInfo.GrantTypes) {
		return nil, fmt.Errorf("issuer at %s for prefix %s does not support device flow", issuerUrl, entry.Prefix)
	}

	// Always trim the filename off the path
	osdfPath = path.Dir(osdfPath)

	pathCleaned := path.Clean(osdfPath)[len(entry.Prefix):]
	// The credential generation object provides various hints and guidance about how
	// to best create the OAuth2 credential
	if credentialGen != nil {
		// Tweak the relative path the issuer starts with
		if credentialGen.BasePath != nil && len(*credentialGen.BasePath) > 0 {
			pathCleaned = path.Clean(osdfPath)[len(*credentialGen.BasePath):]
		}

		// Potentially increase the coarseness of the token
		if opts.Operation != config.TokenSharedWrite && opts.Operation != config.TokenSharedRead && credentialGen.MaxScopeDepth != nil && *credentialGen.MaxScopeDepth >= 0 {
			pathCleaned = trimPath(pathCleaned, *credentialGen.MaxScopeDepth)
		}
	}

	var storageScope string
	if opts.Operation == config.TokenSharedWrite || opts.Operation == config.TokenWrite {
		storageScope = "storage.create:"
	} else {
		storageScope = "storage.read:"
	}
	storageScope += pathCleaned
	log.Debugln("Requesting a credential with the following scope:", storageScope)

	oauth2Config := Config{
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		Endpoint: Endpoint{AuthURL: issuerInfo.AuthURL,
			TokenURL:      issuerInfo.TokenURL,
			DeviceAuthURL: issuerInfo.DeviceAuthURL},
		Scopes: []string{"wlcg", "offline_access", storageScope},
	}

	client := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(context.Background(), HTTPClient, client)
	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to perform device code flow with URL %s", issuerInfo.DeviceAuthURL)
	}

	if len(deviceAuth.VerificationURIComplete) > 0 {
		fmt.Fprintln(os.Stdin, "To approve credentials for this operation, please navigate to the following URL and approve the request:")
		fmt.Fprintln(os.Stdin, "")
		fmt.Fprintln(os.Stdin, deviceAuth.VerificationURIComplete)
	} else {
		fmt.Fprintln(os.Stdin, "To approve credentials for this operation, please navigate to the following URL:")
		fmt.Fprintln(os.Stdin, "")
		fmt.Fprintln(os.Stdin, deviceAuth.VerificationURIComplete)
		fmt.Fprintln(os.Stdin, "\nand enter the following code")
		fmt.Fprintln(os.Stdin, "")
		fmt.Fprintln(os.Stdin, deviceAuth.UserCode)
	}

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
