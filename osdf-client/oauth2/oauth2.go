
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

        log "github.com/sirupsen/logrus"
	config "github.com/htcondor/osdf-client/v6/config"
	namespaces "github.com/htcondor/osdf-client/v6/namespaces"
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

func AcquireToken(issuerUrl string, entry *config.PrefixEntry, credentialGen *namespaces.CredentialGeneration, osdfPath string, isWrite bool) (*config.TokenEntry, error) {

	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return nil, errors.New("This program must be run in a terminal to acquire a new token")
	}

	issuerInfo, err := GetIssuerMetadata(issuerUrl)
	if err != nil {
		return nil, err
	}

	if !deviceCodeSupported(&issuerInfo.GrantTypes) {
		return nil, fmt.Errorf("Issuer at %s for prefix %s does not support device flow", issuerUrl, entry.Prefix)
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
		if credentialGen.MaxScopeDepth != nil && *credentialGen.MaxScopeDepth >= 0 {
			pathCleaned = trimPath(pathCleaned, *credentialGen.MaxScopeDepth)
		}
	}

	var storageScope string
	if isWrite {
		storageScope = "storage.create:"
	} else {
		storageScope = "storage.read:"
	}
	storageScope += pathCleaned
	log.Debugln("Requesting a credential with the following scope:", storageScope)

	oauth2Config := Config{
		ClientID: entry.ClientID,
		ClientSecret: entry.ClientSecret,
		Endpoint: Endpoint{AuthURL: issuerInfo.AuthURL,
		                   TokenURL: issuerInfo.TokenURL,
		                   DeviceAuthURL: issuerInfo.DeviceAuthURL},
		Scopes : []string{"wlcg", "offline_access", storageScope},
	}

	ctx := context.Background()
	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	if err != nil {
		return nil, err
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
		Expiration: upstream_token.Expiry.Unix(),
		AccessToken: upstream_token.AccessToken,
		RefreshToken: upstream_token.RefreshToken,
	}
	return &token, nil
}
