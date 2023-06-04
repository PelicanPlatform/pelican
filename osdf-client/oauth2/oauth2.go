
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

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

	pathCleaned := path.Clean(osdfPath)[len(entry.Prefix):]
	if credentialGen != nil && credentialGen.BasePath != nil && len(*credentialGen.BasePath) > 0 {
		pathCleaned = path.Clean(osdfPath)[len(*credentialGen.BasePath):]
	}

	var storageScope string
	if isWrite {
		storageScope = "storage.create:"
	} else {
		storageScope = "storage.read:"
	}
	storageScope += pathCleaned

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
