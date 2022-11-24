package stashcp

import (
	"fmt"
	"net/url"

	config "github.com/htcondor/osdf-client/v6/config"
	oauth2 "github.com/htcondor/osdf-client/v6/oauth2"
)

// Given a URL and a piece of the namespace, attempt to acquire a valid
// token for that URL.
func AcquireToken(destination *url.URL, namespace Namespace, isWrite bool) (string, error) {

	osdfConfig, err := config.GetConfigContents()
	if err != nil {
		return "", err
	}

	prefixIdx := -1
	for idx, entry := range osdfConfig.OSDF.OauthClient {
		if entry.Prefix == namespace.Path {
			prefixIdx = idx
			break
		}
	}
	if prefixIdx < 0 {
		return "", fmt.Errorf("Path %s not found in configuration file", namespace.Path)
	}
	
	prefixEntry := &osdfConfig.OSDF.OauthClient[prefixIdx]

	// For now, a fairly useless token-selection algorithm - take the first in the list.
	// In the future, we should:
	// - Check scopes
	bestToken := ""
	for _, token := range prefixEntry.Tokens {
		bestToken = token.AccessToken
	}
	if len(bestToken) > 0 {
		return bestToken, nil
	}

	if len(namespace.Issuer) == 0 {
		return "", fmt.Errorf("Unable to acquire new token; token issuer for %s is unknown", namespace.Path)
	}
	token, err := oauth2.AcquireToken(namespace.Issuer, prefixEntry, destination.Path, isWrite)
	if err != nil {
		return "", err
	}

	Tokens := &prefixEntry.Tokens
	*Tokens = append(*Tokens, *token)
	return token.AccessToken, nil
}

