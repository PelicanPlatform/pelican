package stashcp

import (
	"errors"
	"fmt"
	"net/url"

	config "github.com/htcondor/osdf-client/v6/config"
)

// Given a URL and a piece of the namespace, attempt to acquire a valid
// token for that URL.
func acquireToken(destination *url.URL, namespace Namespace) (string, error) {

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

	// For now, a fairly useless token-selection algorithm - take the first in the list.
	// In the future, we should:
	// - Check scopes
	bestToken := ""
	for _, token := range osdfConfig.OSDF.OauthClient[prefixIdx].Tokens {
		bestToken = token.AccessToken
	}
	if len(bestToken) > 0 {
		return bestToken, nil
	}

	return "", errors.New("Failed to acquire token")
}

