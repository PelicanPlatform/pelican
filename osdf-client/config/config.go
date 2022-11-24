
package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Struct holding the OAuth2 state (and any other OSDF config needed)

type PrefixEntry struct {
// OSDF namespace prefix
	Prefix       string `yaml:"prefix"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Tokens     []struct {
		Expiration   int64  `yaml:"expiration"`
		AccessToken  string `yaml:"access_token"`
		RefreshToken string `yaml:"refresh_token,omitempty"`
	} `yaml:"tokens,omitempty"`
}

type OSDFConfig struct {

	// Top-level OSDF object
	OSDF struct {
		// List of OAuth2 client configurations
		OauthClient [] PrefixEntry `yaml:"oauth_client,omitempty"`
	} `yaml:"OSDF"`
}

type OauthIssuer struct {
	Issuer string `json:"issuer"`
	DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
	GrantTypes []string `json:"grant_types_supported"`
}

func GetIssuerMetadata(issuer_url string) (*OauthIssuer, error) {
	wellKnownUrl := strings.TrimSuffix(issuer_url, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(wellKnownUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("Failed to retrieve issuer metadata")
	}

	issuer := &OauthIssuer{}
	err = json.Unmarshal(body, issuer)
	return issuer, err
}
