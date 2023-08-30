package oauth2

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type OauthIssuer struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	DeviceAuthURL   string   `json:"device_authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	RegistrationURL string   `json:"registration_endpoint"`
	GrantTypes      []string `json:"grant_types_supported"`
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
