
package config


// Structs holding the OAuth2 state (and any other OSDF config needed)

type TokenEntry struct {
	Expiration   int64  `yaml:"expiration"`
	AccessToken  string `yaml:"access_token"`
	RefreshToken string `yaml:"refresh_token,omitempty"`
}

type PrefixEntry struct {
// OSDF namespace prefix
	Prefix       string `yaml:"prefix"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Tokens     []TokenEntry `yaml:"tokens,omitempty"`
}

type OSDFConfig struct {

	// Top-level OSDF object
	OSDF struct {
		// List of OAuth2 client configurations
		OauthClient [] PrefixEntry `yaml:"oauth_client,omitempty"`
	} `yaml:"OSDF"`
}
