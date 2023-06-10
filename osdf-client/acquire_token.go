package stashcp

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	config "github.com/htcondor/osdf-client/v6/config"
	namespaces "github.com/htcondor/osdf-client/v6/namespaces"
	log "github.com/sirupsen/logrus"
	jwt "github.com/golang-jwt/jwt"
	oauth2 "github.com/htcondor/osdf-client/v6/oauth2"
	oauth2_upstream "golang.org/x/oauth2"
)

func TokenIsAcceptable(jwtSerialized string, osdfPath string, namespace namespaces.Namespace, isWrite bool) bool {
	parser := jwt.Parser{SkipClaimsValidation: true}
	token, _, err := parser.ParseUnverified(jwtSerialized, &jwt.MapClaims{})
	if err != nil {
		log.Warningln("Failed to parse token:", err)
		return false
	}

	// For now, we'll accept any WLCG token
	wlcg_ver := (*token.Claims.(*jwt.MapClaims))["wlcg.ver"]
	if wlcg_ver == nil {
		return false
	}

	osdfPathCleaned := path.Clean(osdfPath)
	if !strings.HasPrefix(osdfPathCleaned, namespace.Path) {
		return false
	}

	// For some issuers, the token base path is distinct from the OSDF base path.
	// Example:
	// - Issuer base path: `/chtc`
	// - Namespace path: `/chtc/PROTECTED`
	// In this case, we want to strip out the issuer base path, not the
	// namespace one, in order to see if the token has the right privs.

	targetResource := path.Clean("/" + osdfPathCleaned[len(namespace.Path):])
	if namespace.CredentialGen != nil && namespace.CredentialGen.BasePath != nil && len(*namespace.CredentialGen.BasePath) > 0 {
		targetResource = path.Clean("/" + osdfPathCleaned[len(*namespace.CredentialGen.BasePath):])
	}

	scopes_iface := (*token.Claims.(*jwt.MapClaims))["scope"]
	if scopes, ok := scopes_iface.(string); ok {
		acceptableScope := false
		for _, scope := range strings.Split(scopes, " ") {
			scope_info := strings.Split(scope, ":")
			scopeOK := false
			if isWrite && (scope_info[0] == "storage.modify" || scope_info[0] == "storage.create") {
				scopeOK = true
			} else if scope_info[0] == "storage.read" {
				scopeOK = true
			}
			if !scopeOK {
				continue
			}

			if len(scope_info) == 1 {
				acceptableScope = true
				break
			}
			if strings.HasPrefix(targetResource, scope_info[1]) {
				acceptableScope = true
				break
			}
		}
		if acceptableScope {
			return true
		}
	}
	return false
}

func TokenIsExpired(jwtSerialized string) bool {
	parser := jwt.Parser{SkipClaimsValidation: true}
	token, _, err := parser.ParseUnverified(jwtSerialized, &jwt.StandardClaims{})
	if err != nil {
		log.Warningln("Failed to parse token:", err)
		return true
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
		return claims.Valid() != nil
	}
	return true
}

func RegisterClient(namespace namespaces.Namespace) (*config.PrefixEntry, error) {
	issuer, err := oauth2.GetIssuerMetadata(*namespace.CredentialGen.Issuer)
	if err != nil {
		return nil, err
	}
	if issuer.RegistrationURL == "" {
		return nil, fmt.Errorf("Issuer %s does not support dynamic client registration", *namespace.CredentialGen.Issuer)
	}

	drcp := oauth2.DCRPConfig{ClientRegistrationEndpointURL: issuer.RegistrationURL, Metadata: oauth2.Metadata{
		RedirectURIs: []string{"https://localhost/osdf-client"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes: []string{"code"},
		ClientName: "OSDF Command Line Client",
		Scopes: []string{"offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"},
	}}

	resp, err := drcp.Register()
	if err != nil {
		return nil, err
	}
	newEntry := config.PrefixEntry{
		Prefix: namespace.Path,
		ClientID: resp.ClientID,
		ClientSecret: resp.ClientSecret,
	}
	return &newEntry, nil
}

// Given a URL and a piece of the namespace, attempt to acquire a valid
// token for that URL.
func AcquireToken(destination *url.URL, namespace namespaces.Namespace, isWrite bool) (string, error) {
	log.Debugln("Acquiring a token from configuration and OAuth2")

	if namespace.CredentialGen == nil || namespace.CredentialGen.Strategy == nil {
		return "", fmt.Errorf("Credential generation scheme unknown for prefix %s", namespace.Path)
	}
	switch strategy := *namespace.CredentialGen.Strategy; strategy {
	case "OAuth2":
	case "Vault":
		return "", fmt.Errorf("Vault credential generation strategy is not supported")
	default:
		return "", fmt.Errorf("Unknown credential generation strategy (%s) for prefix %s",
                                      strategy, namespace.Path)
	}
	issuer := *namespace.CredentialGen.Issuer
	if len(issuer) == 0 {
		return "", fmt.Errorf("Issuer for prefix %s is unknown", namespace.Path)
	}

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
	var prefixEntry *config.PrefixEntry
	newEntry := false
	if prefixIdx < 0 {
		log.Infof("Prefix configuration for %s not in configuration file; will request new client", namespace.Path)
		prefixEntry, err = RegisterClient(namespace)
		if err != nil {
			return "", err
		}
		osdfConfig.OSDF.OauthClient = append(osdfConfig.OSDF.OauthClient, *prefixEntry)
		prefixEntry = &osdfConfig.OSDF.OauthClient[len(osdfConfig.OSDF.OauthClient) - 1]
		newEntry = true
	} else {
		prefixEntry = &osdfConfig.OSDF.OauthClient[prefixIdx]
		if len(prefixEntry.ClientID) == 0 || len(prefixEntry.ClientSecret) == 0 {
			log.Infof("Prefix configuration for %s missing OAuth2 client information", namespace.Path)
			prefixEntry, err = RegisterClient(namespace)
			if err != nil {
				return "", err
			}
			osdfConfig.OSDF.OauthClient[prefixIdx] = *prefixEntry
			newEntry = true
		}
	}
	if newEntry {
		if err = config.SaveConfigContents(&osdfConfig); err != nil {
			log.Warningln("Failed to save new token to configuration file:", err)
		}
	}

	// For now, a fairly useless token-selection algorithm - take the first in the list.
	// In the future, we should:
	// - Check scopes
	var acceptableToken *config.TokenEntry = nil
	acceptableUnexpiredToken := ""
	for idx, token := range prefixEntry.Tokens {
		if !TokenIsAcceptable(token.AccessToken, destination.Path, namespace, isWrite) {
			continue
		}
		if acceptableToken == nil {
			acceptableToken = &prefixEntry.Tokens[idx]
		} else if acceptableUnexpiredToken != "" {
			// Both tokens are non-empty; let's use them
			break
		}
		if !TokenIsExpired(token.AccessToken) {
			acceptableUnexpiredToken = token.AccessToken
		}
	}
	if len(acceptableUnexpiredToken) > 0 {
		log.Debugln("Returning an unexpired token from cache")
		return acceptableUnexpiredToken, nil
	}

	if acceptableToken != nil && len(acceptableToken.RefreshToken) > 0 {

		// We have a reasonable token; let's try refreshing it.
		upstreamToken := oauth2_upstream.Token{
			AccessToken: acceptableToken.AccessToken,
			RefreshToken: acceptableToken.RefreshToken,
			Expiry: time.Unix(0, 0),
		}
		issuerInfo, err := oauth2.GetIssuerMetadata(issuer)
		if err == nil {
			upstreamConfig := oauth2_upstream.Config{
				ClientID: prefixEntry.ClientID,
				ClientSecret: prefixEntry.ClientSecret,
				Endpoint: oauth2_upstream.Endpoint{
					AuthURL: issuerInfo.AuthURL,
					TokenURL: issuerInfo.TokenURL,
				}}
			ctx := context.Background()
			source := upstreamConfig.TokenSource(ctx, &upstreamToken)
			newToken, err := source.Token()
			if err != nil {
				log.Warningln("Failed to renew an expired token:", err)
			} else {
				acceptableToken.AccessToken = newToken.AccessToken
				acceptableToken.Expiration = newToken.Expiry.Unix()
				if len(newToken.RefreshToken) != 0 {
					acceptableToken.RefreshToken = newToken.RefreshToken
				}
				if err = config.SaveConfigContents(&osdfConfig); err != nil {
					log.Warningln("Failed to save new token to configuration file:", err)
				}
				return newToken.AccessToken, nil
			}
		}
	}

	token, err := oauth2.AcquireToken(issuer, prefixEntry, namespace.CredentialGen, destination.Path, isWrite)
	if err != nil {
		return "", err
	}

	Tokens := &prefixEntry.Tokens
	*Tokens = append(*Tokens, *token)

	if err = config.SaveConfigContents(&osdfConfig); err != nil {
		log.Warningln("Failed to save new token to configuration file:", err)
	}

	return token.AccessToken, nil
}

