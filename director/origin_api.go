package director

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
)

type (
	OriginAdvertise struct {
		Name       string        `json:"name"`
		URL        string        `json:"url"`
		Namespaces []NamespaceAd `json:"namespaces"`
	}
)

var (
	namespaceKeys      = ttlcache.New[string, *jwk.Cache](ttlcache.WithTTL[string, *jwk.Cache](15 * time.Minute))
	namespaceKeysMutex = sync.RWMutex{}
)

func CreateAdvertiseToken(namespace string) (string, error) {
	key, err := config.GetOriginJWK()
	if err != nil {
		return "", err
	}
	issuer_url, err := GetIssuerURL(namespace)
	if err != nil {
		return "", err
	}
	director := viper.GetString("DirectorURL")
	if director == "" {
		return "", errors.New("Director URL is not known; cannot create advertise token")
	}

	tok, err := jwt.NewBuilder().
		Claim("scope", "pelican.advertise").
		Issuer(issuer_url).
		Audience([]string{director}).
		Subject("origin").
		Expiration(time.Now().Add(time.Minute)).
		Build()
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, key))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// Given a token and a location in the namespace to advertise in,
// see if the entity is authorized to advertise an origin for the
// namespace
func VerifyAdvertiseToken(token, namespace string) (bool, error) {
	issuer_url, err := GetIssuerURL(namespace)
	if err != nil {
		return false, err
	}
	var ar *jwk.Cache
	{
		namespaceKeysMutex.RLock()
		defer namespaceKeysMutex.Unlock()
		item := namespaceKeys.Get(namespace)
		if !item.IsExpired() {
			ar = item.Value()
		}
	}
	ctx := context.Background()
	if ar == nil {
		ar := jwk.NewCache(ctx)
		if err = ar.Register(issuer_url, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
			return false, err
		}
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		namespaceKeys.Set(namespace, ar, ttlcache.DefaultTTL)
	}
	keyset, err := ar.Get(ctx, issuer_url)
	if err != nil {
		return false, err
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(keyset), jwt.WithValidate(true))
	if err != nil {
		return false, err
	}

	scope_any, present := tok.Get("scope")
	if !present {
		return false, errors.New("No scope is present; required to advertise to director")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}

	scopes := strings.Split(scope, " ")

	for _, scope := range scopes {
		if scope == "pelican.advertise" {
			return true, nil
		}
	}
	return false, nil
}

func GetIssuerURL(prefix string) (string, error) {
	namespace_url_string := viper.GetString("NamespaceURL")
	if namespace_url_string == "" {
		return "", errors.New("Namespace URL is not set")
	}
	namespace_url, err := url.Parse(namespace_url_string)
	if err != nil {
		return "", err
	}
	namespace_url.Path = path.Join(namespace_url.Path, "namespaces", prefix)
	return namespace_url.String(), nil
}
