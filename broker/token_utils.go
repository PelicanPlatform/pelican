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

package broker

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// namespaceKeys caches the registry's public keys for each namespace, keyed by
// namespace prefix.  It is installed at startup and cleared at shutdown while
// requests may be reading it, so it is swapped atomically.
var namespaceKeys atomic.Pointer[token.JwksCache]

// namespaceKeyCapacity bounds how many namespaces are tracked at once.  The
// prefix is taken from the request before the caller's token has been verified,
// so without a bound a stream of made-up prefixes would grow the cache without
// limit.  Least recently used entries go first, which keeps the namespaces
// actually in use.
const namespaceKeyCapacity = 4096

// namespaceKeyRetryInterval is the minimum spacing between fetches of one
// namespace's keys, so that neither a down registry nor a run of tokens naming
// unknown key IDs turns into a run of registry requests.  A variable so tests
// can exercise the refresh paths without waiting it out; it is read when the
// cache is built.
var namespaceKeyRetryInterval = 30 * time.Second

// Launches a background goroutine that periodically expires
// the namespace key cache
func LaunchNamespaceKeyMaintenance(ctx context.Context, egrp *errgroup.Group) {
	// This is launched by both the director and the cache; if we are in a unit test
	// where both are running in the same process, we only want to
	// launch the goroutine once.
	if getNamespaceKeys() != nil {
		return
	}

	setNamespaceKeys(token.NewJwksCache(ctx, egrp,
		token.WithJwksCapacity(namespaceKeyCapacity),
		token.WithJwksRetryInterval(namespaceKeyRetryInterval),
		// The registry's answers here are specific: 404 for a namespace that is
		// not registered, 403 for one whose approval has been withdrawn.  Those
		// are the two ways a federation administrator removes a service, so
		// stop trusting the cached keys instead of serving them until the
		// staleness ceiling.
		token.WithJwksDropOnAbsence(),
	))

	egrp.Go(func() error {
		<-ctx.Done()
		setNamespaceKeys(nil)
		return nil
	})
}

func getNamespaceKeys() *token.JwksCache {
	return namespaceKeys.Load()
}

func setNamespaceKeys(cache *token.JwksCache) {
	namespaceKeys.Store(cache)
}

// registryJwksResolver returns the location of the registry's JWKS for the
// given namespace prefix.
func registryJwksResolver(prefix string) token.JwksUrlResolver {
	return func(context.Context) (string, error) {
		iss, err := getRegistryIssValue(prefix)
		if err != nil {
			return "", err
		}
		return iss + "/.well-known/issuer.jwks", nil
	}
}

// validateNamespacePrefix rejects a prefix that would not address the namespace
// it names.  The prefix reaches us from the request body, before the caller's
// token has been verified, and it is joined into the registry's URL path;
// joining cleans the result, so ".." segments would silently walk out of the
// registry's API path and point the lookup somewhere else on the registry.
func validateNamespacePrefix(prefix string) error {
	if prefix == "" {
		return errors.New("namespace prefix is empty")
	}
	if !strings.HasPrefix(prefix, "/") {
		return errors.Errorf("namespace prefix %q does not begin with '/'", prefix)
	}
	// Only relative segments are rejected.  Cache prefixes legitimately embed a
	// URL (/caches/https://cache.com), so the prefix is not required to survive
	// path.Clean unchanged -- just to not walk upward.
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "." || segment == ".." {
			return errors.Errorf("namespace prefix %q contains a relative path segment", prefix)
		}
	}
	return nil
}

// Given a namespace prefix, return the value that should be used
// by the `iss` claim in a token for this federation's registry.
func getRegistryIssValue(prefix string) (iss string, err error) {
	if err = validateNamespacePrefix(prefix); err != nil {
		return
	}

	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return
	}
	namespaceUrlStr := fedInfo.RegistryEndpoint
	if namespaceUrlStr == "" {
		err = errors.New("namespace URL is not set")
		return
	}
	namespaceUrl, err := url.Parse(namespaceUrlStr)
	if err != nil {
		return
	}
	namespaceUrl.Path, err = url.JoinPath(namespaceUrl.Path, "api", "v1.0", "registry", prefix)
	if err != nil {
		return
	}
	iss = namespaceUrl.String()
	return
}

// Given a namespace prefix, return the value for the `iss` claim and
// the public keyset to use
func getRegistryIssuerInfo(ctx context.Context, prefix string) (iss string, keyset jwk.Set, err error) {
	if iss, err = getRegistryIssValue(prefix); err != nil {
		return
	}

	cache := getNamespaceKeys()
	if cache == nil {
		err = errors.New("namespace key cache not initialized; call LaunchNamespaceKeyMaintenance first")
		return
	}

	keyset, err = cache.Keys(ctx, prefix, registryJwksResolver(prefix))
	if err != nil {
		err = errors.Wrapf(err, "failed to retrieve the registry's public keys for namespace %s", prefix)
		return
	}
	return
}

// refreshNamespaceKeys re-reads a namespace's keys from the registry ahead of
// their normal revalidation, subject to the cache's throttle.  It returns nil,
// and no error, when the throttle suppressed the fetch, and leaves the cached
// keys in place when the fetch fails.
func refreshNamespaceKeys(ctx context.Context, prefix string) (jwk.Set, error) {
	cache := getNamespaceKeys()
	if cache == nil {
		return nil, errors.New("namespace key cache not initialized; call LaunchNamespaceKeyMaintenance first")
	}
	return cache.Refresh(ctx, prefix, registryJwksResolver(prefix))
}

// signingKeyId returns the key ID named in the token's JWS header, or an empty
// string when the token does not name one.
func signingKeyId(tokenStr string) string {
	msg, err := jws.Parse([]byte(tokenStr))
	if err != nil {
		return ""
	}
	for _, sig := range msg.Signatures() {
		if hdrs := sig.ProtectedHeaders(); hdrs != nil {
			if kid := hdrs.KeyID(); kid != "" {
				return kid
			}
		}
	}
	return ""
}

// Create a signed JWT appropriate for retrieving requests from the connection broker
func createToken(namespace, subject, audience string, desiredScope token_scopes.TokenScope) (tokenStr string, err error) {
	issuerUrl, err := getRegistryIssValue(namespace)
	if err != nil {
		return
	}

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuerUrl
	tokenCfg.Subject = subject
	tokenCfg.AddAudiences(audience)
	tokenCfg.AddScopes(desiredScope)
	tokenStr, err = tokenCfg.CreateToken()

	return
}

func getCacheHostnameFromToken(tokenBytes []byte) (hostname string, err error) {
	tok, err := token.UnsafeParseClaims(string(tokenBytes))
	if err != nil {
		return
	}
	iss := tok.Issuer()
	expectedPrefix, err := getRegistryIssValue(server_structs.CachePrefix.String())
	if err != nil {
		return
	}
	hostname, hasPrefix := strings.CutPrefix(iss, expectedPrefix)
	if !hasPrefix {
		err = errors.Errorf("Token issuer %s doesn't start with expected registry issuer %s", iss, expectedPrefix)
		return
	}
	return
}

// Given a token and a namespace prefix, determine if it has the desired scope
// and audience.
func verifyToken(ctx context.Context, tokenStr, namespace, audience string, requiredScope token_scopes.TokenScope) (ok bool, err error) {
	issuerUrl, keyset, err := getRegistryIssuerInfo(ctx, namespace)
	if err != nil {
		err = errors.Wrapf(err, "failed to get issuer info for namespace %s", namespace)
		return
	}

	scopeValidator := token_scopes.CreateScopeValidator([]token_scopes.TokenScope{requiredScope}, false)
	verify := func(keys jwk.Set) error {
		_, verifyErr := token.VerifyWithKeyset(tokenStr, keys,
			jwt.WithAudience(audience),
			jwt.WithValidator(scopeValidator),
			jwt.WithClaimValue("iss", issuerUrl),
		)
		return verifyErr
	}

	verifyErr := verify(keyset)
	if verifyErr == nil {
		ok = true
		return
	}

	// Verification failed.  A namespace's registered keys churn as services
	// re-register or rotate them, so before rejecting, consider whether the
	// token was signed by a key we have not seen yet; the keys are otherwise
	// only re-read on their revalidation schedule.
	//
	// Deciding that costs another parse of the token, so it is worth reaching
	// only when it could change the answer.  A rejected claim -- expired,
	// wrong audience, insufficient scope -- says nothing about the keys, and
	// neither does a signature failure while the throttle would refuse to
	// re-read them anyway.  Both checks are cheap and both are common: the
	// first covers ordinary expired tokens, the second covers a caller sending
	// a run of tokens with made-up signing keys.
	cache := getNamespaceKeys()
	if errors.Is(verifyErr, token.ErrTokenSignature) && keyset != nil && cache != nil && cache.CanRefresh(namespace) {
		if kid := signingKeyId(tokenStr); kid != "" {
			if _, found := keyset.LookupKeyID(kid); !found {
				refreshed, refreshErr := refreshNamespaceKeys(ctx, namespace)
				if refreshErr != nil {
					log.Debugf("Failed to re-read keys for namespace %s after seeing unknown key ID %s: %v", namespace, kid, refreshErr)
				} else if refreshed != nil {
					if verifyErr = verify(refreshed); verifyErr == nil {
						ok = true
						return
					}
				}
			}
		}
	}

	err = errors.Wrap(verifyErr, "failed to verify token")
	return
}
