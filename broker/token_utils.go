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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
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

var (
	// A thread-safe cache for the namespace public keys
	namespaceKeys *ttlcache.Cache[string, *jwk.Cache]
)

const (
	// namespaceKeyTTL bounds how long a namespace's key fetcher is retained
	// after it stops being used.  Entries in active use are kept alive
	// indefinitely (see the touch-on-hit note in LaunchNamespaceKeyMaintenance).
	namespaceKeyTTL = 15 * time.Minute

	// jwksMinRefreshInterval is the floor on how often the background
	// refresher re-fetches a namespace's JWKS from the registry.  Key
	// rotations are normally picked up within this interval.
	jwksMinRefreshInterval = 15 * time.Minute

	// jwksFetchTimeout bounds a single synchronous JWKS fetch.
	jwksFetchTimeout = 10 * time.Second
)

// jwksForcedRefreshInterval rate-limits the out-of-band refresh triggered by a
// token naming a key we do not hold, so that a stream of bogus key IDs cannot
// become a stream of registry fetches.  A variable so tests can drive the
// rotation path without waiting it out.
var jwksForcedRefreshInterval = 30 * time.Second

// jwksErrSink reports background JWKS refresh failures, which the jwk cache
// otherwise discards silently.  Without it, a namespace whose refreshes have
// been failing keeps serving its last known good keys with nothing in the log
// to explain why a rotated key never took effect.
type jwksErrSink struct {
	iss string
}

func (s jwksErrSink) Error(err error) {
	log.Warningf("Background JWKS refresh failed for issuer %s (serving last known good keys): %v", s.iss, err)
}

// Launches a background goroutine that periodically expires
// the namespace key cache
func LaunchNamespaceKeyMaintenance(ctx context.Context, egrp *errgroup.Group) {
	// This is launched by both the director and the cache; if we are in a unit test
	// where both are running in the same process, we only want to
	// launch the goroutine once.
	if namespaceKeys != nil {
		return
	}

	loader := ttlcache.LoaderFunc[string, *jwk.Cache](
		func(cache *ttlcache.Cache[string, *jwk.Cache], prefix string) *ttlcache.Item[string, *jwk.Cache] {
			iss, err := getRegistryIssValue(prefix)
			if err != nil {
				return nil
			}
			// The actual location of the JWKS at the registry
			jwksUrl := iss + "/.well-known/issuer.jwks"

			ar := jwk.NewCache(ctx, jwk.WithErrSink(jwksErrSink{iss: iss}))
			client := &http.Client{Transport: config.GetBasicTransport()}
			if err = ar.Register(jwksUrl, jwk.WithMinRefreshInterval(jwksMinRefreshInterval), jwk.WithHTTPClient(client)); err != nil {
				log.Errorln("Failed to fetch issuer information for", iss, "from JWKS URL", jwksUrl, ":", err)
				return nil
			}
			// Register does not fetch; the first fetch happens in
			// getRegistryIssuerInfo, which can report a failure to the caller
			// and retry on the next request.
			log.Debugln("Setting public key cache for issuer", iss)
			item := cache.Set(prefix, ar, ttlcache.DefaultTTL)
			return item
		},
	)
	// Touch-on-hit is deliberately left enabled here, unlike the token
	// authorization caches fixed for #3696.  Entries hold self-refreshing
	// jwk.Cache fetchers rather than authorization decisions, and the keyset
	// lives inside the fetcher: a namespace's registered keys do churn, but
	// those changes arrive through the fetcher's own refresh loop no matter
	// how old the entry is, so extending an entry never prolongs a stale key.
	// Dropping a fetcher, by contrast, discards the last known good keyset
	// with it.  Keeping busy prefixes pinned therefore means a registry
	// outage cannot break token verification for the namespaces that are
	// actually in use, while the TTL still reclaims fetchers for idle ones.
	namespaceKeys = ttlcache.New(
		ttlcache.WithTTL[string, *jwk.Cache](namespaceKeyTTL),
		ttlcache.WithLoader(ttlcache.NewSuppressedLoader(loader, nil)),
	)

	go namespaceKeys.Start()
	egrp.Go(func() error {
		<-ctx.Done()
		namespaceKeys.Stop()
		namespaceKeys.DeleteAll()
		namespaceKeys = nil
		return nil
	})
}

// Given a namespace prefix, return the value that should be used
// by the `iss` claim in a token for this federation's registry.
func getRegistryIssValue(prefix string) (iss string, err error) {
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

	// The actual location of the JWKS at the registry
	jwksUrl := iss + "/.well-known/issuer.jwks"

	if namespaceKeys == nil {
		err = errors.New("namespace key cache not initialized; call LaunchNamespaceKeyMaintenance first")
		return
	}

	item := namespaceKeys.Get(prefix)
	if item == nil || item.Value() == nil {
		err = errors.Errorf("failed to load issuer information for namespace %s: namespace may not be registered in the registry or registry endpoint is unreachable", prefix)
		return
	}
	fetcher := item.Value()
	keyset, err = fetcher.Get(ctx, jwksUrl)
	if err == nil && keyset != nil && keyset.Len() > 0 {
		return
	}

	// We have no usable keys for this namespace.  The fetcher may simply be
	// new, or it may be one whose earlier fetch failed: the jwk cache stamps
	// an entry as fetched before the attempt, so a fetcher that has never
	// succeeded is never retried by Get and keeps returning nothing.  Force
	// one attempt so the namespace recovers as soon as the registry does.
	// A fetcher already holding keys never reaches this path, which is what
	// keeps a registry outage from disturbing namespaces that are in use.
	refreshCtx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	keyset, err = fetcher.Refresh(refreshCtx, jwksUrl)
	if err != nil {
		err = errors.Wrapf(err, "failed to retrieve keyset from JWKS URL %s for namespace %s", jwksUrl, prefix)
		return
	}
	return
}

// refreshNamespaceKeys forces an out-of-band JWKS fetch for the namespace,
// rate-limited to one attempt per jwksForcedRefreshInterval.  It returns the
// refreshed keyset, or nil when the rate limit suppressed the fetch.  A failed
// fetch leaves the fetcher's last known good keyset untouched.
func refreshNamespaceKeys(ctx context.Context, prefix string) (jwk.Set, error) {
	if namespaceKeys == nil {
		return nil, errors.New("namespace key cache not initialized; call LaunchNamespaceKeyMaintenance first")
	}
	iss, err := getRegistryIssValue(prefix)
	if err != nil {
		return nil, err
	}
	jwksUrl := iss + "/.well-known/issuer.jwks"

	item := namespaceKeys.Get(prefix)
	if item == nil || item.Value() == nil {
		return nil, errors.Errorf("failed to load issuer information for namespace %s", prefix)
	}
	fetcher := item.Value()
	if fetchedWithin(fetcher, jwksUrl, jwksForcedRefreshInterval) {
		return nil, nil
	}

	refreshCtx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	return fetcher.Refresh(refreshCtx, jwksUrl)
}

// fetchedWithin reports whether the fetcher last attempted to retrieve the
// given URL less than d ago.  The jwk cache records the attempt time whether
// or not it succeeded, so this throttles retries against a failing registry
// as well as refreshes against a healthy one.
func fetchedWithin(fetcher *jwk.Cache, jwksUrl string, d time.Duration) bool {
	snapshot := fetcher.Snapshot()
	if snapshot == nil {
		return false
	}
	for _, entry := range snapshot.Entries {
		if entry.URL == jwksUrl {
			return time.Since(entry.LastFetched) < d
		}
	}
	return false
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

	// A namespace's registered keys churn as services re-register or rotate
	// them.  The background refresher only runs every jwksMinRefreshInterval,
	// so a token signed by a newly registered key would otherwise be rejected
	// until that interval elapsed.  When the token names a key we do not hold,
	// pull the keyset again (rate-limited) before deciding.
	if kid := signingKeyId(tokenStr); kid != "" && keyset != nil {
		if _, found := keyset.LookupKeyID(kid); !found {
			refreshed, rerr := refreshNamespaceKeys(ctx, namespace)
			if rerr != nil {
				// Keep going with the keys we have: the token may still verify,
				// and if it does not the verification error is the useful one.
				log.Debugf("Failed to refresh keys for namespace %s after seeing unknown key ID %s: %v", namespace, kid, rerr)
			} else if refreshed != nil {
				keyset = refreshed
			}
		}
	}

	scopeValidator := token_scopes.CreateScopeValidator([]token_scopes.TokenScope{requiredScope}, false)
	_, err = token.VerifyWithKeyset(tokenStr, keyset,
		jwt.WithAudience(audience),
		jwt.WithValidator(scopeValidator),
		jwt.WithClaimValue("iss", issuerUrl),
	)
	if err == nil {
		ok = true
	} else {
		err = errors.Wrap(err, "failed to verify token")
	}
	return
}
