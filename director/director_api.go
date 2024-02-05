/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	"strings"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// List all namespaces from origins registered at the director
func ListNamespacesFromOrigins() []NamespaceAdV2 {

	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()

	serverAdItems := serverAds.Items()
	namespaces := make([]NamespaceAdV2, 0, len(serverAdItems))
	for _, item := range serverAdItems {
		if item.Key().Type == OriginType {
			namespaces = append(namespaces, item.Value()...)
		}
	}
	return namespaces
}

// List all serverAds in the cache that matches the serverType array
func ListServerAds(serverTypes []ServerType) []ServerAd {
	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()
	ads := make([]ServerAd, 0)
	for _, ad := range serverAds.Keys() {
		for _, serverType := range serverTypes {
			if ad.Type == serverType {
				ads = append(ads, ad)
			}
		}
	}
	return ads
}

// Verify that a token received is a valid token from director and has
// correct scope for accessing the service discovery endpoint. This function
// is intended to be called on the same director server that issues the token.
func VerifyDirectorSDToken(strToken string) (bool, error) {
	// This token is essentialled an "issuer"/server itself issued token and
	// the server happended to be a director. This allows us to just follow
	// IssuerCheck logic for this token
	directorURL := param.Server_ExternalWebUrl.GetString()
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))
	if err != nil {
		return false, err
	}

	if directorURL != token.Issuer() {
		return false, errors.Errorf("Token issuer is not a director")
	}
	// Given that this function is intended to be called on the same director server
	// that issues the token. so it's safe to skip getting the public key
	// from director's discovery URL.
	key, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return false, err
	}
	tok, err := jwt.Parse([]byte(strToken), jwt.WithKeySet(key), jwt.WithValidate(true))
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
		if scope == token_scopes.Pelican_DirectorServiceDiscovery.String() {
			return true, nil
		}
	}
	return false, nil
}

// Configure TTL caches to enable cache eviction and other additional cache events handling logic
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
// goroutine and `wg` is the wait group to notify when the clean up goroutine finishes
func ConfigTTLCache(ctx context.Context, egrp *errgroup.Group) {
	// Start automatic expired item deletion
	go serverAds.Start()
	go namespaceKeys.Start()

	serverAds.OnEviction(func(ctx context.Context, er ttlcache.EvictionReason, i *ttlcache.Item[ServerAd, []NamespaceAdV2]) {
		healthTestCancelFuncsMutex.Lock()
		defer healthTestCancelFuncsMutex.Unlock()
		if cancelFunc, exists := healthTestCancelFuncs[i.Key()]; exists {
			// Call the cancel function for the evicted originAd to end its health test
			cancelFunc()

			// Remove the cancel function from the map as it's no longer needed
			delete(healthTestCancelFuncs, i.Key())
		}
	})

	// Put stop logic in a separate goroutine so that parent function is not blocking
	egrp.Go(func() error {
		<-ctx.Done()
		log.Info("Gracefully stopping director TTL cache eviction...")
		serverAds.DeleteAll()
		serverAds.Stop()
		namespaceKeys.DeleteAll()
		namespaceKeys.Stop()
		log.Info("Director TTL cache eviction has been stopped")
		return nil
	})
}
