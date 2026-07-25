/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package client

import (
	"context"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/registry/registry_client"
)

var (
	// Serializes federation CA bootstrapping and caches its outcome so the root
	// is fetched at most once on success.
	fedCAMu sync.Mutex

	// Set true once the federation root has been successfully added to the trust
	// store; further calls become no-ops.
	fedCALoaded bool

	// Timestamp of the last (failed) fetch attempt, used to rate-limit retries
	// against a down or untrusting registry.
	fedCALastAttempt time.Time
)

// fedCARetryCooldown bounds how often we re-attempt fetching the federation root
// after a failure, so a persistently unreachable registry does not trigger a
// fetch on every single transfer.
const fedCARetryCooldown = time.Minute

// ensureFederationCATrust fetches the federation root certificate advertised at
// caEndpoint (the base registry URL, e.g. https://registry.example) and merges
// it into the client's TLS trust store. This allows a direct HTTPS connection to
// an origin presenting a federation-issued certificate -- for example one
// reached by IP with the origin's registry slug as the TLS ServerName -- to
// validate against the federation CA root.
//
// It is deliberately best-effort. A federation that advertises no CA endpoint,
// or a CA that is absent or unreachable, is logged and ignored -- never surfaced
// as an error -- so it can never break the client: transfers over the normal
// (DNS + publicly-trusted certificate) path keep working on the existing system
// trust. Because the fetch is itself an HTTPS GET to the registry, if the
// registry's own certificate is not yet trusted the fetch simply fails and we
// continue on existing trust (graceful bootstrapping degradation).
//
// The root is fetched at most once on success; transient failures are retried,
// but no more frequently than fedCARetryCooldown.
func ensureFederationCATrust(ctx context.Context, caEndpoint string) {
	if caEndpoint == "" {
		return
	}

	fedCAMu.Lock()
	defer fedCAMu.Unlock()

	if fedCALoaded {
		return
	}
	if !fedCALastAttempt.IsZero() && time.Since(fedCALastAttempt) < fedCARetryCooldown {
		return
	}
	fedCALastAttempt = time.Now()

	registryApiBase, err := url.JoinPath(caEndpoint, "api", "v1.0", "registry")
	if err != nil {
		log.Debugf("Unable to construct federation CA API base from %q: %v", caEndpoint, err)
		return
	}

	rootPEM, err := registry_client.FetchCABundle(ctx, registryApiBase)
	if err != nil {
		// Bootstrapping concern: this GET is itself validated against the current
		// trust store. If the registry's certificate is not yet trusted (or the
		// registry is simply down), degrade gracefully and keep using system trust.
		log.Debugf("Could not fetch federation CA bundle from %q; continuing on existing trust: %v", registryApiBase, err)
		return
	}

	added, err := config.AddFederationCA(rootPEM)
	if err != nil {
		log.Warningf("Failed to add the federation CA to the client trust store: %v", err)
		return
	}
	if added {
		log.Debugln("Added the federation CA root to the client TLS trust store")
	}
	fedCALoaded = true
}
