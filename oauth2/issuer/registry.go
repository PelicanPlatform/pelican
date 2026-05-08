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

package issuer

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// ProviderRegistry maps federation namespace prefixes to their per-namespace
// OIDCProvider instances. It is safe for concurrent reads (providers are
// registered once at startup; the map is not mutated after that).
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]*OIDCProvider

	// RegistrationLimiter is a shared rate limiter for dynamic client
	// registration across all namespaces, preventing an attacker from
	// multiplying the per-IP rate limit by cycling through namespaces.
	RegistrationLimiter *registrationRateLimiter
}

// NewProviderRegistry creates an empty provider registry with a shared
// rate limiter for dynamic client registration.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers:           make(map[string]*OIDCProvider),
		RegistrationLimiter: newRegistrationRateLimiter(1.0/60.0, 5),
	}
}

// Register adds a provider for the given namespace prefix.
func (r *ProviderRegistry) Register(namespace string, provider *OIDCProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[namespace] = provider
}

// Get returns the provider for a namespace, or nil if not found.
func (r *ProviderRegistry) Get(namespace string) *OIDCProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[namespace]
}

// Namespaces returns all registered namespace prefixes.
func (r *ProviderRegistry) Namespaces() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ns := make([]string, 0, len(r.providers))
	for k := range r.providers {
		ns = append(ns, k)
	}
	return ns
}

// First returns the first registered provider (arbitrary order).
// This is a convenience for the launcher health check which just needs
// any valid provider to verify the issuer is up.
func (r *ProviderRegistry) First() *OIDCProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.providers {
		return p
	}
	return nil
}

// namespaceContextKey is the gin context key for the resolved namespace.
const namespaceContextKey = "issuerNamespace"

// providerContextKey is the gin context key for the resolved OIDCProvider.
const providerContextKey = "issuerProvider"

// registryContextKey is the gin context key for the ProviderRegistry.
const registryContextKey = "issuerRegistry"

// NamespaceMiddleware returns a Gin middleware that extracts the namespace
// from the URL path and resolves the corresponding OIDCProvider.
//
// The route must contain a wildcard parameter named "namespace" that captures
// the federation prefix (e.g. /api/v1.0/issuer/ns/*namespace/token).
// The middleware strips any trailing action component (e.g. "/token") before
// looking up the provider, but the full namespace is on the *namespace param.
//
// Actually: the middleware uses the gin wildcard and the registry to find the
// matching namespace by longest-prefix match, since the wildcard captures
// everything after /ns/ (both namespace and action).
func NamespaceMiddleware(registry *ProviderRegistry) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// The *namespace wildcard captures e.g. "/data/analysis/token"
		// We need to find which registered namespace prefix matches.
		fullPath := ctx.Param("namespace")
		if fullPath == "" {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "namespace required"})
			ctx.Abort()
			return
		}

		// Try longest-prefix match against registered namespaces.
		provider := resolveProvider(registry, fullPath)
		if provider == nil {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":             "unknown_namespace",
				"error_description": "No issuer configured for the requested namespace",
			})
			ctx.Abort()
			return
		}

		ctx.Set(namespaceContextKey, provider.Namespace)
		ctx.Set(providerContextKey, provider)
		ctx.Set(registryContextKey, registry)
		ctx.Next()
	}
}

// resolveProvider finds the OIDCProvider whose namespace is a prefix of the
// given path. It picks the longest matching prefix and requires matches at
// path-component boundaries to prevent prefix aliasing (e.g. "/test/ns"
// must not match "/test/nsoidc-cm").
func resolveProvider(registry *ProviderRegistry, path string) *OIDCProvider {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var best *OIDCProvider
	bestLen := 0
	for ns, p := range registry.providers {
		if path == ns || strings.HasPrefix(path, ns+"/") {
			if len(ns) > bestLen {
				best = p
				bestLen = len(ns)
			}
		}
	}
	return best
}

// GetProvider extracts the OIDCProvider from the Gin context (set by
// NamespaceMiddleware).
func GetProvider(ctx *gin.Context) *OIDCProvider {
	v, _ := ctx.Get(providerContextKey)
	if v == nil {
		return nil
	}
	return v.(*OIDCProvider)
}

// GetNamespace extracts the resolved namespace from the Gin context.
func GetNamespace(ctx *gin.Context) string {
	return ctx.GetString(namespaceContextKey)
}

// GetRegistry extracts the ProviderRegistry from the Gin context.
func GetRegistry(ctx *gin.Context) *ProviderRegistry {
	v, _ := ctx.Get(registryContextKey)
	if v == nil {
		return nil
	}
	return v.(*ProviderRegistry)
}

// ActionSuffix returns the portion of the wildcard path after the namespace
// prefix. For example, if namespace is "/data/analysis" and the wildcard is
// "/data/analysis/token", the action is "/token".
func ActionSuffix(ctx *gin.Context) string {
	ns := GetNamespace(ctx)
	full := ctx.Param("namespace")
	if ns == "" || full == "" {
		return full
	}
	return strings.TrimPrefix(full, ns)
}
