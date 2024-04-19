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

package test_utils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/config"
	"golang.org/x/sync/errgroup"
)

func TestContext(ictx context.Context, t *testing.T) (ctx context.Context, cancel context.CancelFunc, egrp *errgroup.Group) {
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ictx, deadline)
	} else {
		ctx, cancel = context.WithCancel(ictx)
	}
	egrp, ctx = errgroup.WithContext(ctx)
	ctx = context.WithValue(ctx, config.EgrpKey, egrp)
	return
}

// GenerateJWK generates a JWK private key and a corresponding JWKS public key,
// and the string representation of the public key
func GenerateJWK() (jwk.Key, jwk.Set, string, error) {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWK from the private key
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "mykey")
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	// Extract the public key
	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWKS from the public key
	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		return nil, nil, "", err
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, nil, "", err
	}

	return jwkKey, jwks, string(jwksBytes), nil
}

// For these tests, we only need to lookup key locations. Create a dummy registry that only returns
// the jwks_uri location for the given key. Once a server is instantiated, it will only return
// locations for the provided prefix. To change prefixes, create a new registry mockup.
func RegistryMockup(t *testing.T, prefix string) *httptest.Server {
	registryUrl, _ := url.Parse("https://registry.com:8446")
	path, err := url.JoinPath("/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to parse key path for prefix %s", prefix)
	}
	registryUrl.Path = path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + registryUrl.String() + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	}))
	t.Cleanup(server.Close)
	return server
}
