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
