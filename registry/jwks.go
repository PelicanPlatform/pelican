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

package registry

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

// publicJWKSForServing returns the public projection of a JWKS loaded from the
// registry database, ready to publish. Registrants submit their own key
// material, which is never validated to be public-only, so this degrades
// gracefully: any symmetric (kty=oct) key or key that cannot be projected by
// jwk.PublicKeyOf is logged and skipped rather than failing, so one malformed
// stored key cannot turn a namespace's key endpoint into an HTTP 500. Private
// key material is always removed via jwk.PublicKeyOf.
//
// Skipping individual keys is safe, but skipping *every* key is not: if a
// non-empty stored set projects to nothing, there is no correct subset left to
// serve, and returning an empty JWKS with HTTP 200 would silently break token
// verification federation-wide while looking healthy. That case is a hard
// error, mirroring the "no correct subset left to serve" rule in
// config.GetIssuerPublicJWKSForNamespace. A genuinely empty input set is not an
// error: it projects to an empty set, which callers serve as-is.
//
// This is deliberately more lenient than config.stripPrivateKeys, which is used
// for the server's own trusted keys where any bad key is a hard error.
func publicJWKSForServing(set jwk.Set) (jwk.Set, error) {
	// The callback never returns an error, so ProjectPublicJWKS cannot fail
	// here: every unpublishable key is logged and skipped.
	out, _ := config.ProjectPublicJWKS(set, func(k jwk.Key, err error) error {
		log.Warnf("Skipping key %q while publishing JWKS: %v", k.KeyID(), err)
		return nil
	})
	if set.Len() > 0 && out.Len() == 0 {
		return nil, errors.Errorf(
			"all %d stored key(s) are unpublishable; refusing to serve an empty JWKS",
			set.Len())
	}
	return out, nil
}
