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

package registry

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// This file has all custom validator logic for registry struct
// data validation besides the ones already included in validator package

func validatePrefix(nspath string) (string, error) {
	if len(nspath) == 0 {
		return "", errors.New("Path prefix may not be empty")
	}
	if nspath[0] != '/' {
		return "", errors.New("Path prefix must be absolute - relative paths are not allowed")
	}
	components := strings.Split(nspath, "/")[1:]
	if len(components) == 0 {
		return "", errors.New("Cannot register the prefix '/' for an origin")
	} else if components[0] == "api" {
		return "", errors.New("Cannot register a prefix starting with '/api'")
	} else if components[0] == "view" {
		return "", errors.New("Cannot register a prefix starting with '/view'")
	} else if components[0] == "pelican" {
		return "", errors.New("Cannot register a prefix starting with '/pelican'")
	}
	result := ""
	for _, component := range components {
		if len(component) == 0 {
			continue
		} else if component == "." {
			return "", errors.New("Path component cannot be '.'")
		} else if component == ".." {
			return "", errors.New("Path component cannot be '..'")
		} else if component[0] == '.' {
			return "", errors.New("Path component cannot begin with a '.'")
		}
		result += "/" + component
	}
	if result == "/" || len(result) == 0 {
		return "", errors.New("Cannot register the prefix '/' for an origin")
	}

	return result, nil
}

func validateKeyChaining(prefix string, pubkey jwk.Key) (inTopo bool, topoNss []Topology, validationError error, serverError error) {
	// We don't check keyChaining for caches
	if strings.HasPrefix(prefix, "/caches/") {
		return
	}
	// Here, we do the namespaceSupSubChecks anyway but only returns error (if any)
	// when the Registry.RequireKeyChaining flag is on. This is to make sure the topology check is independent
	// of key chaining check
	superspaces, subspaces, inTopo, topoNss, err := namespaceSupSubChecks(prefix)
	if !param.Registry_RequireKeyChaining.GetBool() {
		return
	} else {
		if err != nil {
			serverError = errors.Wrap(err, "Server encountered an error checking if namespace already exists")
			return
		}
	}

	// If we make the assumption that namespace prefixes are hierarchical, eg that the owner of /foo should own
	// everything under /foo (/foo/bar, /foo/baz, etc), then it makes sense to check for superspaces first. If any
	// superspace is found, they logically "own" the incoming namespace.
	if len(superspaces) > 0 {
		// If this is the case, we want to make sure that at least one of the superspaces has the
		// same registration key as the incoming. This guarantees the owner of the superspace is
		// permitting the action (assuming their keys haven't been stolen!)
		matched, err := matchKeys(pubkey, superspaces)
		if err != nil {
			serverError = errors.Errorf("%v: Unable to check if the incoming key for %s matched any public keys for %s", err, prefix, subspaces)
			return
		}
		if !matched {
			validationError = errors.New("Cannot register a namespace that is suffixed or prefixed by an already-registered namespace unless the incoming public key matches a registered key")
			return
		}

	} else if len(subspaces) > 0 {
		// If there are no superspaces, we can check the subspaces.

		// TODO: Eventually we might want to check only the highest level subspaces and use those keys for matching. For example,
		// if /foo/bar and /foo/bar/baz are registered with two keysets such that the complement of their intersections is not null,
		// it may be the case that the only key we match against belongs to /foo/bar/baz. If we go ahead with registration at that
		// point, we're essentially saying /foo/bar/baz, the logical subspace of /foo/bar, has authorized a superspace for both.
		// More interestingly, if /foo/bar and /foo/baz are both registered, should they both be consulted before adding /foo?

		// For now, we'll just check for any key match.
		matched, err := matchKeys(pubkey, subspaces)
		if err != nil {
			serverError = errors.Errorf("%v: Unable to check if the incoming key for %s matched any public keys for %s", err, prefix, subspaces)
			return
		}
		if !matched {
			validationError = errors.New("Cannot register a namespace that is suffixed or prefixed by an already-registered namespace unless the incoming public key matches a registered key")
			return
		}
	}
	return
}

func validateJwks(jwksStr string) (jwk.Key, error) {
	clientJwks, err := jwk.ParseString(jwksStr)
	if err != nil {
		return nil, errors.Wrap(err, "Couldn't parse the pubkey from the request")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Let's check that we can convert to JSON and get the right thing...
		jsonbuf, err := json.Marshal(clientJwks)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal the reuqest pubKey's keyset into JSON")
		}
		log.Debugln("Client JWKS as seen by the registry server:", string(jsonbuf))
	}

	/*
	 * TODO: This section makes the assumption that the incoming jwks only contains a single
	 *       key, a property that is enforced by the client at the origin. Eventually we need
	 *       to support the addition of other keys in the jwks stored for the origin. There is
	 *       a similar TODO listed in client_commands.go, as the choices made there mirror the
	 *       choices made here.
	 */
	key, exists := clientJwks.Key(0)
	if !exists {
		return nil, errors.New("There was no key at index 0 in the reuqest pubKey's JWKS. Something is wrong")
	}
	return key, nil
}

// Validates if the instID, the id of the institution, matches institution options
// provided through Registry.InstitutionsUrl or Registy.Institutions. If both are set,
// content of Registry.InstitutionsUrl will be ignored
func validateInstitution(instID string) (bool, error) {
	institutions := []Institution{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		return false, err
	}

	if len(institutions) == 0 {
		if institutionsCache == nil || institutionsCache.Len() == 0 {
			// We don't check if config and Registry.InstitutionsUrl was both unpopulated
			return true, nil
		} else {
			cachedInsts, intErr, extErr := getCachedInstitutions()
			if intErr != nil {
				log.Warning(intErr)
			}
			if extErr != nil {
				return false, errors.Wrap(extErr, "Error fetching instituions from TTL cache")
			}
			for _, availableInst := range cachedInsts {
				// We required full equality, as we expect the value is from the institution API
				if instID == availableInst.ID {
					return true, nil
				}
			}
		}
	}

	// When Registry.InstitutionsUrl was not set
	for _, availableInst := range institutions {
		// We required full equality, as we expect the value is from the institution API
		if instID == availableInst.ID {
			return true, nil
		}
	}
	return false, nil
}

// Validates if customFields are valid based on config. Set exactMatch to false to be
// backward compatible with legacy custom fields that were once defined but removed
func validateCustomFields(customFields map[string]interface{}, exactMatch bool) (bool, error) {
	if len(customRegFieldsConfigs) == 0 {
		if len(customFields) > 0 {
			return false, errors.New("Bad configuration, Registry.CustomRegistrationFields is not set while validate against custom fields")
		} else {
			return true, nil
		}
	} else {
		if customFields == nil {
			return false, errors.New("Can't validate against nil customFields")
		}
	}
	for _, conf := range customRegFieldsConfigs {
		val, ok := customFields[conf.Name]
		if !ok && conf.Required {
			return false, errors.New(fmt.Sprintf("%q is required", conf.Name))
		}
		if ok {
			switch conf.Type {
			case "string":
				if _, ok := val.(string); !ok {
					return false, errors.New(fmt.Sprintf("%q is expected to be a string, but got %v", conf.Name, val))
				}
			case "int":
				if _, ok := val.(int); !ok {
					return false, errors.New(fmt.Sprintf("%q is expected to be an int, but got %v", conf.Name, val))
				}
			case "bool":
				if _, ok := val.(bool); !ok {
					return false, errors.New(fmt.Sprintf("%q is expected to be a boolean, but got %v", conf.Name, val))
				}
			case "datetime":
				switch val.(type) {
				case int:
					break
				case int32:
					break
				case int64:
					break
				default:
					return false, fmt.Errorf("%q is expected to be a Unix timestamp, but got %v", conf.Name, val)
				}
			case "enum":
				inOpt := false
				for _, item := range conf.Options {
					if item.ID == val {
						inOpt = true
					}
				}
				if !inOpt {
					return false, fmt.Errorf("%q is an enumeration type, but the value is not in the options. Got %v", conf.Name, val)
				}
			default:
				return false, errors.New(fmt.Sprintf("The type of %q is not supported", conf.Name))
			}
		}
	}
	// Optioanlly check if the customFields are defined in config
	if exactMatch {
		for key := range customFields {
			found := false
			for _, conf := range customRegFieldsConfigs {
				if conf.Name == key {
					found = true
					break
				}
			}
			if !found {
				return false, errors.New(fmt.Sprintf("%q is not a valid custom field", key))
			}
		}
	}
	return true, nil
}
