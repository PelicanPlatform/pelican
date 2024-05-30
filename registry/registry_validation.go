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

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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
		return "", errors.New("Cannot register the prefix '/'")
	}
	// Check cache/origin prefxies
	if strings.TrimPrefix(nspath, server_structs.OriginPrefix.String()) == "" {
		return "", errors.New("Origin prefix is missing hostname")
	}
	if strings.TrimPrefix(nspath, server_structs.CachePrefix.String()) == "" {
		return "", errors.New("Cache prefix is missing sitename")
	}
	if server_structs.IsCacheNS(nspath) {
		hostname := strings.TrimPrefix(nspath, server_structs.CachePrefix.String()) // /caches/blah -> blah
		if server_structs.IsCacheNS("/" + hostname) {                               // /caches/caches/blah -> caches/blah -> /caches/blah
			return "", errors.Errorf("Duplicated cache prefix %s", nspath)
		}
	} else if server_structs.IsOriginNS(nspath) {
		hostname := strings.TrimPrefix(nspath, server_structs.OriginPrefix.String()) // /origins/blah -> blah
		if server_structs.IsOriginNS("/" + hostname) {                               // /origins/origins/blah -> origins/blah -> /origins/blah
			return "", errors.Errorf("Duplicated origin prefix %s", nspath)
		}
	}

	return result, nil
}

func validateKeyChaining(prefix string, pubkey jwk.Key) (inTopo bool, topoNss []Topology, validationError error, serverError error) {
	// We don't check keyChaining for caches or origins
	if server_structs.IsCacheNS(prefix) || server_structs.IsOriginNS(prefix) {
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
	if jwksStr == "" {
		return nil, errors.New("public key is empty")
	}
	clientJwks, err := jwk.ParseString(jwksStr)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't parse the pubkey from the request")
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
// provided through Registry.InstitutionsUrl or Registry.Institutions. If both are set,
// content of Registry.InstitutionsUrl will be ignored
func validateInstitution(instID string) (bool, error) {
	if instID == "" {
		return false, errors.New("Institution ID is required")
	}

	institutions := []registrationFieldOption{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		return false, err
	}

	if len(institutions) == 0 {
		instUrl := param.Registry_InstitutionsUrl.GetString()
		instUrlTTL := param.Registry_InstitutionsUrlReloadMinutes.GetDuration()
		if instUrl == "" {
			// We don't check if config and Registry.InstitutionsUrl was both unpopulated
			return true, nil
		} else {
			insts, err := getCachedOptions(instUrl, instUrlTTL)
			if err != nil {
				return false, errors.Wrap(err, "Error fetching instituions from TTL cache")
			}
			for _, availableInst := range insts {
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
func validateCustomFields(customFields map[string]interface{}) (bool, error) {
	if len(customRegFieldsConfigs) == 0 {
		if len(customFields) > 0 {
			return false, errors.New("Bad configuration, Registry.CustomRegistrationFields is not set while validate against custom fields")
		} else {
			return true, nil
		}
	}
	// We initialized all registration fields in registrationFields variable and
	// this is the source of truth for validation
	for idx, regField := range registrationFields {
		// This is how we mark the field is a custom field
		if !strings.HasPrefix(regField.Name, "custom_fields.") {
			continue
		}
		// This is the key of customFields
		custFieldName := strings.TrimPrefix(regField.Name, "custom_fields.")

		if regField.Required && customFields == nil {
			return false, fmt.Errorf("%q is required", regField.DisplayedName)
		} else if !regField.Required && customFields == nil { // Not required,and no input, pass
			continue
		} else { // input is not nil, do the validation first, then do the requirement check
			inField, ok := customFields[custFieldName]
			if !ok && regField.Required {
				return false, fmt.Errorf("%q is required", regField.DisplayedName)
			}
			if ok { // found, do the validation check
				switch regField.Type {
				case "string":
					if _, ok := inField.(string); !ok {
						return false, errors.New(fmt.Sprintf("%q is expected to be a string, but got %v", regField.DisplayedName, inField))
					}
				case "int":
					if _, ok := inField.(int); !ok {
						return false, errors.New(fmt.Sprintf("%q is expected to be an int, but got %v", regField.DisplayedName, inField))
					}
				case "bool":
					if _, ok := inField.(bool); !ok {
						return false, errors.New(fmt.Sprintf("%q is expected to be a boolean, but got %v", regField.DisplayedName, inField))
					}
				case "datetime":
					switch inField.(type) {
					case int:
						break
					case int32:
						break
					case int64:
						break
					default:
						return false, fmt.Errorf("%q is expected to be a Unix timestamp, but got %v", regField.DisplayedName, inField)
					}
				case "enum":
					// Get the options from optionsCache if OptionsUrl is set
					// and update the registrationFields accordingly
					options := regField.Options
					if regField.OptionsUrl != "" {
						fetchedOptions, err := getCachedOptions(regField.OptionsUrl, ttlcache.DefaultTTL)
						if err != nil {
							log.Errorf("Error getting/fetching options for the field %s. Use cached options instead", regField.DisplayedName)
						} else {
							options = fetchedOptions
							registrationFields[idx].Options = options
						}
					}

					// Check the provided option is in the list of available options
					if len(options) == 0 {
						return false, fmt.Errorf("Bad configuration, the custom field %q has empty options", regField.DisplayedName)
					}
					inOpt := false
					for _, item := range options {
						if item.ID == inField {
							inOpt = true
							break
						}
					}
					if !inOpt {
						return false, fmt.Errorf("%q is an enumeration type, but the value (ID) is not in the options. Got %v. Available options are: %s", regField.DisplayedName, inField, optionsToString(regField.Options))
					}
				default:
					return false, errors.New(fmt.Sprintf("field %q has unsupported type %s", regField.DisplayedName, regField.Type))
				}
			}
		}
	}
	// Check the custom fields exists in the configured fields
	for key := range customFields {
		found := false
		for _, conf := range registrationFields {
			if strings.TrimPrefix(conf.Name, "custom_fields.") == key {
				found = true
				break
			}
		}
		if !found {
			return false, errors.New(fmt.Sprintf("%q is not a valid custom field", key))
		}
	}
	return true, nil
}
