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

package token_scopes

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type (
	// A resourced scope is a scope whose privileges
	// are narrowed to a specific resource.  If there's
	// the authorization for foo, then the ResourceScope of
	// foo:/bar also contains foo:/bar/baz.
	ResourceScope struct {
		Authorization TokenScope
		Resource      string
	}
)

func NewResourceScope(authz TokenScope, resource string) ResourceScope {
	return ResourceScope{
		Authorization: authz,
		Resource:      path.Clean("/" + resource),
	}
}

func (rc ResourceScope) String() string {
	if rc.Resource == "/" {
		return string(rc.Authorization)
	}
	return rc.Authorization.String() + ":" + rc.Resource
}

func (rc ResourceScope) Contains(other ResourceScope) bool {
	if rc.Authorization != other.Authorization {
		return false
	}
	if strings.HasPrefix(other.Resource, rc.Resource) {
		if len(rc.Resource) == 1 {
			return true
		}
		if len(other.Resource) > len(rc.Resource) {
			return other.Resource[len(rc.Resource)] == '/'
		}
		return true
	}
	return false
}

// Get a string representation of a list of scopes, which can then be passed
// to the Claim builder of JWT constructor
func GetScopeString(scopes []TokenScope) (scopeString string) {
	scopeString = ""
	if len(scopes) == 0 {
		return
	}
	if len(scopes) == 1 {
		scopeString = string(scopes[0])
		return
	}
	for _, scope := range scopes {
		scopeString += scope.String() + " "
	}
	scopeString = strings.TrimRight(scopeString, " ")
	return
}

// Get a list of resource-style scopes from the token
func ParseResourceScopeString(tok jwt.Token) (scopes []ResourceScope) {
	scopes = make([]ResourceScope, 0)
	scopeAny, ok := tok.Get("scope")
	if !ok {
		return
	}
	scopeString, ok := scopeAny.(string)
	if !ok {
		return
	}
	for _, scope := range strings.Split(scopeString, " ") {
		if scope == "" {
			continue
		}
		info := strings.SplitN(scope, ":", 2)
		if len(info) == 1 {
			scopes = append(scopes, NewResourceScope(TokenScope(info[0]), "/"))
		} else {
			scopes = append(scopes, NewResourceScope(TokenScope(info[0]), info[1]))
		}
	}
	return
}

// Return if expectedScopes contains the tokenScope and it's case-insensitive.
// If all=false, it checks if the tokenScopes have any one scope in expectedScopes;
// If all=true, it checks if tokenScopes is the same set as expectedScopes
func ScopeContains(tokenScopes []string, expectedScopes []TokenScope, all bool) bool {
	if !all { // Any tokenScope in desiredScopes is OK
		for _, tokenScope := range tokenScopes {
			for _, sc := range expectedScopes {
				if strings.EqualFold(sc.String(), tokenScope) {
					return true
				}
			}
		}
		return false
	} else { // All tokenScope must be in desiredScopes
		if len(tokenScopes) != len(expectedScopes) {
			return false
		}
		sort.Strings(tokenScopes)
		slices.Sort(expectedScopes)
		for i := 0; i < len(tokenScopes); i++ {
			if tokenScopes[i] != expectedScopes[i].String() {
				return false
			}
		}
		return true
	}
}

// Creates a validator that checks if a token's scope matches the given scope: expectedScopes.
// See `scopeContains` for detailed checking mechanism
func CreateScopeValidator(expectedScopes []TokenScope, all bool) jwt.ValidatorFunc {

	return jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		// If no scope is present, always return true
		if len(expectedScopes) == 0 {
			return nil
		}
		scope_any, present := tok.Get("scope")
		if !present {
			return jwt.NewValidationError(errors.New("no scope is present; required for authorization"))
		}
		scope, ok := scope_any.(string)
		if !ok {
			return jwt.NewValidationError(errors.New("scope claim in token is not string-valued"))
		}
		if ScopeContains(strings.Split(scope, " "), expectedScopes, all) {
			return nil
		}
		return jwt.NewValidationError(errors.New(fmt.Sprint("Token does not contain any of the scopes: ", expectedScopes)))
	})
}
