package token_scopes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

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
			return jwt.NewValidationError(errors.New("No scope is present; required for authorization"))
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
