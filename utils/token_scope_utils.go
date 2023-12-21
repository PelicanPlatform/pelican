package utils

import "strings"

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
