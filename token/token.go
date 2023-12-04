/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package token

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
