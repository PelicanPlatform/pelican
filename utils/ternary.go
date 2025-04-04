/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

// This "ternary" file can be used to represent any values where valid states
// can be "true", "false", and "unknown".

package utils

type (
	Ternary int
)

const (
	Tern_Unknown Ternary = iota
	Tern_True
	Tern_False
)

func (t Ternary) String() string {
	switch t {
	case Tern_True:
		return "true"
	case Tern_False:
		return "false"
	default:
		return "unknown"
	}
}
