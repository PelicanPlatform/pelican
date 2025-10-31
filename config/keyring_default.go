//go:build !linux || (linux && !amd64)

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

package config

var savedPassword bool = false
var savedPasswordVal []byte = make([]byte, 0)

// Returns the password stored in the session keyring, or an empty byte
// array if it cannot be found. The keyring is provided by in-process memory
// because we assume that the kernel key retention service is unavailable.
func TryGetPassword() ([]byte, error) {
	if savedPassword {
		return savedPasswordVal, nil
	}
	return make([]byte, 0), nil
}

// Saves a password to the session keyring. The keyring is provided by
// in-process memory because we assume that the kernel key retention service
// is unavailable.
func SavePassword(password []byte) error {
	savedPasswordVal = password
	savedPassword = true
	return nil
}
