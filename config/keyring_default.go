//go:build !linux || (linux && !amd64)

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

package config

var saved_password bool = false
var saved_password_val []byte = make([]byte, 0)

func TryGetPassword() ([]byte, error) {
	if saved_password {
		return saved_password_val, nil
	}
	return make([]byte, 0), nil
}

func SavePassword(new_pass []byte) error {
	saved_password_val = new_pass
	saved_password = true
	return nil
}
