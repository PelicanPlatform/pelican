//go:build linux && amd64

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

import (
	"github.com/jsipprell/keyctl"
)

func TryGetPassword() ([]byte, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return make([]byte, 0), err
	}
	key, err := keyring.Search("osdf-oauth2-password")
	if err != nil {
		return make([]byte, 0), err
	}
	if key == nil {
		return make([]byte, 0), nil
	}
	data, err := key.Get()
	if err != nil {
		return make([]byte, 0), err
	}
	return data, nil
}

func SavePassword(password []byte) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return err
	}
	key, err := keyring.Add("osdf-oauth2-password", password)
	if err != nil {
		return err
	}
	// IGTF guidelines state that unencrypted credentials should last for
	// no longer than 1M seconds.  These credentials potentially last longer
	// so instead we keep them unencrypted in memory for approximately a day.
	err = key.ExpireAfter(100000)
	if err != nil {
		return err
	}
	return nil
}
