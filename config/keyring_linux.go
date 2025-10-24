//go:build linux && amd64

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

package config

import (
	"github.com/jsipprell/keyctl"
	log "github.com/sirupsen/logrus"
)

// In the event that the session keyring is unavailable, we will fallback
// to saving the password to in-process memory.
var saved_password bool = false
var saved_password_val []byte = make([]byte, 0)

func TryGetPassword() ([]byte, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		log.Debugln("Failed to get session keyring")
		return tryGetPasswordFromMemory()
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
		log.Debugln("Failed to get session keyring")
		return savePasswordToMemory(password)
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

func tryGetPasswordFromMemory() ([]byte, error) {
	if saved_password {
		return saved_password_val, nil
	}
	return make([]byte, 0), nil
}

func savePasswordToMemory(new_pass []byte) error {
	saved_password_val = new_pass
	saved_password = true
	return nil
}
