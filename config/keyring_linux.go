//go:build linux && amd64

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

import (
	"github.com/jsipprell/keyctl"
	log "github.com/sirupsen/logrus"
)

var savedPassword bool = false
var savedPasswordVal []byte = make([]byte, 0)

// Returns the password stored in the session keyring, or an empty byte
// array if it cannot be found. The keyring will be provided by in-process
// memory if the kernel key retention service is unavailable.
func TryGetPassword() ([]byte, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		// Do _not_ return this error because we do not require the
		// kernel key retention service to be available. However, do
		// log the error to indicate that we tried to use it.
		log.Debugln("Failed to get kernel session keyring:", err)
		if savedPassword {
			return savedPasswordVal, nil
		}
		return make([]byte, 0), nil
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

// Saves a password to the session keyring. The keyring will be provided by
// in-process memory if the kernel key retention service is unavailable.
func SavePassword(password []byte) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		// Do _not_ return this error because we do not require the
		// kernel key retention service to be available. However, do
		// log the error to indicate that we tried to use it.
		log.Debugln("Failed to get kernel session keyring:", err)
		savedPasswordVal = password
		savedPassword = true
		return nil
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
