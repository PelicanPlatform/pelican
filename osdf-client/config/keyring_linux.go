//go:build linux && amd64
// +build linux,amd64

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
