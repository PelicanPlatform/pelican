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

func SavePassword(password []byte) (error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return err
	}
	key, err := keyring.Add("osdf-oauth2-password", password)
	if err != nil {
		return err
	}
	key.ExpireAfter(3600)
	return nil
}

