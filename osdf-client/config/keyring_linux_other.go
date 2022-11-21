// +build linux,!amd64

package config

func TryGetPassword() ([]byte, error) {
	return make([]byte, 0), nil
}

func SavePassword([]byte) (error) {
	return nil
}
