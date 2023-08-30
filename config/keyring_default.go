//go:build !linux || (linux && !amd64)

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
