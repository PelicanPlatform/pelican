//go:build !linux

package config

// If we're not on Linux, we always lack the privilege to run multiuser
func HasMultiuserCaps() (bool, error) {
	return false, nil
}
