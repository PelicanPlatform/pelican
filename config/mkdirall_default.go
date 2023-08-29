//go:build !windows

package config

func fixRootDirectory(p string) string {
	return p
}

