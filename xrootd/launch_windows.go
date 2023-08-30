//go:build windows

package xrootd

import (
	"github.com/pkg/errors"
)

type PrivilegedXrootdLauncher struct{}

func LaunchOrigin() error {
	return errors.New("'origin serve' command is not supported on Windows")
}
