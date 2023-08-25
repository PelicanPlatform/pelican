//go:build linux

package config

import (
	"github.com/pkg/errors"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Determine whether the current process has the
// capabilities necessary for running xrootd in multiuser mode.
func HasMultiuserCaps() (result bool, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errors.New("Unable to determine the process's capabilities")
		}
	}()

	curSet := cap.GetProc()
	if curSet == nil {
		// Note: per package documentation, this should never happen; instead,
		// the `GetProc` function should have panic'd...
		return false, errors.New("Unable to determine current capabilities")
	}

	if enabled, err := curSet.GetFlag(cap.Permitted, cap.SETUID); err != nil || !enabled {
		return false, err
	}
	if enabled, err := curSet.GetFlag(cap.Permitted, cap.SETGID); err != nil || !enabled {
		return false, err
	}
	return true, nil
}
