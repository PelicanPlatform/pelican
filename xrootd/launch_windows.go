//go:build windows

package xrootd

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func LaunchOrigin() error {
	return errors.New("'origin serve' command is not supported on Windows")
}
