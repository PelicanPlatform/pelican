//go:build !linux

package xrootd

import (
	"context"

	"github.com/pkg/errors"
)

func (PrivilegedXrootdLauncher) Launch(ctx context.Context, daemonName string, configPath string) (context.Context, int, error) {
	return ctx, -1, errors.New("Privileged process launching not supported on this platform")
}

