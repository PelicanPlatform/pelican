//go:build windows

package main

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func serve(/*cmd*/ *cobra.Command, /*args*/ []string) error {
	return errors.New("'origin serve' command is not supported on Windows")
}
