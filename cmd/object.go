
package main

import (
	"github.com/spf13/cobra"
)

var (
	objectCmd = &cobra.Command{
		Use:   "object",
		Short: "Interact with objects in the federation",
        }
)
