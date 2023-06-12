
package main

import (
	"github.com/spf13/cobra"
)

var (
	originCmd = &cobra.Command{
		Use:   "origin",
		Short: "Operate a Pelican origin service",
        }

	originConfigCmd = &cobra.Command{
		Use: "config",
		Short: "Launch the Pelican web service in configuration mode",
	}

	originServeCmd = &cobra.Command{
		Use: "serve",
		Short: "Start the origin service",
	}
)

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)
}
