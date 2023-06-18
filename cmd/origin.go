
package main

import (
	"fmt"
	"os"

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
		Run: config,
	}

	originServeCmd = &cobra.Command{
		Use: "serve",
		Short: "Start the origin service",
		Run: serve,
	}
)

func config(/*cmd*/ *cobra.Command, /*args*/ []string) {
	fmt.Println("'origin config' command is not yet implemented")
	os.Exit(1)
}

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)
}
