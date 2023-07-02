
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	originCmd = &cobra.Command{
		Use:   "origin",
		Short: "Operate a Pelican origin service",
        }

	originConfigCmd = &cobra.Command{
		Use: "config",
		Short: "Launch the Pelican web service in configuration mode",
		Run: configOrigin,
	}

	originServeCmd = &cobra.Command{
		Use: "serve",
		Short: "Start the origin service",
		RunE: serve,
		SilenceUsage: true,
	}
)

func configOrigin(/*cmd*/ *cobra.Command, /*args*/ []string) {
	fmt.Println("'origin config' command is not yet implemented")
	os.Exit(1)
}

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)
	originServeCmd.Flags().StringP("volume", "v", "", "Setting the volue to /SRC:/DEST will export the contents of /SRC as /DEST in the Pelican federation")
	viper.BindPFlag("ExportVolume", originServeCmd.Flags().Lookup("volume"))
}
