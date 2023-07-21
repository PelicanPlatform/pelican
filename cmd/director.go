/*
Copyright © 2023 Justin Hiemstra <jhiemstra@morgridge.org>
*/
package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// directorCmd represents the director command
var (
	directorCmd = &cobra.Command{
		Use:   "director",
		Short: "Launch a Pelican Director",
		Long: `Launch a Pelican Director service:
		
		The Pelican Director is responsible for origin/cache discovery within
		the Pelican Platform. When a client asks the Director how to obtain a
		specific namespaced resource, the Director will respond with the info
		needed by the client (usually a cache and some authentication details)
		to obtain that information. When a cache asks the Director for the same
		namespaced resource, the Director will point the cache to the origin
		responsible for serving the object.`,
	}

	directorServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "serve the director service",
		RunE:         serveDirector,
		SilenceUsage: true,
	}
)

func init() {
	// Tie the directorServe command to the root CLI command
	directorCmd.AddCommand(directorServeCmd)

	// Set up flags for the command
	directorServeCmd.Flags().StringP("cache-port", "p", "", "Set the port to which the Director's cache redirect service should be bound")
	err := viper.BindPFlag("cachePort", directorServeCmd.Flags().Lookup("cache-port"))
	if err != nil {
		panic(err)
	}

	directorServeCmd.Flags().StringP("origin-port", "P", "", "Set the port to which the Director's origin redirect service should be bound")
	err = viper.BindPFlag("originPort", directorServeCmd.Flags().Lookup("origin-port"))
	if err != nil {
		panic(err)
	}

}
