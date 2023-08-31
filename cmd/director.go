/*
Copyright © 2023 Justin Hiemstra <jhiemstra@morgridge.org>
*/
package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	directorCmd = &cobra.Command{
		Use:   "director",
		Short: "Launch a Pelican Director",
		Long: `Launch a Pelican Director service:
		
		The Pelican Director is the primary mechanism by which clients/caches
		can discover the source of a requested resource. It has two endpoints
		at /api/v1.0/director/origin/ and /api/v1.0/director/object/, where the
		former redirects to the closest origin supporting the object and the 
		latter redirects to the closest cache. As a shortcut, requests to the
		director at /foo/bar will be treated as a request for the object from
		cache.`,
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
	directorServeCmd.Flags().AddFlag(portFlag)

	directorServeCmd.Flags().StringP("default-response", "", "", "Set whether the default endpoint should redirect clients to caches or origins")
	err := viper.BindPFlag("Director.DefaultResponse", directorServeCmd.Flags().Lookup("default-response"))
	if err != nil {
		panic(err)
	}
}
