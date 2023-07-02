/*
Copyright 2023 Brian Bockelman <bbockelman@morgridge.org>

*/
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var (
	cfgFile string
	outputJSON bool

	rootCmd = &cobra.Command{
		Use:   "pelican",
		Short: "Interact with data federations",
		Long: `The pelican software allows one to build and interact
with data federations, enabling the sharing of objects and collections
across multiple dataset providers.`,
	}
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {



	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(objectCmd)
	rootCmd.AddCommand(originCmd)
	rootCmd.AddCommand(rootConfigCmd)
	preferredPrefix := config.GetPreferredPrefix()
	rootCmd.Use = strings.ToLower(preferredPrefix)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/pelican/pelican.yaml)")

	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug logs")

	rootCmd.PersistentFlags().BoolVarP(&outputJSON, "json", "", false, "output results in JSON format")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(filepath.Join(home, ".config", "pelican"))
		viper.AddConfigPath(filepath.Join("/etc", "pelican"))
		viper.SetConfigType("yaml")
		viper.SetConfigName("pelican.yaml")
	}
	viper.BindPFlag("Debug", rootCmd.Flags().Lookup("debug"))

	viper.SetEnvPrefix(config.GetPreferredPrefix())
	viper.AutomaticEnv()
	if err := viper.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			cobra.CheckErr(err)
		}
	}

	if viper.GetBool("Debug") {
		log.SetLevel(log.DebugLevel)
	}
}
