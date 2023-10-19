/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package main

import (
	"fmt"
	"os"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	originCmd = &cobra.Command{
		Use:   "origin",
		Short: "Operate a Pelican origin service",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := initOrigin()
			return err
		},
	}

	originConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "Launch the Pelican web service in configuration mode",
		Run:   configOrigin,
	}

	originServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "Start the origin service",
		RunE:         serveOrigin,
		SilenceUsage: true,
	}

	originUiCmd = &cobra.Command{
		Use:   "web-ui",
		Short: "Manage the Pelican origin web UI",
	}

	originUiResetCmd = &cobra.Command{
		Use:   "reset-password",
		Short: "Reset the admin password for the web UI",
		RunE:  uiPasswordReset,
	}

	// Expose the token manipulation CLI
	originTokenCmd = &cobra.Command{
		Use:   "token",
		Short: "Manage Pelican origin tokens",
	}

	originTokenCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a Pelican origin token",
		Long: `Create a JSON web token (JWT) using the origin's signing keys:
Usage: pelican origin token create [FLAGS] claims
E.g. pelican origin token create --profile scitokens2 aud=my-audience scope="read:/storage" scope="write:/storage"

Pelican origins use JWTs as bearer tokens for authorizing specific requests,
such as reading from or writing to the origin's underlying storage, advertising
to a director, etc. For more information about the makeup of a JWT, see
https://jwt.io/introduction.

Additional profiles that expand on JWT are supported. They include scitokens2 and
wlcg. For more information about these profiles, see https://scitokens.org/technical_docs/Claims
and https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md, respectively`,
		RunE: cliTokenCreate,
	}

	originTokenVerifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify a Pelican origin token",
		RunE:  verifyToken,
	}
)

func configOrigin( /*cmd*/ *cobra.Command /*args*/, []string) {
	fmt.Println("'origin config' command is not yet implemented")
	os.Exit(1)
}

func initOrigin() error {
	err := config.InitServer()
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("xrootd", "critical", "xrootd has not been started")
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("cmsd", "critical", "cmsd has not been started")
	cobra.CheckErr(err)

	return err
}

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)
	originServeCmd.Flags().StringP("volume", "v", "", "Setting the volue to /SRC:/DEST will export the contents of /SRC as /DEST in the Pelican federation")
	if err := viper.BindPFlag("Origin.ExportVolume", originServeCmd.Flags().Lookup("volume")); err != nil {
		panic(err)
	}
	originServeCmd.Flags().AddFlag(portFlag)

	originCmd.AddCommand(originTokenCmd)
	originTokenCmd.AddCommand(originTokenCreateCmd)
	originTokenCmd.PersistentFlags().String("profile", "wlcg", "Passing a profile ensures the token adheres to the profile's requirements. Accepted values are scitokens2 and wlcg")
	originTokenCreateCmd.Flags().Int("lifetime", 1200, "The lifetime of the token, in seconds.")
	originTokenCreateCmd.Flags().StringSlice("audience", []string{}, "The token's intended audience.")
	originTokenCreateCmd.Flags().String("subject", "", "The token's subject.")
	originTokenCreateCmd.Flags().StringSlice("scope", []string{}, "Scopes for granting fine-grained permissions to the token.")
	originTokenCreateCmd.Flags().StringSlice("claim", []string{}, "Additional token claims. A claim must be of the form <claim name>=<value>")
	originTokenCreateCmd.Flags().String("issuer", "", "The URL of the token's issuer. If not provided, the tool will attempt to find one in the configuration file.")
	if err := viper.BindPFlag("IssuerUrl", originTokenCreateCmd.Flags().Lookup("issuer")); err != nil {
		panic(err)
	}
	originTokenCreateCmd.Flags().String("private-key", viper.GetString("IssuerKey"), "Filepath designating the location of the private key in PEM format to be used for signing, if different from the origin's default.")
	if err := viper.BindPFlag("IssuerKey", originTokenCreateCmd.Flags().Lookup("private-key")); err != nil {
		panic(err)
	}
	originTokenCmd.AddCommand(originTokenVerifyCmd)

	// A pre-run hook to enforce flags specific to each profile
	originTokenCreateCmd.PreRun = func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		reqFlags := []string{}
		reqSlices := []string{}
		switch profile {
		case "wlcg":
			reqFlags = []string{"subject"}
			reqSlices = []string{"audience"}
		case "scitokens2":
			reqSlices = []string{"audience", "scope"}
		}

		shouldCancel := false
		for _, flag := range reqFlags {
			if val, _ := cmd.Flags().GetString(flag); val == "" {
				fmt.Printf("The --%s flag must be populated for the scitokens profile\n", flag)
				shouldCancel = true
			}
		}
		for _, flag := range reqSlices {
			if slice, _ := cmd.Flags().GetStringSlice(flag); len(slice) == 0 {
				fmt.Printf("The --%s flag must be populated for the scitokens profile\n", flag)
				shouldCancel = true
			}
		}

		if shouldCancel {
			os.Exit(1)
		}
	}

	originCmd.AddCommand(originUiCmd)
	originUiCmd.AddCommand(originUiResetCmd)
	originUiResetCmd.Flags().String("user", "admin", "The user whose password should be reset.")
	originUiResetCmd.Flags().Bool("stdin", false, "Read the password in from stdin.")
}
