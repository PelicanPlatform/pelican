/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/metrics"
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
	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "xrootd has not been started")
	metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusCritical, "cmsd has not been started")
	return nil
}

func init() {
	originCmd.AddCommand(originConfigCmd)
	originCmd.AddCommand(originServeCmd)

	// The -m flag is used to specify what kind of backend we plan to use for the origin.
	originServeCmd.Flags().StringP("mode", "m", "posix", "Set the mode for the origin service (default is 'posix'). Supported modes are 'posix' and 's3'.")
	if err := viper.BindPFlag("Origin.StorageType", originServeCmd.Flags().Lookup("mode")); err != nil {
		panic(err)
	}

	// The -v flag is used for passing docker-style volume mounts to the origin.
	originServeCmd.Flags().StringSliceP("volume", "v", []string{}, "Setting the volume to /SRC:/DEST will export the contents of /SRC as /DEST in the Pelican federation")
	if err := viper.BindPFlag("Origin.ExportVolumes", originServeCmd.Flags().Lookup("volume")); err != nil {
		panic(err)
	}

	// The -w flag is used if we want the origin to be writeable.
	originServeCmd.Flags().BoolP("writeable", "", true, "Allow/disable writing to the origin")
	if err := viper.BindPFlag("Origin.EnableWrites", originServeCmd.Flags().Lookup("writeable")); err != nil {
		panic(err)
	}

	// A variety of flags we add for S3 mode. These are ultimately required for configuring the S3 xrootd plugin
	originServeCmd.Flags().String("service-name", "", "Specify the S3 service-name. Only used when an origin is launched in S3 mode.")
	_ = originServeCmd.Flags().MarkDeprecated("service-name", "It no longer has any effect and will be removed in a future version.")
	originServeCmd.Flags().String("region", "", "Specify the S3 region. Only used when an origin is launched in S3 mode.")
	originServeCmd.Flags().String("bucket", "", "Specify the S3 bucket. Only used when an origin is launched in S3 mode.")
	_ = originServeCmd.Flags().MarkDeprecated("bucket", `It no longer has any effect and will be removed in a future version. To set an S3 export use
	-v bucket:/federation/prefix
instead.
	`)
	originServeCmd.Flags().String("service-url", "", "Specify the S3 service-url. Only used when an origin is launched in S3 mode.")
	originServeCmd.Flags().String("bucket-access-keyfile", "", "Specify a filepath to use for configuring the bucket's access key.")
	originServeCmd.Flags().String("bucket-secret-keyfile", "", "Specify a filepath to use for configuring the bucket's access key.")
	originServeCmd.Flags().String("url-style", "", "Specify the S3 url-style. Only used when an origin is launched in S3 mode, and can be either 'path' (default) or 'virtual.")
	if err := viper.BindPFlag("Origin.S3Region", originServeCmd.Flags().Lookup("region")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("Origin.S3ServiceUrl", originServeCmd.Flags().Lookup("service-url")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("Origin.S3AccessKeyfile", originServeCmd.Flags().Lookup("bucket-access-keyfile")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("Origin.S3SecretKeyfile", originServeCmd.Flags().Lookup("bucket-secret-keyfile")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("Origin.S3UrlStyle", originServeCmd.Flags().Lookup("url-style")); err != nil {
		panic(err)
	}
	if viper.IsSet("Origin.S3UrlStyle") && viper.GetString("Origin.S3UrlStyle") != "path" && viper.GetString("Origin.S3UrlStyle") != "virtual" {
		panic("The --url-style flag must be either 'path' or 'virtual'")
	}

	// We don't require the bucket access and secret keyfiles as they're not needed for unauthenticated buckets.
	// However, if you give us one, you've got to give us both.
	originServeCmd.MarkFlagsRequiredTogether("bucket-access-keyfile", "bucket-secret-keyfile")

	// The hostname flag is used to specify the hostname of the upstream xrootd server being exported by THIS origin.
	// It is NOT the same as the current origin's hostname.
	originServeCmd.Flags().String("xroot-service-url", "", "When configured in xroot mode, specifies the hostname and port of the upstream xroot server "+
		"(not to be mistaken with the current server's hostname).")
	if err := viper.BindPFlag("Origin.XRootServiceUrl", originServeCmd.Flags().Lookup("xroot-service-url")); err != nil {
		panic(err)
	}

	// The port any web UI stuff will be served on
	originServeCmd.Flags().AddFlag(portFlag)

	// origin token, used for creating and verifying tokens with
	// the origin's signing jwk.
	originCmd.AddCommand(originTokenCmd)
	originTokenCmd.AddCommand(originTokenCreateCmd)
	originTokenCmd.PersistentFlags().String("profile", "wlcg", "Passing a profile ensures the token adheres to the profile's requirements. Accepted values are scitokens2 and wlcg")
	originTokenCreateCmd.Flags().Int("lifetime", 1200, "The lifetime of the token, in seconds.")
	originTokenCreateCmd.Flags().StringSlice("audience", []string{}, "The token's intended audience.")
	originTokenCreateCmd.Flags().String("subject", "", "The token's subject.")
	originTokenCreateCmd.Flags().StringSlice("scope", []string{}, "Scopes for granting fine-grained permissions to the token.")
	originTokenCreateCmd.Flags().StringSlice("claim", []string{}, "Additional token claims. A claim must be of the form <claim name>=<value>")
	originTokenCreateCmd.Flags().String("issuer", "", "The URL of the token's issuer. If not provided, the tool will attempt to find one in the configuration file.")
	if err := viper.BindPFlag("Server.IssuerUrl", originTokenCreateCmd.Flags().Lookup("issuer")); err != nil {
		panic(err)
	}
	originTokenCreateCmd.Flags().String("private-key", "", "Filepath designating the location of the private key in PEM format to be used for signing, if different from the origin's default.")
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
