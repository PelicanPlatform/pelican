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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func main() {
	err := handleCLI(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

func handleCLI(args []string) error {
	execName := filepath.Base(args[0])
	// Take care of our Windows users
	execName = strings.TrimSuffix(execName, ".exe")
	// Being case-insensitive
	execName = strings.ToLower(execName)

	if strings.HasPrefix(execName, "stash_plugin") || strings.HasPrefix(execName, "osdf_plugin") || strings.HasPrefix(execName, "pelican_xfer_plugin") {
		stashPluginMain(args[1:])
	} else if strings.HasPrefix(execName, "stashcp") {
		err := copyCmd.Execute()
		if err != nil {
			return err
		}
	} else {
		// * We assume that os.Args should have minimum length of 1, so skipped empty check
		// * Version flag is captured manually to ensure it's available to all the commands and subcommands
		// 		This is because there's no gracefully way to do it through Cobra
		// * Note that append "--version" to CLI as the last argument will give the
		// version info regardless of the commands and whether they are defined
		// * Remove the -v shorthand since in "origin serve" flagset it's already used for "volume" flag
		if args[len(args)-1] == "--version" {
			config.PrintPelicanVersion(os.Stdout)
			return nil
		}
		err := Execute()
		if errors.Is(err, server_utils.ErrInvalidOriginConfig) {
			mode := param.Origin_StorageType.GetString()
			backendType, _ := server_structs.ParseOriginStorageType(mode)
			switch backendType {
			case server_structs.OriginStoragePosix:
				fmt.Fprintf(os.Stderr, `
Export information was not correct.
For POSIX, to specify exports via the command line, use:

	-v /mnt/foo:/bar -v /mnt/test:/baz

to export the directories /mnt/foo and /mnt/test under the namespace prefixes /bar and /baz, respectively.

Alternatively, specify Origin.Exports in the parameters.yaml file:

	Origin:
		Exports:
		- StoragePrefix: /mnt/foo
		  FederationPrefix: /bar
		  Capabilities: ["PublicReads", "Writes", "Listings"]
		- StoragePrefix: /mnt/test
		  FederationPrefix: /baz
		  Capabilities: ["Writes"]

to export the directories /mnt/foo and /mnt/test under the namespace prefixes /bar and /baz, respectively (with listed permissions).
`)
			case server_structs.OriginStorageS3:
				fmt.Fprintf(os.Stderr, `
Export information was not correct.
To specify exports via the command line, use:

		-v my-bucket:/my/prefix (REQUIRED --service-url https://my-s3-url.com) (REQUIRED --url-style <path or virtual>) \
				(REQUIRED --region "my-region") (OPTIONAL --bucket-access-keyfile /path/to/access.key) \
				(OPTIONAL --bucket-secret-keyfile /path/to/secret.key)


to export the S3 bucket under the namespace prefix /my/prefix.

Alternatively, specify Origin.Exports in the parameters.yaml file:

Origin:
	StorageType: s3
	S3UrlStyle: <path or virtual>
	S3ServiceUrl: https://my-s3-url.com
	S3Region: my-region
	Exports:
	  - FederationPrefix: /my/prefix
		S3Bucket: my-bucket
		S3AccessKeyfile: /path/to/access.key
		S3SecretKeyfile: /path/to/secret.key
		Capabilities: ["PublicReads", "Writes", "Listings"]

to export the S3 bucket my-bucket from https://my-s3-url.com under the namespace prefix /my/prefix (with listed permissions).
`)
			case server_structs.OriginStorageHTTPS:
				fmt.Fprintf(os.Stderr, `
Export information was not correct.
HTTPS exports must be specified via configuration file.  Example:

Origin:
	StorageType: https
	FederationPrefix: /my/prefix
	HttpServiceUrl: "https://example.com/testfiles"
	Capabilities: ["PublicReads", "Writes", "Listings"]
`)
			case server_structs.OriginStorageXRoot:
				fmt.Fprintf(os.Stderr, `
Export information was not correct.
For xroot backends, specify exports via the command line using the -v flag.  Example:

	-v /foo:/foo -v /bar:/bar (REQUIRED --xroot-service-url upstream-xroot-url.com:1095)

Note that this backend type requires that the Storage Prefix (before the colon) and Federation Prefix (after the colon) match.
It also requires that the exports are configured for public reads.

Alternatively, specify Origin.Exports in the parameters.yaml file:

	Origin:
		StorageType: xroot
		XRootServiceUrl: upstream-xroot-url.com:1095
		Exports:
		- StoragePrefix: /foo
		  FederationPrefix: /
		  Capabilities: ["PublicReads", "Writes", "Listings"]
		- StoragePrefix: /bar
		  FederationPrefix: /bar
		  Capabilities: ["PublicReads", "Writes"]
`)
			default:
				fmt.Fprintf(os.Stderr, "Currently-supported origin modes include posix, https, and s3, but you provided %s.", mode)
			}
		}
		if err != nil {
			os.Exit(1)
		}
	}
	return nil
}
