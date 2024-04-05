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
		// 		This is becuase there's no gracefuly way to do it through Cobra
		// * Note that append "--version" to CLI as the last argument will give the
		// version info regardless of the commands and whether they are defined
		// * Remove the -v shorthand since in "origin serve" flagset it's already used for "volume" flag
		if args[len(args)-1] == "--version" {
			config.PrintPelicanVersion()
			return nil
		}
		err := Execute()
		if errors.Is(err, server_utils.ErrInvalidOriginConfig) {
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

		}
		if err != nil {
			os.Exit(1)
		}
	}
	return nil
}
