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
	"path/filepath"
	"strings"
)

func main() {
	err := handleCLI(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

func handleCLI(args []string) error {
	exec_name := filepath.Base(args[0])
	// Take care of our Windows users
	exec_name = strings.TrimSuffix(exec_name, ".exe")
	// Being case-insensitive
	exec_name = strings.ToLower(exec_name)

	if exec_name == "stash_plugin" || exec_name == "osdf_plugin" || exec_name == "pelican_xfer_plugin" {
		stashPluginMain(args[1:])
	} else if exec_name == "stashcp" {
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
			fmt.Println("Version:", version)
			fmt.Println("Build Date:", date)
			fmt.Println("Build Commit:", commit)
			fmt.Println("Built By:", builtBy)
			return nil
		}
		Execute()
	}
	return nil
}
