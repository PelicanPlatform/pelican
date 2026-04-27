//go:build client || server

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"os"
	"path/filepath"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
)

// cliDispatchHook allows builds to handle special exec-name-based dispatch
// (e.g., stashcp, pelican_plugin). Returns (handled, error) where handled=true
// means the hook consumed the invocation.
var cliDispatchHook func(execName string, args []string) (bool, error)

// cliExecErrorHook allows builds to provide custom error handling/messaging
// after Execute() returns an error (e.g., origin config help text).
var cliExecErrorHook func(err error)

//go:generate go run -tags client . generate-docs docs/app/commands-reference/pelican
//go:generate go run -tags server . generate-docs docs/app/commands-reference/pelican-server
func main() {
	logging.SetupLogBuffering()
	defer logging.FlushLogs(false)
	if len(os.Args) > 1 && os.Args[1] == "generate-docs" {
		outputDir := "docs/app/commands-reference"
		if len(os.Args) > 2 {
			outputDir = os.Args[2]
		}
		err := generateCLIDocs(outputDir)
		if err != nil {
			os.Exit(1)
		}
		return
	}
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

	// Let build-specific hooks handle special exec names (stashcp, plugin, etc.)
	if cliDispatchHook != nil {
		if handled, err := cliDispatchHook(execName, args); handled {
			return err
		}
	}

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
	if err != nil && cliExecErrorHook != nil {
		cliExecErrorHook(err)
	}
	if err != nil {
		os.Exit(1)
	}
	return nil
}
