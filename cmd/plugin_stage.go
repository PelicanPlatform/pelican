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
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/param"
)

func init() {
	// Define the file transfer plugin command
	stageCmd := &cobra.Command{
		Use:   "stage",
		Short: "Run pelican CLI to stage files as a HTCSS shadow plugin",
		Run:   stagePluginMain,
	}
	stageCmd.Flags().StringP("token", "t", "", "Token file to use for reading and/or writing")
	if err := viper.BindPFlag("Plugin.Token", stageCmd.Flags().Lookup("token")); err != nil {
		panic(err)
	}
	stageCmd.Flags().Bool("hook", false, "Implement the HTCondor hook behavior")
	if err := viper.BindPFlag("StagePlugin.Hook", stageCmd.Flags().Lookup("hook")); err != nil {
		panic(err)
	}
	stageCmd.Flags().StringP("mount", "m", "", "Prefix corresponding to the local mount point of the origin")
	if err := viper.BindPFlag("StagePlugin.MountPrefix", stageCmd.Flags().Lookup("mount")); err != nil {
		panic(err)
	}
	stageCmd.Flags().StringP("origin-prefix", "o", "", "Prefix corresponding to the local origin")
	if err := viper.BindPFlag("StagePlugin.OriginPrefix", stageCmd.Flags().Lookup("origin-prefix")); err != nil {
		panic(err)
	}
	stageCmd.Flags().StringP("shadow-prefix", "s", "", "Prefix corresponding to the shadow origin")
	if err := viper.BindPFlag("StagePlugin.ShadowOriginPrefix", stageCmd.Flags().Lookup("shadow-prefix")); err != nil {
		panic(err)
	}

	usage := stageCmd.HelpTemplate() + `This utility parses a job ClassAd and, for each "osdf://" URL found in
the input files that is in a locally-mounted origin, copies the file
over to a "shadow origin".  The files in the shadow origin are given a
unique based on their last modification time; this means that local
files can be modified without causing cache consistency issues.

Terminology:
- Origin prefix: Where in the OSDF namespace the origin exports its
  files.  Example: osdf://osg-connect/protected
- Mount prefix: The location in the locally-mounted filesystem that
  correspondings to the files in the origin prefix. Example:
  /mnt/cephfs/protected
- Shadow prefix: Where in the OSDF namespace the resulting files should
  be uploaded.  Example: osdf://osg-connect-shadow/protected
`

	stageCmd.SetHelpTemplate(usage)

	stageCmd.CompletionOptions.DisableDefaultCmd = true
	rootPluginCmd.AddCommand(stageCmd)
}

func stagePluginMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	originPrefixStr := param.StagePlugin_OriginPrefix.GetString()
	mountPrefixStr := param.StagePlugin_MountPrefix.GetString()
	shadowOriginPrefixStr := param.StagePlugin_ShadowOriginPrefix.GetString()

	originPrefixUri, err := validatePrefixes(originPrefixStr, mountPrefixStr, shadowOriginPrefixStr)
	if err != nil {
		log.Errorln("Problem validating provided prefixes:", err)
		os.Exit(1)
	}

	originPrefixPath := path.Clean("/" + originPrefixUri.Host + "/" + originPrefixUri.Path)
	log.Debugln("Local origin prefix:", originPrefixPath)

	tokenLocation := param.Plugin_Token.GetString()

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		pb.launchDisplay(ctx)
	}

	isHook := param.StagePlugin_Hook.GetBool()
	var sources, extraSources []string
	var exitCode int

	// If not a condor hook, our souces come from our args
	if !isHook {
		log.Debugln("Len of source:", len(args))
		if len(args) < 1 {
			log.Errorln("No ingest sources")
			if err = cmd.Help(); err != nil {
				log.Errorln("Failure when printing out help:", err)
			}
			os.Exit(1)
		}
		sources = args
		log.Debugln("Sources:", sources)
	} else { // Otherwise, parse the classad for our sources
		// We pass in stdin here because that is how we get the classad
		sources, extraSources, err, exitCode = processTransferInput(os.Stdin, mountPrefixStr, originPrefixPath)
		if err != nil {
			log.Errorln("Failure to get sources from job's classad:", err)
			os.Exit(exitCode)
		}
	}

	var result error
	var xformSources []string

	xformSources, result = doPluginStaging(sources, extraSources, mountPrefixStr, shadowOriginPrefixStr, tokenLocation)
	// Exit with failure
	if result != nil {
		// Print the list of errors
		log.Errorln("Failure in staging files:", result)
		if client.ShouldRetry(result) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}
	// If we are a condor hook, we need to print the classad change out. Condor will notice it and handle the rest
	if isHook {
		printOutput(xformSources, extraSources)
	}
}

// This function performs the actual "staging" on the specified shadow origin
func doPluginStaging(sources []string, extraSources []string, mountPrefixStr, shadowOriginPrefixStr, tokenLocation string) (xformSources []string, result error) {

	for _, src := range sources {
		newSource := ""
		_, newSource, result = client.DoShadowIngest(context.Background(), src, mountPrefixStr, shadowOriginPrefixStr, client.WithTokenLocation(tokenLocation), client.WithAcquireToken(false))
		if result != nil {
			// What's the correct behavior on failure?  For now, we silently put the transfer
			// back on the original list.  This is arguably the wrong approach as it might
			// give the user surprising semantics -- but keeping this until we have a bit more
			// confidence in the approach.
			extraSources = append(extraSources, src)
			log.Errorf("Failed to ingest %s: %s.  Adding original back to the transfer list",
				src, result.Error())
			continue
		}
		xformSources = append(xformSources, newSource)
	}

	return xformSources, result
}

// This function is used to print our changes out in the case we are a condor hook
func printOutput(xformSources []string, extraSources []string) {
	inputsStr := strings.Join(extraSources, ", ")
	if len(extraSources) > 0 && len(xformSources) > 0 {
		inputsStr = inputsStr + ", " + strings.Join(xformSources, ", ")
	} else if len(xformSources) > 0 {
		inputsStr = strings.Join(xformSources, ", ")
	}
	fmt.Printf("TransferInput = \"%s\"", inputsStr)
}

// This function is utilized to validate the arguments passed in to ensure they exist and are in the correct format
func validatePrefixes(originPrefixStr string, mountPrefixStr string, shadowOriginPrefixStr string) (originPrefixUri *url.URL, err error) {
	if len(originPrefixStr) == 0 {
		return nil, fmt.Errorf("Origin prefix not specified; must be a URL (osdf://...)")
	}

	originPrefixUri, err = url.Parse(originPrefixStr)
	if err != nil {
		return nil, fmt.Errorf("Origin prefix must be a URL (osdf://...): %v", err)
	}
	if originPrefixUri.Scheme != "osdf" {
		return nil, fmt.Errorf("Origin prefix scheme must be osdf://: %s", originPrefixUri.Scheme)
	}

	if len(mountPrefixStr) == 0 {
		return nil, fmt.Errorf("Mount prefix is required; must be a local path (/mnt/foo/...)")
	}
	if len(shadowOriginPrefixStr) == 0 {
		return nil, fmt.Errorf("Shadow origin prefix is required; must be a URL (osdf://....)")
	}

	return originPrefixUri, nil
}

// This function is used when we are using a condor hook and need to get our sources from the "TransferInput" classad
// We return our sources, any extra sources, an err, and the exit code (since we have a case to exit 0)
// Note: we pass in a reader for testability but the main function will always pass stdin to get the classad
func processTransferInput(reader io.Reader, mountPrefixStr string, originPrefixPath string) (sources []string, extraSources []string, err error, exitCode int) {
	buffer := make([]byte, 100*1024)
	bytesread, err := reader.Read(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read ClassAd from stdin: %v", err), 1
	}
	classad, err := classads.ParseShadowClassAd(string(buffer[:bytesread]))
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse ClassAd from stdin: %v", err), 1
	}
	inputList, err := classad.Get("TransferInput")
	if err != nil || inputList == nil {
		// No TransferInput, no need to transform therefore we exit(0)
		return nil, nil, fmt.Errorf("No transfer input found in classad, no need to transform."), 0
	}
	inputListStr, ok := inputList.(string)
	if !ok {
		return nil, nil, fmt.Errorf("TransferInput is not a string"), 1
	}
	re := regexp.MustCompile(`[,\s]+`)
	for _, source := range re.Split(inputListStr, -1) {
		log.Debugln("Examining transfer input file", source)
		if strings.HasPrefix(source, mountPrefixStr) {
			sources = append(sources, source)
		} else {
			// Replace the osdf:// prefix with the local mount path
			source_uri, err := url.Parse(source)
			source_uri_scheme := strings.SplitN(source_uri.Scheme, "+", 2)[0]
			if err == nil && source_uri_scheme == "osdf" {
				source_path := path.Clean("/" + source_uri.Host + "/" + source_uri.Path)
				if strings.HasPrefix(source_path, originPrefixPath) {
					sources = append(sources, mountPrefixStr+source_path[len(originPrefixPath):])
					continue
				}
			}
			extraSources = append(extraSources, source)
		}
	}
	log.Debugln("Sources:", sources)
	return sources, extraSources, nil, 0
}
