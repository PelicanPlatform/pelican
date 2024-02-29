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
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	if len(originPrefixStr) == 0 {
		log.Errorln("Origin prefix not specified; must be a URL (osdf://...)")
		os.Exit(1)
	}
	originPrefixUri, err := url.Parse(originPrefixStr)
	if err != nil {
		log.Errorln("Origin prefix must be a URL (osdf://...):", err)
		os.Exit(1)
	}
	if originPrefixUri.Scheme != "osdf" {
		log.Errorln("Origin prefix scheme must be osdf://:", originPrefixUri.Scheme)
		os.Exit(1)
	}
	originPrefixPath := path.Clean("/" + originPrefixUri.Host + "/" + originPrefixUri.Path)
	log.Debugln("Local origin prefix:", originPrefixPath)

	mountPrefixStr := param.StagePlugin_MountPrefix.GetString()
	if len(mountPrefixStr) == 0 {
		log.Errorln("Mount prefix is required; must be a local path (/mnt/foo/...)")
		os.Exit(1)
	}

	shadowOriginPrefixStr := param.StagePlugin_ShadowOriginPrefix.GetString()
	if len(shadowOriginPrefixStr) == 0 {
		log.Errorln("Shadow origin prefix is required; must be a URL (osdf://....)")
		os.Exit(1)
	}

	tokenLocation := param.Plugin_Token.GetString()

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		pb.launchDisplay(ctx)
	}

	var sources []string
	var extraSources []string
	isHook := param.StagePlugin_Hook.GetBool()
	if isHook {
		buffer := make([]byte, 100*1024)
		bytesread, err := os.Stdin.Read(buffer)
		if err != nil {
			log.Errorln("Failed to read ClassAd from stdin:", err)
			os.Exit(1)
		}
		classad, err := classads.ParseClassAd(string(buffer[:bytesread]))
		if err != nil {
			log.Errorln("Failed to parse ClassAd from stdin: ", err)
			os.Exit(1)
		}
		inputList, err := classad.Get("TransferInput")
		if err != nil || inputList == nil {
			// No TransferInput, no need to transform...
			os.Exit(0)
		}
		inputListStr, ok := inputList.(string)
		if !ok {
			log.Errorln("TransferInput is not a string")
			os.Exit(1)
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
	} else {
		log.Debugln("Len of source:", len(args))
		if len(args) < 1 {
			log.Errorln("No ingest sources")
			if err = cmd.Help(); err != nil {
				log.Errorln("Failure when printing out help:", err)
			}
			os.Exit(1)
		}
		sources = args
	}
	log.Debugln("Sources:", sources)

	var result error
	var xformSources []string
	for _, src := range sources {
		_, newSource, result := client.DoShadowIngest(context.Background(), src, mountPrefixStr, shadowOriginPrefixStr, client.WithTokenLocation(tokenLocation), client.WithAcquireToken(false))
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
	if isHook {
		inputsStr := strings.Join(extraSources, ", ")
		if len(extraSources) > 0 && len(xformSources) > 0 {
			inputsStr = inputsStr + ", " + strings.Join(xformSources, ", ")
		} else if len(xformSources) > 0 {
			inputsStr = strings.Join(xformSources, ", ")
		}
		fmt.Printf("TransferInput = \"%s\"", inputsStr)
	}
}
