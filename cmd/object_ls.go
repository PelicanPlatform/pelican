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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	lsCmd = &cobra.Command{
		Use:   "ls {object}",
		Short: "List objects in a namespace from a federation",
		RunE:  listMain,
	}
)

func init() {
	flagSet := lsCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("long", "L", false, "Include extended information")
	flagSet.BoolP("collectionOnly", "C", false, "List collections only")
	flagSet.BoolP("objectonly", "O", false, "List objects only")
	flagSet.BoolP("json", "j", false, "Print results in JSON format")

	objectCmd.AddCommand(lsCmd)
}

func listMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	err := config.InitClient()
	if err != nil {
		log.Errorln(err)

		if client.IsRetryable(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		} else {
			os.Exit(1)
		}
	}

	tokenLocation, _ := cmd.Flags().GetString("token")

	if len(args) < 1 {
		log.Errorln("no location provided")
		err = cmd.Help()
		if err != nil {
			log.Errorln("failed to print out help:", err)
		}
		os.Exit(1)
	}
	object := args[len(args)-1]

	log.Debugln("Location:", object)

	long, _ := cmd.Flags().GetBool("long")
	collectionOnly, _ := cmd.Flags().GetBool("collectionOnly")
	objectOnly, _ := cmd.Flags().GetBool("objectonly")
	asJSON, _ := cmd.Flags().GetBool("json")

	if collectionOnly && objectOnly {
		// If a user specifies collectionOnly and objectOnly, this means basic functionality (list both objects and directories) so just remove the flags
		return errors.New("cannot specify both collectionOnly (-C) and object only (-O) flags, as they are mutually exclusive")
	}

	fileInfos, err := client.DoList(ctx, object, client.WithTokenLocation(tokenLocation))

	// Exit with failure
	if err != nil {
		// Print the list of errors
		errMsg := err.Error()
		var te *client.TransferErrors
		if errors.As(err, &te) {
			errMsg = te.UserError()
		}
		log.Errorln("Failure getting " + object + ": " + errMsg)
		if client.ShouldRetry(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

	filteredInfos := []client.FileInfo{}

	// Filter by object or directory
	for _, info := range fileInfos {
		if collectionOnly && !info.IsDir {
			continue
		}
		if objectOnly && info.IsDir {
			continue
		}
		filteredInfos = append(filteredInfos, info)
	}

	// Take our fileInfos and print them in a nice way
	// if the -L flag was set, we print more information
	if long {
		w := tabwriter.NewWriter(os.Stdout, 1, 2, 10, ' ', tabwriter.TabIndent|tabwriter.DiscardEmptyColumns)
		// If we want JSON format, we append the file info to a slice of fileInfo structs so that we can marshal it
		if asJSON {
			jsonData, err := json.Marshal(filteredInfos)
			if err != nil {
				return errors.Errorf("failed to marshal object/directory info to JSON format: %v", err)
			}
			fmt.Println(string(jsonData))
			return nil
		}
		for _, info := range filteredInfos {
			// If not json formats, just print out the information in a clean way
			fmt.Fprintln(w, info.Name+"\t"+strconv.FormatInt(info.Size, 10)+"\t"+info.ModTime.Format("2006-01-02 15:04:05"))
		}
		w.Flush()
	} else if asJSON {
		// In this case, we are not using the long option (-L) and want a JSON format
		jsonInfo := []string{}
		for _, info := range filteredInfos {
			jsonInfo = append(jsonInfo, info.Name)
		}
		// Convert the FileInfo to JSON and print it
		jsonData, err := json.Marshal(jsonInfo)
		if err != nil {
			return errors.Errorf("failed to marshal object/directory info to JSON format: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// We print using a tabwriter to enhance readability of the listed files and to make things look nicer
		totalColumns := 4
		// column is a counter letting us know what item/column we are on
		var column int
		w := tabwriter.NewWriter(os.Stdout, 1, 2, 10, ' ', tabwriter.TabIndent|tabwriter.DiscardEmptyColumns)
		var line string
		for _, info := range filteredInfos {
			line += info.Name
			//increase our counter
			column++

			// This section just checks if we go thru <numColumns> times, we print a newline. Otherwise, add the object to the current line with a tab after
			if column%totalColumns == 0 {
				fmt.Fprintln(w, line)
				line = ""
			} else {
				line += "\t"
			}
		}
		// If we have anything remaining in line, print it
		if line != "" {
			fmt.Fprintln(w, line)
		}
		w.Flush()
	}
	return nil
}
