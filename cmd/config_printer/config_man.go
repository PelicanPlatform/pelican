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

package config_printer

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/pelicanplatform/pelican/docs"
	"github.com/spf13/cobra"

	"github.com/charmbracelet/glamour"
)

func configMan(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Println("Please provide a configuration parameter name.")
		return
	}
	paramName := args[0]

	matchedParam, exists := docs.ParsedParameters[strings.ToLower(paramName)]

	if !exists {
		fmt.Printf("No documentation found for parameter: %s\n", paramName)
		return
	}

	labelColor := color.New(color.FgGreen).Add(color.Bold)
	paramColor := color.New(color.FgCyan).Add(color.Bold)

	fmt.Println()
	fmt.Printf("%s %s\n", labelColor.Sprint("Parameter:"), paramColor.Sprint(matchedParam.Name))
	fmt.Printf("%s %s\n", labelColor.Sprint("Type:"), matchedParam.Type)
	fmt.Printf("%s %s\n", labelColor.Sprint("Default:"), formatValue(matchedParam.Default))
	fmt.Printf("%s %s\n", labelColor.Sprint("Tags:"), formatValue(matchedParam.Tags))
	fmt.Printf("%s\n\n", labelColor.Sprint("Description:"))
	renderedDescription, _ := glamour.Render(matchedParam.Description, "dark")
	fmt.Println(renderedDescription)
}
