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
