package config_printer

import (
	"fmt"
	"reflect"
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

func formatValue(value interface{}) string {
	if value == nil {
		return "none"
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		var elements []string
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i).Interface()
			elements = append(elements, fmt.Sprintf("%v", elem))
		}
		return "[" + strings.Join(elements, ", ") + "]"

	case reflect.Map:
		// Handle map[string]struct{} as a set
		if rv.Type().Key().Kind() == reflect.String && rv.Type().Elem().Kind() == reflect.Struct {
			var keys []string
			for _, key := range rv.MapKeys() {
				keys = append(keys, key.String())
			}
			return "[" + strings.Join(keys, ", ") + "]"
		}
		// Generic map handling (if needed)
		return fmt.Sprintf("%v", value)
	case reflect.String:
		// Surround string with double quotes
		return fmt.Sprintf("\"%s\"", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}
