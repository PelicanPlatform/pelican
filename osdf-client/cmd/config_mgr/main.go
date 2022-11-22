package main

import (
	"fmt"
	"os"

	config "github.com/htcondor/osdf-client/v6/config"
	log "github.com/sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

type Options struct {
	Debug bool `short:"d" long:"debug" description:"Turn on debug logging"`

	Version bool `long:"version" short:"v" description:"Print the version and exit"`

	Commands []string `positional-arg-name:"commands" description:"Command to run"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)

func main_config(commands []string) {

	if len(commands) == 0 || commands[0] == "print" {
		config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}
		config_b, err := yaml.Marshal(&config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to convert object to YAML:", err)
			os.Exit(1)
		}
		fmt.Println(string(config_b))
		return
	}

	switch verb := commands[0]; verb {
	case "replace":
		if len(commands) < 2 {
			fmt.Fprintln(os.Stderr, "Must provide a filename to replace the configuration with")
			os.Exit(1)
		}
		input_config_b, err := os.ReadFile(commands[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read config file:", err)
			os.Exit(1)
		}

		input_config := config.OSDFConfig{}
		err = yaml.Unmarshal(input_config_b, &input_config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse config file:", err)
			os.Exit(1)
		}

		err = config.SaveConfigContents(&input_config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
			os.Exit(1)
		}
	case "reset-password":
		err := config.ResetPassword()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get reset password:", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Error: Unknown command '%s'\n", verb)
		fmt.Printf("Usage: %s config [print|replace|reset-password]", os.Args[0])
		os.Exit(1)
	}
	return
}

func main_prefix(commands []string) {

	if len(commands) == 0 || commands[0] == "print" {
		config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}
		clientList := &config.OSDF.OauthClient
		config_b, err := yaml.Marshal(&clientList)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to convert object to YAML:", err)
			os.Exit(1)
		}
		fmt.Println(string(config_b))
		return
	}

	switch verb := commands[0]; verb {
	case "add":
		if len(commands) < 2 {
			fmt.Fprintln(os.Stderr, "Must provide a prefix name to add")
			os.Exit(1)
		}

		input_config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}

		hasPrefix := false
		for _, entry := range input_config.OSDF.OauthClient {
			if entry.Prefix == commands[1] {
				hasPrefix = true
				break
			}
		}
		if !hasPrefix {
			newPrefix := config.PrefixEntry{Prefix: commands[1]}
			input_config.OSDF.OauthClient = append(input_config.OSDF.OauthClient, newPrefix)
		} else {
			fmt.Fprintln(os.Stderr, "Prefix to add already exists")
			return
		}

		err = config.SaveConfigContents(&input_config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
			os.Exit(1)
		}
	case "set":
		if len(commands) < 4 {
			fmt.Fprintln(os.Stderr, "Must provide a prefix name, attribute, and value to set")
			os.Exit(1)
		}

		input_config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}

		var existingPrefix *config.PrefixEntry
		existingPrefix = nil
		for idx, _ := range input_config.OSDF.OauthClient {
			if input_config.OSDF.OauthClient[idx].Prefix == commands[1] {
				existingPrefix = &input_config.OSDF.OauthClient[idx]
				break
			}
		}
		if existingPrefix == nil {
			fmt.Fprintln(os.Stderr, "Prefix to set was not present")
			os.Exit(1)
		}

		if commands[2] == "client_id" {
			existingPrefix.ClientID = commands[3]
		} else if commands[2] == "client_secret" {
			existingPrefix.ClientSecret = commands[3]
		} else {
			fmt.Fprintln(os.Stderr, "Unknown attribute to set:", commands[2])
			os.Exit(1)
		}

		err = config.SaveConfigContents(&input_config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
			os.Exit(1)
		}
	case "delete":
		if len(commands) < 2 {
			fmt.Fprintln(os.Stderr, "Must provide a prefix to remove")
			os.Exit(1)
		}

		input_config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}

		prefix_list := input_config.OSDF.OauthClient
		new_prefix_list := make([]config.PrefixEntry, 0, len(prefix_list) - 1)
		for _, entry := range prefix_list {
			if entry.Prefix != commands[1] {
				new_prefix_list = append(new_prefix_list, entry)
			}
		}
		input_config.OSDF.OauthClient = new_prefix_list

		err = config.SaveConfigContents(&input_config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Error: Unknown command '%s'\n", verb)
		fmt.Printf("Usage: %s config [print|add|delete]", os.Args[0])
		os.Exit(1)
	}
	return
}

func main() {

	args, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			log.Errorln(err)
			os.Exit(1)
		}
	}

	//var err error
	if options.Debug {
		setLogging(log.DebugLevel)
	} else {
		setLogging(log.ErrorLevel)
	}

	if options.Version {
		fmt.Println("Version:", version)
		fmt.Println("Build Date:", date)
		fmt.Println("Build Commit:", commit)
		fmt.Println("Built By:", builtBy)
		os.Exit(0)
	}

	if len(args) == 0 {
		fmt.Printf("Usage: %s [config ...]\n", os.Args[0])
		os.Exit(0)
	}

	switch noun := args[0]; noun {
	case "config":
		main_config(args[1:])
	case "prefix":
		main_prefix(args[1:])
	default:
		fmt.Printf("Error: Unknown command '%s'\n", noun)
		os.Exit(1)
	}
	os.Exit(0)

}


func setLogging(logLevel log.Level) {
	textFormatter := log.TextFormatter{}
	textFormatter.DisableLevelTruncation = true
	textFormatter.FullTimestamp = true
	log.SetFormatter(&textFormatter)
	log.SetLevel(logLevel)
}
