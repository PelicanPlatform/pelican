package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"net/url"
	"os"
	"path"

	config "github.com/htcondor/osdf-client/v6/config"
	stashcp "github.com/htcondor/osdf-client/v6"
	namespaces "github.com/htcondor/osdf-client/v6/namespaces"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	/*
		commit  = "none"
		date    = "unknown"
		builtBy = "unknown"
	*/
)

func printConfig() {
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
}

func addConfigSubcommands(configCmd *cobra.Command) {

	configCmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the configuration file",
		Long:  "Print the configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			printConfig()
		},
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "replace <file>",
		Short: "Replace the configuration file",
		Long:  "Replace the configuration file",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config_b, err := os.ReadFile(args[0])
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
		},
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "reset-password",
		Short: "Reset the password for the current user",
		Long:  "Reset the password for the current user",
		Run: func(cmd *cobra.Command, args []string) {
			err := config.ResetPassword()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get reset password:", err)
				os.Exit(1)
			}
		},
	})

}

func printOauthConfig() {
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

}

func addTokenSubcommands(tokenCmd *cobra.Command) {

	tokenCmd.AddCommand(&cobra.Command{
		Use:   "get <read|write> <prefix>",
		Short: "Get a new token for a given prefix",
		Long:  "Get a new token for a given prefix",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			isWrite := false
			switch args[0] {
			case "read":
			case "write":
				isWrite = true
			default:
				fmt.Fprintln(os.Stderr, "Unknown value for operation type (must be 'read' or 'write')", args[0])
				os.Exit(1)
			}
			dest := url.URL{Path: path.Clean("/" + args[1])}

			namespace, err := namespaces.MatchNamespace(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get namespace for path:", err)
				os.Exit(1)
			}

			token, err := stashcp.AcquireToken(&dest, namespace, isWrite)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get a token:", err)
				os.Exit(1)
			}

			fmt.Println(token)
		},
	})
}

func addPrefixSubcommands(prefixCmd *cobra.Command) {

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the oauth client configuration file",
		Long:  "Print the oauth client configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			printOauthConfig()
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "add <prefix>",
		Short: "Add a new oauth client",
		Long:  "Add a new oauth client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			hasPrefix := false
			for _, entry := range input_config.OSDF.OauthClient {
				if entry.Prefix == args[0] {
					hasPrefix = true
					break
				}
			}
			if !hasPrefix {
				newPrefix := config.PrefixEntry{Prefix: args[0]}
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
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "set <prefix> <client_id|client_secret> <value>",
		Short: "Set the oauth client attributes",
		Long:  "Set the oauth client attributes (client_id or client_secret)",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			var existingPrefix *config.PrefixEntry
			existingPrefix = nil
			for idx := range input_config.OSDF.OauthClient {
				if input_config.OSDF.OauthClient[idx].Prefix == args[0] {
					existingPrefix = &input_config.OSDF.OauthClient[idx]
					break
				}
			}
			if existingPrefix == nil {
				fmt.Fprintln(os.Stderr, "Prefix to set was not present")
				os.Exit(1)
			}

			if args[1] == "client_id" {
				existingPrefix.ClientID = args[2]
			} else if args[1] == "client_secret" {
				existingPrefix.ClientSecret = args[2]
			} else {
				fmt.Fprintln(os.Stderr, "Unknown attribute to set:", args[1])
				os.Exit(1)
			}

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "delete <prefix>",
		Short: "Delete the oauth client",
		Long:  "Delete the oauth client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			prefix_list := input_config.OSDF.OauthClient
			new_prefix_list := make([]config.PrefixEntry, 0, len(prefix_list)-1)
			for _, entry := range prefix_list {
				if entry.Prefix != args[0] {
					new_prefix_list = append(new_prefix_list, entry)
				}
			}
			input_config.OSDF.OauthClient = new_prefix_list

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

}

func main() {

	// Define the config commands
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage the configuration file",
		Long:  "Manage the configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			printConfig()
		},
	}
	addConfigSubcommands(configCmd)

	// Define the prefix commands
	prefixCmd := &cobra.Command{
		Use:   "prefix",
		Short: "Manage the prefix configuration",
		Long:  "Manage the prefix configuration",
	}
	addPrefixSubcommands(prefixCmd)

	// Define the token commands
	tokenCmd := &cobra.Command{
		Use: "token",
		Short: "Manage the available tokens",
		Long: "Manage the available tokens",
	}
	addTokenSubcommands(tokenCmd)

	// Add the config and prefix commands
	var rootCmd = &cobra.Command{
		Use:     "config_mgr",
		Version: version,
	}
	var Debug bool
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Debug output")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if Debug {
			setLogging(log.DebugLevel)
		} else {
			setLogging(log.ErrorLevel)
		}
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(prefixCmd)
	rootCmd.AddCommand(tokenCmd)
	err := rootCmd.Execute()
	if err != nil {
		log.Errorln(err)
	}

}

func setLogging(logLevel log.Level) {
	textFormatter := log.TextFormatter{}
	textFormatter.DisableLevelTruncation = true
	textFormatter.FullTimestamp = true
	log.SetFormatter(&textFormatter)
	log.SetLevel(logLevel)
}
