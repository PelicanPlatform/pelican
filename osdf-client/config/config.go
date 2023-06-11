
package config

import (
	"path/filepath"
	"strconv"
	"strings"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Structs holding the OAuth2 state (and any other OSDF config needed)

type TokenEntry struct {
	Expiration   int64  `yaml:"expiration"`
	AccessToken  string `yaml:"access_token"`
	RefreshToken string `yaml:"refresh_token,omitempty"`
}

type PrefixEntry struct {
// OSDF namespace prefix
	Prefix       string `yaml:"prefix"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Tokens     []TokenEntry `yaml:"tokens,omitempty"`
}

type OSDFConfig struct {

	// Top-level OSDF object
	OSDF struct {
		// List of OAuth2 client configurations
		OauthClient [] PrefixEntry `yaml:"oauth_client,omitempty"`
	} `yaml:"OSDF"`
}

//
// Based on the name of the current binary, determine the preferred "style"
// of behavior.  For example, a binary with the "osdf_" prefix should utilize
// the known URLs for OSDF.  For "pelican"-style commands, the user will
// need to manually configure the location of the director endpoint.
//
func GetPreferredPrefix() string {
	arg0 := strings.ToUpper(filepath.Base(os.Args[0]))
	underscore_idx := strings.Index(arg0, "_")
	if underscore_idx != -1 {
		return arg0[0:underscore_idx]
	}
	if strings.HasPrefix(arg0, "STASH") {
		return "STASH"
	} else if strings.HasPrefix(arg0, "OSDF") {
		return "OSDF"
	}
	return "PELICAN"
}

//
// Get the list of valid prefixes for this binary.  Given there's been so
// many renames of the project (stash -> osdf -> pelican), we allow multiple
// prefixes when searching through environment variables.
//
func GetAllPrefixes() []string {
	prefixes := []string{GetPreferredPrefix()}

	if prefixes[0] == "OSDF" {
		prefixes = append(prefixes, "STASH", "PELICAN")
	} else if prefixes[0] == "STASH" {
		prefixes = append(prefixes, "OSDF", "PELICAN")
	}
	return prefixes
}

func Init() error {
	upper_prefix := GetPreferredPrefix()
	lower_prefix := strings.ToLower(upper_prefix)

	viper.SetDefault("StoppedTransferTimeout", 100)
	viper.SetDefault("SlowTransferRampupTime", 100)
	viper.SetDefault("SlowTransferWindow", 30)

	if upper_prefix == "OSDF" || upper_prefix == "STASH" {
		viper.SetDefault("NamespaceURL", "https://topology.opensciencegrid.org/stashcache/namespaces")
	}

	viper.SetEnvPrefix(upper_prefix)
	viper.AutomaticEnv()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/." + lower_prefix)
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// Do not fail if the config file is missing
	}
	env_config_file := os.Getenv(upper_prefix + "_CONFIG_FILE")
	if len(env_config_file) != 0 {
		fp, err := os.Open(env_config_file)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		err = viper.ReadConfig(fp)
		if err != nil {
			return err
		}
	}

	// Handle all the grandfathered configuration parameters
	prefixes := GetAllPrefixes()
	prefixes_with_osg := append(prefixes, "OSG")
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix + "_DISABLE_HTTP_PROXY"); isSet {
			viper.Set("DisableHttpProxy", true)
			break
		}
	}
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix + "_DISABLE_PROXY_FALLBACK"); isSet {
			viper.Set("DisableProxyFallback", true)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_DIRECTOR_URL"); isSet {
			viper.Set("DirectorURL", val)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_NAMESPACE_URL"); isSet {
			viper.Set("NamespaceURL", val)
			break
		}
	}

	// Check the environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED (and all the prefix variants)
	var downloadLimit int64 = 1024 * 100
	var prefixes_with_cp []string
	for _, prefix := range prefixes {
		prefixes_with_cp = append(prefixes_with_cp, prefix + "CP")
	}
	for _, prefix := range append(prefixes, prefixes_with_cp...) {
		downloadLimitStr := os.Getenv(prefix + "_MINIMUM_DOWNLOAD_SPEED")
		if len(downloadLimitStr) == 0 {
			continue
		}
		var err error
		downloadLimit, err = strconv.ParseInt(downloadLimitStr, 10, 64)
		if err != nil {
			log.Errorf("Environment variable %s_MINIMUM_DOWNLOAD_SPEED=%s is not parsable as integer: %s",
			    prefixes, downloadLimitStr, err.Error())
		}
		break
	}
	viper.Set("MinimumDownloadSpeed", downloadLimit)

	return nil
}
