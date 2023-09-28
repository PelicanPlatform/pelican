/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
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
	Prefix       string       `yaml:"prefix"`
	ClientID     string       `yaml:"client_id"`
	ClientSecret string       `yaml:"client_secret"`
	Tokens       []TokenEntry `yaml:"tokens,omitempty"`
}

type OSDFConfig struct {

	// Top-level OSDF object
	OSDF struct {
		// List of OAuth2 client configurations
		OauthClient []PrefixEntry `yaml:"oauth_client,omitempty"`
	} `yaml:"OSDF"`
}

type FederationDiscovery struct {
	DirectorEndpoint              string `json:"director_endpoint"`
	NamespaceRegistrationEndpoint string `json:"namespace_registration_endpoint"`
	CollectorEndpoint             string `json:"collector_endpoint"`
	JwksUri                       string `json:"jwks_uri"`
}

var (
	// Some of the unit tests probe behavior specific to OSDF vs Pelican.  Hence,
	// we need a way to override the preferred prefix.
	testingPreferredPrefix string

	//go:embed resources/defaults.yaml
	defaultsYaml string
	//go:embed resources/osdf.yaml
	osdfDefaultsYaml string

	// Potentially holds a directory to cleanup
	tempRunDir  string
	cleanupOnce sync.Once
)

// Based on the name of the current binary, determine the preferred "style"
// of behavior.  For example, a binary with the "osdf_" prefix should utilize
// the known URLs for OSDF.  For "pelican"-style commands, the user will
// need to manually configure the location of the director endpoint.
func GetPreferredPrefix() string {
	// Testing override to programmatically force different behaviors.
	if testingPreferredPrefix != "" {
		return testingPreferredPrefix
	}
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

// Override the auto-detected preferred prefix; mostly meant for unittests.
// Returns the old preferred prefix.
func SetPreferredPrefix(newPref string) string {
	oldPref := testingPreferredPrefix
	testingPreferredPrefix = newPref
	return oldPref
}

// Get the list of valid prefixes for this binary.  Given there's been so
// many renames of the project (stash -> osdf -> pelican), we allow multiple
// prefixes when searching through environment variables.
func GetAllPrefixes() []string {
	prefixes := []string{GetPreferredPrefix()}

	if prefixes[0] == "OSDF" {
		prefixes = append(prefixes, "STASH", "PELICAN")
	} else if prefixes[0] == "STASH" {
		prefixes = append(prefixes, "OSDF", "PELICAN")
	}
	return prefixes
}

func DiscoverFederation() error {
	federationStr := viper.GetString("FederationURL")
	if len(federationStr) == 0 {
		log.Debugln("Federation URL is unset; skipping discovery")
		return nil
	}
	log.Debugln("Federation URL:", federationStr)
	curDirectorURL := viper.GetString("DirectorURL")
	curNamespaceURL := viper.GetString("NamespaceURL")
	if len(curDirectorURL) != 0 && len(curNamespaceURL) != 0 {
		return nil
	}

	log.Debugln("Performing federation service discovery against endpoint", federationStr)
	federationUrl, err := url.Parse(federationStr)
	if err != nil {
		return errors.Wrapf(err, "Invalid federation value %s:", federationStr)
	}
	federationUrl.Scheme = "https"
	if len(federationUrl.Path) > 0 && len(federationUrl.Host) == 0 {
		federationUrl.Host = federationUrl.Path
		federationUrl.Path = ""
	}

	discoveryUrl, _ := url.Parse(federationUrl.String())
	discoveryUrl.Path = path.Join(".well-known/pelican-configuration", federationUrl.Path)

	httpClient := http.Client{
		Timeout: time.Second * 5,
	}
	req, err := http.NewRequest(http.MethodGet, discoveryUrl.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "Failure when doing federation metadata request creation for %s", discoveryUrl)
	}
	req.Header.Set("User-Agent", "pelican/7")

	result, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failure when doing federation metadata lookup to %s", discoveryUrl)
	}

	if result.Body != nil {
		defer result.Body.Close()
	}

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return errors.Wrapf(err, "Failure when doing federation metadata read to %s", discoveryUrl)
	}

	metadata := FederationDiscovery{}
	err = json.Unmarshal(body, &metadata)
	if err != nil {
		return errors.Wrapf(err, "Failure when parsing federation metadata at %s", discoveryUrl)
	}
	if curDirectorURL == "" {
		log.Debugln("Federation service discovery resulted in director URL", metadata.DirectorEndpoint)
		viper.Set("DirectorURL", metadata.DirectorEndpoint)
	}
	if curNamespaceURL == "" {
		log.Debugln("Federation service discovery resulted in namespace registration URL",
			metadata.NamespaceRegistrationEndpoint)
		viper.Set("NamespaceURL", metadata.NamespaceRegistrationEndpoint)
	}

	return nil
}

func cleanupDirOnShutdown(dir string) {
	sigs := make(chan os.Signal, 1)
	tempRunDir = dir
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigs
		CleanupTempResources()
	}()
}

func CleanupTempResources() {
	cleanupOnce.Do(func() {
		if tempRunDir != "" {
			os.RemoveAll(tempRunDir)
			tempRunDir = ""
		}
	})
}

func ComputeExternalAddress() string {
	config_url := viper.GetString("ExternalAddress")
	if config_url != "" {
		return config_url
	}
	return fmt.Sprintf("%v:%v", viper.GetString("Hostname"), viper.GetInt("WebPort"))
}

func getConfigBase() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".config", "pelican"), nil
}

func InitServer() error {
	configDir := viper.GetString("ConfigDir")
	viper.SetConfigType("yaml")
	if configDir == "" {
		if IsRootExecution() {
			configDir = "/etc/pelican"
		} else {
			configTmp, err := getConfigBase()
			if err != nil {
				return err
			}
			configDir = configTmp
		}
	}
	viper.SetDefault("TLSCertificate", filepath.Join(configDir, "certificates", "tls.crt"))
	viper.SetDefault("TLSKey", filepath.Join(configDir, "certificates", "tls.key"))
	viper.SetDefault("RobotsTxtFile", filepath.Join(configDir, "robots.txt"))
	viper.SetDefault("ScitokensConfig", filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	viper.SetDefault("Authfile", filepath.Join(configDir, "xrootd", "authfile"))
	viper.SetDefault("MacaroonsKeyFile", filepath.Join(configDir, "macaroons-secret"))
	viper.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))
	viper.SetDefault("OriginUI.PasswordFile", filepath.Join(configDir, "origin-ui-passwd"))
	viper.SetDefault("OIDC.ClientIDFile", filepath.Join(configDir, "oidc-client-id"))
	viper.SetDefault("OIDC.ClientSecretFile", filepath.Join(configDir, "oidc-client-secret"))
	if IsRootExecution() {
		viper.SetDefault("XrootdRun", "/run/pelican/xrootd")
		viper.SetDefault("XrootdMultiuser", true)
		viper.SetDefault("GeoIPLocation", "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		viper.SetDefault("NSRegistryLocation", "/var/lib/pelican/registry.sqlite")
		viper.SetDefault("MonitoringData", "/var/lib/pelican/monitoring/data")
	} else {
		viper.SetDefault("GeoIPLocation", filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		viper.SetDefault("NSRegistryLocation", filepath.Join(configDir, "ns-registry.sqlite"))
		viper.SetDefault("MonitoringData", filepath.Join(configDir, "monitoring/data"))

		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir := filepath.Join(userRuntimeDir, "pelican")
			err := os.MkdirAll(runtimeDir, 0750)
			if err != nil {
				return err
			}
			viper.SetDefault("XrootdRun", runtimeDir)
		} else {
			dir, err := os.MkdirTemp("", "pelican-xrootd-*")
			if err != nil {
				return err
			}
			viper.SetDefault("XrootdRun", dir)
			cleanupDirOnShutdown(dir)
		}
		viper.SetDefault("XrootdMultiuser", false)
	}
	viper.SetDefault("TLSCertFile", "/etc/pki/tls/cert.pem")

	err := os.MkdirAll(viper.GetString("MonitoringData"), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the monitoring data")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	viper.SetDefault("Hostname", hostname)
	viper.SetDefault("Sitename", hostname)
	viper.SetDefault("Hostname", hostname)

	err = viper.MergeConfig(strings.NewReader(defaultsYaml))
	if err != nil {
		return err
	}

	prefix := GetPreferredPrefix()
	if prefix == "OSDF" {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			return err
		}
	}
	return nil
}

func InitClient() error {
	if IsRootExecution() {
		viper.SetDefault("IssuerKey", "/etc/pelican/issuer.jwk")
	} else {
		configBase, err := getConfigBase()
		if err != nil {
			return err
		}
		viper.SetDefault("IssuerKey", filepath.Join(configBase, "issuer.jwk"))
	}

	upper_prefix := GetPreferredPrefix()
	lower_prefix := strings.ToLower(upper_prefix)

	viper.SetDefault("StoppedTransferTimeout", 100)
	viper.SetDefault("SlowTransferRampupTime", 100)
	viper.SetDefault("SlowTransferWindow", 30)

	if upper_prefix == "OSDF" || upper_prefix == "STASH" {
		viper.SetDefault("TopologyNamespaceURL", "https://topology.opensciencegrid.org/osdf/namespaces")
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
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_TOPOLOGY_NAMESPACE_URL"); isSet {
			viper.Set("TopologyNamespaceURL", val)
			break
		}
	}

	// Check the environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED (and all the prefix variants)
	var downloadLimit int64 = 1024 * 100
	var prefixes_with_cp []string
	for _, prefix := range prefixes {
		prefixes_with_cp = append(prefixes_with_cp, prefix+"CP")
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

	return DiscoverFederation()
}
