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
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Structs holding the OAuth2 state (and any other OSDF config needed)
type (
	TokenEntry struct {
		Expiration   int64  `yaml:"expiration"`
		AccessToken  string `yaml:"access_token"`
		RefreshToken string `yaml:"refresh_token,omitempty"`
	}

	PrefixEntry struct {
		// OSDF namespace prefix
		Prefix       string       `yaml:"prefix"`
		ClientID     string       `yaml:"client_id"`
		ClientSecret string       `yaml:"client_secret"`
		Tokens       []TokenEntry `yaml:"tokens,omitempty"`
	}

	OSDFConfig struct {

		// Top-level OSDF object
		OSDF struct {
			// List of OAuth2 client configurations
			OauthClient []PrefixEntry `yaml:"oauth_client,omitempty"`
		} `yaml:"OSDF"`
	}

	FederationDiscovery struct {
		DirectorEndpoint              string `json:"director_endpoint"`
		NamespaceRegistrationEndpoint string `json:"namespace_registration_endpoint"`
		JwksUri                       string `json:"jwks_uri"`
	}

	TokenOperation int

	TokenGenerationOpts struct {
		Operation TokenOperation
	}
)

const (
	TokenWrite TokenOperation = iota
	TokenRead
	TokenSharedWrite
	TokenSharedRead
)

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

	// Our global transports that only will get reconfigured if needed
	transport     *http.Transport
	onceTransport sync.Once
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
	federationStr := param.Federation_DiscoveryUrl.GetString()
	if len(federationStr) == 0 {
		log.Debugln("Federation URL is unset; skipping discovery")
		return nil
	}
	log.Debugln("Federation URL:", federationStr)
	curDirectorURL := param.Federation_DirectorUrl.GetString()
	curNamespaceURL := param.Federation_NamespaceUrl.GetString()
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
		Transport: GetTransport(),
		Timeout:   time.Second * 5,
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
		viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
	}
	if curNamespaceURL == "" {
		log.Debugln("Federation service discovery resulted in namespace registration URL",
			metadata.NamespaceRegistrationEndpoint)
		viper.Set("Federation.NamespaceUrl", metadata.NamespaceRegistrationEndpoint)
	}

	viper.Set("Federation.JwkUrl", metadata.JwksUri)

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

func getConfigBase() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".config", "pelican"), nil
}

func setupTransport() {
	//Getting timeouts and other information from defaults.yaml
	maxIdleConns := param.Transport_MaxIdleConns.GetInt()
	idleConnTimeout := param.Transport_IdleConnTimeout.GetDuration()
	transportTLSHandshakeTimeout := param.Transport_TLSHandshakeTimeout.GetDuration()
	expectContinueTimeout := param.Transport_ExpectContinueTimeout.GetDuration()
	responseHeaderTimeout := param.Transport_ResponseHeaderTimeout.GetDuration()

	transportDialerTimeout := param.Transport_DialerTimeout.GetDuration()
	transportKeepAlive := param.Transport_DialerKeepAlive.GetDuration()

	//Set up the transport
	transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   transportDialerTimeout,
			KeepAlive: transportKeepAlive,
		}).DialContext,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   transportTLSHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	if param.TLSSkipVerify.GetBool() {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if caCert, err := LoadCertficate(param.Server_TLSCACertificateFile.GetString()); err == nil {
		systemPool, err := x509.SystemCertPool()
		if err == nil {
			systemPool.AddCert(caCert)
			// Ensure that we don't override the InsecureSkipVerify if it's present
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{RootCAs: systemPool}
			} else {
				transport.TLSClientConfig.RootCAs = systemPool
			}
		}
	}
}

// function to get/setup the transport (only once)
func GetTransport() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return transport
}

func InitConfig() {
	viper.SetConfigType("yaml")
	// 1) Set up defaults.yaml
	err := viper.MergeConfig(strings.NewReader(defaultsYaml))
	if err != nil {
		cobra.CheckErr(err)
	}
	// 2) Set up osdf.yaml (if needed)
	prefix := GetPreferredPrefix()
	if prefix == "OSDF" {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			cobra.CheckErr(err)
		}
	}
	if configFile := viper.GetString("config"); configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Warningln("No home directory found for user -- will check for configuration yaml in /etc/pelican/")
		}

		// 3) Set up pelican.yaml (has higher precedence)
		viper.AddConfigPath(filepath.Join(home, ".config", "pelican"))
		viper.AddConfigPath(filepath.Join("/etc", "pelican"))
		viper.SetConfigType("yaml")
		viper.SetConfigName("pelican")
	}

	viper.SetEnvPrefix(prefix)
	viper.AutomaticEnv()
	// This line allows viper to use an env var like ORIGIN_VALUE to override the viper string "Origin.Value"
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	if err := viper.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			cobra.CheckErr(err)
		}
	}
	if param.Debug.GetBool() {
		SetLogging(log.DebugLevel)
	} else {
		logLevel := param.Logging_Level.GetString()
		level, err := log.ParseLevel(logLevel)
		cobra.CheckErr(err)
		SetLogging(level)
	}

	logLocation := param.Logging_LogLocation.GetString()
	if logLocation != "" {
		dir := filepath.Dir(logLocation)
		if dir != "" {
			if err := os.MkdirAll(dir, 0644); err != nil {
				log.Errorf("Failed to access/create specified directory. Error: %v", err)
				os.Exit(1)
			}
		}
		// Note: do not need to close the file, logrus does it for us
		f, err := os.OpenFile(logLocation, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Errorf("Failed to access specified log file. Error: %v", err)
			os.Exit(1)
		}
		log.SetOutput(f)
	}
}

func initConfigDir() error {
	configDir := viper.GetString("ConfigDir")
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
		viper.SetDefault("ConfigDir", configDir)
	}
	return nil
}

func InitServer() error {
	if err := initConfigDir(); err != nil {
		return errors.Wrap(err, "Failed to initialize the server configuration")
	}
	configDir := viper.GetString("ConfigDir")
	viper.SetConfigType("yaml")
	viper.SetDefault("Server.TLSCertificate", filepath.Join(configDir, "certificates", "tls.crt"))
	viper.SetDefault("Server.TLSKey", filepath.Join(configDir, "certificates", "tls.key"))
	viper.SetDefault("Server.TLSCAKey", filepath.Join(configDir, "certificates", "tlsca.key"))
	viper.SetDefault("Xrootd.RobotsTxtFile", filepath.Join(configDir, "robots.txt"))
	viper.SetDefault("Xrootd.ScitokensConfig", filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	viper.SetDefault("Xrootd.Authfile", filepath.Join(configDir, "xrootd", "authfile"))
	viper.SetDefault("Xrootd.MacaroonsKeyFile", filepath.Join(configDir, "macaroons-secret"))
	viper.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))
	viper.SetDefault("Origin.UIPasswordFile", filepath.Join(configDir, "origin-ui-passwd"))
	viper.SetDefault("Origin.UIActivationCodeFile", filepath.Join(configDir, "origin-ui-activation-code"))
	viper.SetDefault("OIDC.ClientIDFile", filepath.Join(configDir, "oidc-client-id"))
	viper.SetDefault("OIDC.ClientSecretFile", filepath.Join(configDir, "oidc-client-secret"))
	viper.SetDefault("Cache.ExportLocation", "/")
	if IsRootExecution() {
		viper.SetDefault("Xrootd.RunLocation", "/run/pelican/xrootd")
		viper.SetDefault("Cache.DataLocation", "/run/pelican/xcache")
		viper.SetDefault("Origin.Multiuser", true)
		viper.SetDefault("Director.GeoIPLocation", "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		viper.SetDefault("Registry.DbLocation", "/var/lib/pelican/registry.sqlite")
		viper.SetDefault("Monitoring.DataLocation", "/var/lib/pelican/monitoring/data")
	} else {
		viper.SetDefault("Director.GeoIPLocation", filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		viper.SetDefault("Registry.DbLocation", filepath.Join(configDir, "ns-registry.sqlite"))
		viper.SetDefault("Monitoring.DataLocation", filepath.Join(configDir, "monitoring/data"))

		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir := filepath.Join(userRuntimeDir, "pelican")
			err := os.MkdirAll(runtimeDir, 0750)
			if err != nil {
				return err
			}
			viper.SetDefault("Xrootd.RunLocation", runtimeDir)
			viper.SetDefault("Cache.DataLocation", path.Join(runtimeDir, "xcache"))
		} else {
			dir, err := os.MkdirTemp("", "pelican-xrootd-*")
			if err != nil {
				return err
			}
			viper.SetDefault("Xrootd.RunLocation", dir)
			viper.SetDefault("Cache.DataLocation", path.Join(dir, "xcache"))
			cleanupDirOnShutdown(dir)
		}
		viper.SetDefault("Origin.Multiuser", false)
	}
	// Any platform-specific paths should go here
	err := InitServerOSDefaults()
	if err != nil {
		return errors.Wrapf(err, "Failure when setting up OS-specific configuration")
	}

	err = os.MkdirAll(param.Monitoring_DataLocation.GetString(), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the monitoring data")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	viper.SetDefault("Server.Hostname", hostname)
	viper.SetDefault("Xrootd.Sitename", hostname)

	xrootdPort := param.Xrootd_Port.GetInt()
	if xrootdPort != 443 {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v:%v", param.Server_Hostname.GetString(), xrootdPort))
	} else {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v", param.Server_Hostname.GetString()))
	}

	webPort := param.Server_Port.GetInt()
	viper.SetDefault("Server.ExternalAddress", fmt.Sprint("https://", hostname, ":", webPort))
	externalAddressStr := param.Server_ExternalAddress.GetString()
	if _, err = url.Parse(externalAddressStr); err != nil {
		return errors.Wrap(err, fmt.Sprint("Invalid Server.ExternalAddress: ", externalAddressStr))
	}

	// Unmarshal Viper config into a Go struct
	err = param.UnmarshalConfig()
	if err != nil {
		return err
	}

	// As necessary, generate a private keys, JWKS and corresponding certs
	// Note: GenerateIssuerJWKS will also generate a private key in the location stored by the viper var "IssuerKey"
	_, err = GenerateIssuerJWKS()
	if err != nil {
		return err
	}

	// Check if we have required files in place to set up TLS, or we will generate them
	err = GenerateCert()
	if err != nil {
		return err
	}

	// After we know we have the certs we need, call setupTransport (which uses those certs for its TLSConfig)
	setupTransport()
	return DiscoverFederation()
}

func InitClient() error {
	if err := initConfigDir(); err != nil {
		log.Warningln("No home directory found for user -- will check for configuration yaml in /etc/pelican/")
		viper.Set("ConfigDir", "/etc/pelican")
	}

	configDir := viper.GetString("ConfigDir")
	viper.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))

	upper_prefix := GetPreferredPrefix()

	viper.SetDefault("Client.StoppedTransferTimeout", 100)
	viper.SetDefault("Client.SlowTransferRampupTime", 100)
	viper.SetDefault("Client.SlowTransferWindow", 30)

	if upper_prefix == "OSDF" || upper_prefix == "STASH" {
		viper.SetDefault("Federation.TopologyNamespaceURL", "https://topology.opensciencegrid.org/osdf/namespaces")
	}

	viper.SetEnvPrefix(upper_prefix)
	viper.AutomaticEnv()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
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
			viper.Set("Client.DisableHttpProxy", true)
			break
		}
	}
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix + "_DISABLE_PROXY_FALLBACK"); isSet {
			viper.Set("Client.DisableProxyFallback", true)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_DIRECTOR_URL"); isSet {
			viper.Set("Federation.DirectorURL", val)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_NAMESPACE_URL"); isSet {
			viper.Set("Federation.NamespaceURL", val)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix + "_TOPOLOGY_NAMESPACE_URL"); isSet {
			viper.Set("Federation.TopologyNamespaceURL", val)
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
	if viper.IsSet("MinimumDownloadSpeed") {
		viper.SetDefault("Client.MinimumDownloadSpeed", param.MinimumDownloadSpeed.GetInt())
	} else {
		viper.Set("Client.MinimumDownloadSpeed", downloadLimit)
	}

	// Handle more legacy config options
	if viper.IsSet("DisableProxyFallback") {
		viper.SetDefault("Client.DisableProxyFallback", param.DisableProxyFallback.GetBool())
	}
	if viper.IsSet("DisableHttpProxy") {
		viper.SetDefault("Client.DisableHttpProxy", param.DisableHttpProxy.GetBool())
	}

	setupTransport()

	// Unmarshal Viper config into a Go struct
	err = param.UnmarshalConfig()
	if err != nil {
		return err
	}

	return DiscoverFederation()
}

func SetLogging(logLevel log.Level) {
	textFormatter := log.TextFormatter{}
	textFormatter.DisableLevelTruncation = true
	textFormatter.FullTimestamp = true
	log.SetFormatter(&textFormatter)
	log.SetLevel(logLevel)
}
