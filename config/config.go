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

package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Structs holding the OAuth2 state (and any other OSDF config needed)
type (
	ConfigPrefix string

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

	TokenOperation int

	TokenGenerationOpts struct {
		Operation TokenOperation
	}

	ContextKey string

	// Custom goose logger
	CustomGooseLogger struct{}
)

const (
	PelicanPrefix ConfigPrefix = "PELICAN"
	OsdfPrefix    ConfigPrefix = "OSDF"
	StashPrefix   ConfigPrefix = "STASH"
)

const (
	EgrpKey ContextKey = "egrp"
)

const (
	TokenWrite TokenOperation = iota
	TokenRead
	TokenSharedWrite
	TokenSharedRead
)

// This block of variables will be overwritten at build time
var (
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
	// Pelican version
	version = "dev"
)

var (
	// Some of the unit tests probe behavior specific to OSDF vs Pelican.  Hence,
	// we need a way to override the preferred prefix.
	testingPreferredPrefix ConfigPrefix

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

	// Global discovery info.  Using the "once" allows us to delay discovery
	// until it's first needed, avoiding a web lookup for invoking configuration
	// Note the 'once' object is a pointer so we can reset the client multiple
	// times during unit tests
	fedDiscoveryOnce *sync.Once
	globalFedInfo    pelican_url.FederationDiscovery
	globalFedErr     error

	// Global struct validator
	validate *validator.Validate

	// Global translator for the validator
	uni *ut.UniversalTranslator

	onceValidate sync.Once

	// English translator
	translator *ut.Translator

	// A variable indicating enabled Pelican servers in the current process
	enabledServers server_structs.ServerType
	setServerOnce  sync.Once

	RestartFlag = make(chan any) // A channel flag to restart the server instance that launcher listens to (including cache)

	watermarkUnits = []byte{'k', 'm', 'g', 't'}
	validPrefixes  = map[ConfigPrefix]bool{
		PelicanPrefix: true,
		OsdfPrefix:    true,
		StashPrefix:   true,
		"":            true,
	}

	clientInitialized = false
)

func init() {
	en := en.New()
	uni = ut.New(en, en)

	trans, _ := uni.GetTranslator("en")
	translator = &trans

	validate = validator.New(validator.WithRequiredStructEnabled())
}

// Implement logging for info and fatal levels using logrus.
func (l CustomGooseLogger) Printf(format string, v ...interface{}) {
	log.Infof(format, v...)
}
func (l CustomGooseLogger) Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// setEnabledServer sets the global variable config.EnabledServers to include newServers.
// Since this function should only be called in config package, we mark it "private" to avoid
// reset value in other package
//
// This will only be called once in a single process
func setEnabledServer(newServers server_structs.ServerType) {
	setServerOnce.Do(func() {
		// For each process, we only want to set enabled servers once
		enabledServers.Set(newServers)
	})
}

// IsServerEnabled checks if testServer is enabled in the current process.
//
// Use this function to check which server(s) are running in the current process.
func IsServerEnabled(testServer server_structs.ServerType) bool {
	return enabledServers.IsEnabled(testServer)
}

// Returns the version of the current binary
func GetVersion() string {
	return version
}

// Overrides the version of the current binary
//
// Intended mainly for use in unit tests
func SetVersion(newVersion string) {
	version = newVersion
}

func GetBuiltCommit() string {
	return commit
}

func SetBuiltCommit(newCommit string) {
	commit = newCommit
}

func GetBuiltDate() string {
	return date
}

func SetBuiltDate(builtDate string) {
	date = builtDate
}

func GetBuiltBy() string {
	return builtBy
}

func SetBuiltBy(newBuiltBy string) {
	builtBy = newBuiltBy
}

func (cp ConfigPrefix) String() string {
	return string(cp)
}

// Get a string slice of currently enabled servers, sorted by alphabetical order.
// By default, it calls String method of each enabled server.
// To get strings in lowerCase, set lowerCase = true.
func GetEnabledServerString(lowerCase bool) []string {
	servers := make([]string, 0)
	if enabledServers.IsEnabled(server_structs.CacheType) {
		servers = append(servers, server_structs.CacheType.String())
	}
	if enabledServers.IsEnabled(server_structs.LocalCacheType) {
		servers = append(servers, server_structs.LocalCacheType.String())
	}
	if enabledServers.IsEnabled(server_structs.OriginType) {
		servers = append(servers, server_structs.OriginType.String())
	}
	if enabledServers.IsEnabled(server_structs.DirectorType) {
		servers = append(servers, server_structs.DirectorType.String())
	}
	if enabledServers.IsEnabled(server_structs.RegistryType) {
		servers = append(servers, server_structs.RegistryType.String())
	}
	sort.Strings(servers)
	if lowerCase {
		for i, serverStr := range servers {
			servers[i] = strings.ToLower(serverStr)
		}
		return servers
	} else {
		return servers
	}
}

// Based on the name of the current binary, determine the preferred "style"
// of behavior.  For example, a binary with the "osdf_" prefix should utilize
// the known URLs for OSDF.  For "pelican"-style commands, the user will
// need to manually configure the location of the director endpoint.
func GetPreferredPrefix() ConfigPrefix {
	// Testing override to programmatically force different behaviors.
	if testingPreferredPrefix != "" {
		return ConfigPrefix(testingPreferredPrefix)
	}
	arg0 := strings.ToUpper(filepath.Base(os.Args[0]))
	underscore_idx := strings.Index(arg0, "_")
	if underscore_idx != -1 {
		prefix := string(ConfigPrefix(arg0[0:underscore_idx]))
		if prefix == "STASH" {
			return OsdfPrefix
		}
	}
	if strings.HasPrefix(arg0, "STASH") || strings.HasPrefix(arg0, "OSDF") {
		return OsdfPrefix
	}
	return PelicanPrefix
}

// Override the auto-detected preferred prefix; mostly meant for unittests.
// Returns the old preferred prefix.
func SetPreferredPrefix(newPref ConfigPrefix) (oldPref ConfigPrefix, err error) {
	if _, ok := validPrefixes[newPref]; !ok {
		return "", errors.New("Invalid prefix provided")
	}
	oldPrefix := testingPreferredPrefix
	testingPreferredPrefix = newPref
	return oldPrefix, nil
}

// Get the list of valid prefixes for this binary.  Given there's been so
// many renames of the project (stash -> osdf -> pelican), we allow multiple
// prefixes when searching through environment variables.
func GetAllPrefixes() []ConfigPrefix {
	prefixes := []ConfigPrefix{GetPreferredPrefix()}

	if prefixes[0] == OsdfPrefix {
		prefixes = append(prefixes, StashPrefix, PelicanPrefix)
	} else if prefixes[0] == StashPrefix {
		prefixes = append(prefixes, OsdfPrefix, PelicanPrefix)
	}
	return prefixes
}

// We can't parse a schemeless hostname when there's a port, so check for a scheme and add one if none exists.
func wrapWithHttpsIfNeeded(urlStr string) string {
	if len(urlStr) > 0 && !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	return urlStr
}

// Global implementation of Discover Federation, outside any caching or
// delayed discovery
func discoverFederationImpl(ctx context.Context) (fedInfo pelican_url.FederationDiscovery, err error) {
	federationStr := param.Federation_DiscoveryUrl.GetString()
	externalUrlStr := param.Server_ExternalWebUrl.GetString()
	defer func() {
		// Set default guesses if these values are still unset.
		if fedInfo.DirectorEndpoint == "" && enabledServers.IsEnabled(server_structs.DirectorType) {
			fedInfo.DirectorEndpoint = externalUrlStr
		}
		if fedInfo.RegistryEndpoint == "" && enabledServers.IsEnabled(server_structs.RegistryType) {
			fedInfo.RegistryEndpoint = externalUrlStr
		}
		if fedInfo.JwksUri == "" && enabledServers.IsEnabled(server_structs.DirectorType) {
			fedInfo.JwksUri = externalUrlStr + "/.well-known/issuer.jwks"
		}
		if fedInfo.BrokerEndpoint == "" && enabledServers.IsEnabled(server_structs.BrokerType) {
			fedInfo.BrokerEndpoint = externalUrlStr
		}

		// Make sure any values in global federation metadata are url-parseable
		fedInfo.DirectorEndpoint = wrapWithHttpsIfNeeded(fedInfo.DirectorEndpoint)
		fedInfo.RegistryEndpoint = wrapWithHttpsIfNeeded(fedInfo.RegistryEndpoint)
		fedInfo.JwksUri = wrapWithHttpsIfNeeded(fedInfo.JwksUri)
		fedInfo.BrokerEndpoint = wrapWithHttpsIfNeeded(fedInfo.BrokerEndpoint)
	}()

	log.Debugln("Configured federation URL:", federationStr)
	fedInfo.DirectorEndpoint = viper.GetString("Federation.DirectorUrl")
	fedInfo.RegistryEndpoint = viper.GetString("Federation.RegistryUrl")
	fedInfo.JwksUri = viper.GetString("Federation.JwkUrl")
	fedInfo.BrokerEndpoint = viper.GetString("Federation.BrokerUrl")
	if fedInfo.DirectorEndpoint != "" && fedInfo.RegistryEndpoint != "" && fedInfo.JwksUri != "" && fedInfo.BrokerEndpoint != "" {
		return
	}

	federationStr = wrapWithHttpsIfNeeded(federationStr)
	federationUrl, err := url.Parse(federationStr)
	if err != nil {
		err = errors.Wrapf(err, "invalid federation value %s:", federationStr)
		return
	}

	if federationUrl.Path != "" && federationUrl.Host != "" {
		// If the host is nothing, then the url is fine, but if we have a host and a path then there is a problem
		err = errors.New("Invalid federation discovery url is set. No path allowed for federation discovery url. Provided url: " + federationStr)
		return
	}

	if len(federationUrl.Path) > 0 && len(federationUrl.Host) == 0 {
		federationUrl.Host = federationUrl.Path
		federationUrl.Path = ""
	}
	fedInfo.DiscoveryEndpoint = federationUrl.String()

	var metadata pelican_url.FederationDiscovery
	if federationStr == "" {
		log.Debugln("Federation URL is unset; skipping discovery")
	} else if federationStr == externalUrlStr {
		log.Debugln("Current web engine hosts the federation; skipping auto-discovery of services")
	} else {
		tr := GetTransport()
		httpClient := &http.Client{
			Transport: tr,
			Timeout:   time.Second * 5,
		}

		// We can't really know the service here, so set to generic Pelican
		ua := "pelican/" + GetVersion()
		metadata, err = pelican_url.DiscoverFederation(ctx, httpClient, ua, federationUrl)
		if err != nil {
			err = errors.Wrapf(err, "invalid federation value (%s)", federationStr)
			return
		}
	}

	// Set our globals
	if fedInfo.DirectorEndpoint == "" {
		log.Debugln("Setting global director url to", metadata.DirectorEndpoint)
		fedInfo.DirectorEndpoint = metadata.DirectorEndpoint
	}
	if fedInfo.RegistryEndpoint == "" {
		log.Debugln("Setting global registry url to", metadata.RegistryEndpoint)
		fedInfo.RegistryEndpoint = metadata.RegistryEndpoint
	}
	if fedInfo.JwksUri == "" {
		log.Debugln("Setting global jwks url to", metadata.JwksUri)
		fedInfo.JwksUri = metadata.JwksUri
	}
	if fedInfo.BrokerEndpoint == "" && metadata.BrokerEndpoint != "" {
		log.Debugln("Setting global broker url to", metadata.BrokerEndpoint)
		fedInfo.BrokerEndpoint = metadata.BrokerEndpoint
	}

	return
}

// Reset the fedDiscoveryOnce to update federation metadata values for GetFederation().
// Should only used for unit tests
func ResetFederationForTest() {
	fedDiscoveryOnce = &sync.Once{}
}

// Retrieve the federation service information from the configuration.
//
// The calculation of the federation info is delayed until needed.  As
// long as this is invoked after `InitClient` / `InitServer`, it is thread-safe.
// If invoked before things are configured, it must be done from a single-threaded
// context.
func GetFederation(ctx context.Context) (pelican_url.FederationDiscovery, error) {
	if fedDiscoveryOnce == nil {
		fedDiscoveryOnce = &sync.Once{}
	}
	fedDiscoveryOnce.Do(func() {
		globalFedInfo, globalFedErr = discoverFederationImpl(ctx)
	})
	return globalFedInfo, globalFedErr
}

// Set the current global federation metadata
func SetFederation(fd pelican_url.FederationDiscovery) {
	viper.Set("Federation.DiscoveryUrl", fd.DiscoveryEndpoint)
	viper.Set("Federation.DirectorUrl", fd.DirectorEndpoint)
	viper.Set("Federation.RegistryUrl", fd.RegistryEndpoint)
	viper.Set("Federation.BrokerUrl", fd.BrokerEndpoint)
	viper.Set("Federation.JwkUrl", fd.JwksUri)
}

// TODO: It's not clear that this function works correctly.  We should
// pass an errgroup here and ensure that the cleanup is complete before
// the main thread shuts down.
func cleanupDirOnShutdown(ctx context.Context, dir string) {
	tempRunDir = dir
	egrp, ok := ctx.Value(EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}
	egrp.Go(func() error {
		<-ctx.Done()
		err := CleanupTempResources()
		if err != nil {
			log.Infoln("Error when cleaning up temporary directories:", err)
		}
		return err
	})
}

func CleanupTempResources() (err error) {
	cleanupOnce.Do(func() {
		if tempRunDir != "" {
			err = os.RemoveAll(tempRunDir)
			tempRunDir = ""
		}
	})
	return
}

func getConfigBase() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Warningln("No home directory found for user -- will check for configuration yaml in /etc/pelican/")
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

// Return an audience string appropriate for the current server
func GetServerAudience() string {
	return viper.GetString("Origin.AudienceURL")
}

func GetServerIssuerURL() (string, error) {
	if issuerUrl := param.Server_IssuerUrl.GetString(); issuerUrl != "" {
		_, err := url.Parse(param.Server_IssuerUrl.GetString())
		if err != nil {
			return "", errors.Wrapf(err, "Failed to parse the Server.IssuerUrl %s loaded from config", param.Server_IssuerUrl.GetString())
		}
		return issuerUrl, nil
	}

	if param.Server_IssuerHostname.GetString() != "" {
		if param.Server_IssuerPort.GetInt() != 0 { // Will be the default if not set
			// We assume any issuer is running https, otherwise we're crazy
			issuerUrl := url.URL{
				Scheme: "https",
				Host:   fmt.Sprintf("%s:%d", param.Server_IssuerHostname.GetString(), param.Server_IssuerPort.GetInt()),
			}
			return issuerUrl.String(), nil
		}
		return "", errors.New("If Server.IssuerHostname is configured, you must provide a valid port")
	}

	issuerUrlStr := param.Server_ExternalWebUrl.GetString()
	issuerUrl, err := url.Parse(issuerUrlStr)
	log.Debugln("GetServerIssuerURL:", issuerUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse the issuer URL generated using the parsed Server.ExternalWebUrl")
	}
	return issuerUrl.String(), nil
}

// function to get/setup the transport (only once)
func GetTransport() *http.Transport {
	onceTransport.Do(func() {
		setupTransport()
	})
	return transport
}

// Get singleton global validte method for field validation
func GetValidate() *validator.Validate {
	return validate
}

func GetEnTranslator() ut.Translator {
	return *translator
}

// If the user provides a deprecated key in their config that can be mapped to some new key, we do that here
// along with printing out a warning to let them know they should update. Whether or not keys are mapped is
// configured in docs/parameters.yaml using the `deprecated: true` and replacedby: `<list of new keys>` fields.
func handleDeprecatedConfig() {
	deprecatedMap := param.GetDeprecated()
	for deprecated, replacement := range deprecatedMap {
		if viper.IsSet(deprecated) {
			if len(replacement) == 1 {
				if replacement[0] == "none" {
					log.Warningf("Deprecated configuration key %s is set. This is being removed in future release", deprecated)
				} else {
					log.Warningf("Deprecated configuration key %s is set. Please migrate to use %s instead", deprecated, replacement[0])
					log.Warningf("Will attempt to use the value of %s as default for %s", deprecated, replacement[0])
					value := viper.Get(deprecated)
					viper.SetDefault(replacement[0], value)
				}
			} else {
				log.Warningf("Deprecated configuration key %s is set. This is being replaced by %s instead", deprecated, replacement)
				log.Warningf("Setting default values of '%s' to the value of %s.", replacement, deprecated)

				value := viper.Get(deprecated)
				for _, rep := range replacement {
					viper.SetDefault(rep, value)
				}
			}
		}
	}
}

func checkWatermark(wmStr string) (bool, int64, error) {
	wmNum, err := strconv.Atoi(wmStr)
	if err == nil {
		if wmNum > 100 || wmNum < 0 {
			return false, 0, errors.Errorf("watermark value %s must be a integer number in range [0, 100]. Refer to parameter page for details: https://docs.pelicanplatform.org/parameters#Cache-HighWatermark", wmStr)
		}
		return true, int64(wmNum), nil
		// Not an integer number, check if it's in form of <int>k|m|g|t
	} else {
		if len(wmStr) < 1 {
			return false, 0, errors.Errorf("watermark value %s is empty.", wmStr)
		}
		unit := wmStr[len(wmStr)-1]
		if slices.Contains(watermarkUnits, unit) {
			byteNum, err := strconv.Atoi(wmStr[:len(wmStr)-1])
			// Bytes portion is not an integer
			if err != nil {
				return false, 0, errors.Errorf("watermark value %s is neither a percentage integer (e.g. 95) or a valid bytes. Refer to parameter page for details: https://docs.pelicanplatform.org/parameters#Cache-HighWatermark", wmStr)
			} else {
				switch unit {
				case 'k':
					return true, int64(byteNum) * 1024, nil
				case 'm':
					return true, int64(byteNum) * 1024 * 1024, nil
				case 'g':
					return true, int64(byteNum) * 1024 * 1024 * 1024, nil
				case 't':
					return true, int64(byteNum) * 1024 * 1024 * 1024 * 1024, nil
				default:
					return false, 0, errors.Errorf("watermark value %s is neither a percentage integer (e.g. 95) or a valid byte. Bytes representation is missing unit (k|m|g|t). Refer to parameter page for details: https://docs.pelicanplatform.org/parameters#Cache-HighWatermark", wmStr)
				}
			}
		} else {
			// Doesn't contain k|m|g|t suffix
			return false, 0, errors.Errorf("watermark value %s is neither a percentage integer (e.g. 95) or a valid byte. Bytes representation is missing unit (k|m|g|t). Refer to parameter page for details: https://docs.pelicanplatform.org/parameters#Cache-HighWatermark", wmStr)
		}
	}
}

func setupTranslation() error {
	err := en_translations.RegisterDefaultTranslations(validate, GetEnTranslator())
	if err != nil {
		return err
	}

	return validate.RegisterTranslation("required", GetEnTranslator(), func(ut ut.Translator) error {
		return ut.Add("required", "{0} is required.", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("required", fe.Field())
		return t
	})
}

// If the config file defines a "ConfigLocations" key and a list of corresponding directories, we parse all the yaml
// files in those directories according to directory-scoped lexicographical order. This allows users/admins to split
// their configuration across multiple directories/files.
//
// Config merging is handled by viper. For more information, see https://pkg.go.dev/github.com/spf13/viper#MergeConfig
func handleContinuedCfg() error {
	cfgDirs := viper.GetStringSlice("ConfigLocations")
	if len(cfgDirs) == 0 {
		return nil
	}

	for _, cfgDir := range cfgDirs {
		// Check that the directory exists
		if _, err := os.Stat(cfgDir); err != nil {
			if os.IsNotExist(err) {
				return errors.Errorf("directory %s specified by the 'ConfigLocations' key does not exist", cfgDir)
			} else {
				return errors.Wrapf(err, "failed to load extra configuration from %s", cfgDir)
			}
		}

		// Get all files from the directory, sorted in lexicographical order (sorting handled by WalkDir)
		configFiles := []string{}
		fileSystem := os.DirFS(cfgDir)
		err := fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && path != "." {
				configFiles = append(configFiles, path)
			}
			return nil
		})
		if err != nil {
			return errors.Wrapf(err, "failed to load extra configuration")
		}

		for _, file := range configFiles {
			fHandle, err := os.Open(filepath.Join(cfgDir, file))
			if err != nil {
				return errors.Wrapf(err, "failed to open extra configuration file %s", filepath.Join(cfgDir, file))
			}
			defer fHandle.Close()

			reader := io.Reader(fHandle)
			err = viper.MergeConfig(reader)
			if err != nil {
				return errors.Wrapf(err, "failed to merge extra configuration file %s", filepath.Join(cfgDir, file))
			}
		}
	}

	log.Infof("Configuration constructed according to directory-scoped lexicographical file order from the following directories: %s",
		strings.Join(cfgDirs, ", "))

	return nil
}

// Read config file from web UI changes, and call viper.Set() to explicitly override the value
// so that env wouldn't take precedence
func setWebConfigOverride(v *viper.Viper, configPath string) error {
	webConfigFile, err := os.OpenFile(configPath, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer webConfigFile.Close()

	tempV := viper.New()
	tempV.SetConfigType("yaml")
	err = tempV.ReadConfig(webConfigFile)
	if err != nil {
		return err
	}

	allKeys := tempV.AllKeys()
	for _, key := range allKeys {
		v.Set(key, tempV.Get(key))
	}

	return nil
}

func SetBaseDefaultsInConfig(v *viper.Viper) {
	//Load defaults.yaml

	err := viper.MergeConfig(strings.NewReader(defaultsYaml))
	if err != nil {
		cobra.CheckErr(err)
	}

	//Load osdf.yaml (if needed)
	prefix := GetPreferredPrefix()
	loadOSDF := prefix == OsdfPrefix
	if os.Getenv("STASH_USE_TOPOLOGY") == "" {
		loadOSDF = loadOSDF || (prefix == "STASH")
	}
	if loadOSDF {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			cobra.CheckErr(err)
		}
	}

}
func InitConfigDir(v *viper.Viper) error {

	fmt.Println("**************** IsRootExecution():", IsRootExecution(), "*******************")

	configDir := v.GetString("ConfigDir")
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
		v.SetDefault("ConfigDir", configDir)
	}
	v.SetConfigName("pelican")
	return nil
}

// InitConfig sets up the global Viper instance by loading defaults and
// user-defined config files, validates config params, and initializes logging.
func InitConfig() {

	// Enable BindStruct to allow unmarshal env into a nested struct
	viper.SetOptions(viper.ExperimentalBindStruct())
	viper.SetConfigType("yaml")

	// Set default values in the global Viper instance
	SetBaseDefaultsInConfig(viper.GetViper())

	if err := InitConfigDir(viper.GetViper()); err != nil {
		log.Errorf("Failed to initialize the config directory, Error: %v", err)
		os.Exit(1)
	}

	if configFile := viper.GetString("config"); configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath(viper.GetString("ConfigDir"))
	}

	// Load environment variables into the config
	bindNonPelicanEnv() // Deprecate OSDF env prefix but be compatible for now

	viper.SetEnvPrefix("pelican")
	viper.AutomaticEnv()

	// This line allows viper to use an env var like ORIGIN_VALUE to override the viper string "Origin.Value"
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	if err := viper.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			cobra.CheckErr(err)
		}
	}
	// Handle any extra yaml configurations specified in the ConfigLocations key
	err := handleContinuedCfg()
	if err != nil {
		cobra.CheckErr(err)
	}
	logLocation := param.Logging_LogLocation.GetString()
	if logLocation != "" {
		dir := filepath.Dir(logLocation)
		if dir != "" {
			if err := os.MkdirAll(dir, 0640); err != nil {
				log.Errorf("Failed to access/create specified directory. Error: %v", err)
				os.Exit(1)
			}
		}
		// Note: do not need to close the file, logrus does it for us
		f, err := os.OpenFile(logLocation, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Errorf("Failed to access specified log file. Error: %v", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Logging.LogLocation is set to %s. All logs are redirected to the log file.\n", logLocation)
		log.SetOutput(f)
	}

	if param.Debug.GetBool() {
		SetLogging(log.DebugLevel)
		log.Warnln("Debug is set as a flag or in config, this will override anything set for Logging.Level within your configuration")
	} else {
		logLevel := param.Logging_Level.GetString()
		level, err := log.ParseLevel(logLevel)
		cobra.CheckErr(err)
		SetLogging(level)
	}

	goose.SetLogger(CustomGooseLogger{})

	// Warn users about deprecated config keys they're using and try to map them to any new equivalent we've defined.
	handleDeprecatedConfig()

	// Spit out a warning if the user has passed config keys that are not recognized
	// This should work against both config files and appropriately-prefixed env vars
	if unknownKeys := validateConfigKeys(); len(unknownKeys) > 0 {
		log.Warningln("Unknown configuration keys found: ", strings.Join(unknownKeys, ", "))
	}

	onceValidate.Do(func() {
		err = setupTranslation()
	})
	if err != nil {
		log.Errorln("Failed to set up translation for the validator: ", err.Error())
		os.Exit(1)
	}
}

// XRootD RunLocation usage logic:
//   - Origin.RunLocation and Cache.RunLocation take precedence for their respective types
//   - If neither keys are set and Xrootd.RunLocation is, then use that and emit a warning
//   - If neither key is set, Xrootd.Runlocation is, and both modules are enabled, then we don't
//     know the next steps -- throw an error
func setXrootdRunLocations(currentServers server_structs.ServerType, dir string) error {
	cacheLocation := viper.GetString("Cache.RunLocation")
	originLocation := viper.GetString("Origin.RunLocation")
	xrootdLocation := viper.GetString("Xrootd.RunLocation")
	xrootdLocationIsSet := viper.IsSet("Xrootd.RunLocation")
	cacheLocFallbackToXrootd := false
	originLocFallbackToXrootd := false
	if currentServers.IsEnabled(server_structs.CacheType) {
		if !viper.IsSet("Cache.RunLocation") {
			if xrootdLocationIsSet {
				cacheLocFallbackToXrootd = true
				cacheLocation = xrootdLocation
			} else {
				cacheLocation = filepath.Join(dir, "cache")
			}
		}
	}
	if currentServers.IsEnabled(server_structs.OriginType) && !viper.IsSet("Origin.RunLocation") {
		if xrootdLocationIsSet {
			originLocFallbackToXrootd = true
			originLocation = xrootdLocation
		} else {
			originLocation = filepath.Join(dir, "origin")
		}
	}
	if cacheLocFallbackToXrootd && originLocFallbackToXrootd {
		return errors.New("Xrootd.RunLocation is set, but both modules are enabled.  Please set Cache.RunLocation and Origin.RunLocation or disable Xrootd.RunLocation so the default location can be used.")
	}
	if currentServers.IsEnabled(server_structs.OriginType) {
		viper.SetDefault("Origin.RunLocation", originLocation)
	}
	if currentServers.IsEnabled(server_structs.CacheType) {
		viper.SetDefault("Cache.RunLocation", cacheLocation)
	}
	return nil
}

func PrintPelicanVersion(out *os.File) {
	fmt.Fprintln(out, "Version:", GetVersion())
	fmt.Fprintln(out, "Build Date:", GetBuiltDate())
	fmt.Fprintln(out, "Build Commit:", GetBuiltCommit())
	fmt.Fprintln(out, "Built By:", GetBuiltBy())
}

func LogPelicanVersion() {
	log.Infoln("Version:", GetVersion())
	log.Infoln("Build Date:", GetBuiltDate())
	log.Infoln("Build Commit:", GetBuiltCommit())
}

// Print Pelican configuration to stderr
func PrintConfig() error {
	rawConfig, err := param.UnmarshalConfig()
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(*rawConfig, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr,
		"================ Pelican Configuration ================\n",
		string(bytes),
		"\n",
		"============= End of Pelican Configuration ============")
	return nil
}
func SetServerDefaults(v *viper.Viper) error {
	configDir := viper.GetString("ConfigDir")
	v.SetDefault("Server.WebConfigFile", filepath.Join(configDir, "web-config.yaml"))
	v.SetDefault("Server.TLSCertificate", filepath.Join(configDir, "certificates", "tls.crt"))
	v.SetDefault("Server.TLSKey", filepath.Join(configDir, "certificates", "tls.key"))
	v.SetDefault("Server.TLSCAKey", filepath.Join(configDir, "certificates", "tlsca.key"))
	v.SetDefault("Server.SessionSecretFile", filepath.Join(configDir, "session-secret"))
	v.SetDefault("Xrootd.RobotsTxtFile", filepath.Join(configDir, "robots.txt"))
	v.SetDefault("Xrootd.ScitokensConfig", filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	v.SetDefault("Xrootd.Authfile", filepath.Join(configDir, "xrootd", "authfile"))
	v.SetDefault("Xrootd.MacaroonsKeyFile", filepath.Join(configDir, "macaroons-secret"))
	v.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))
	v.SetDefault("Server.UIPasswordFile", filepath.Join(configDir, "server-web-passwd"))
	v.SetDefault("Server.UIActivationCodeFile", filepath.Join(configDir, "server-web-activation-code"))
	v.SetDefault("OIDC.ClientIDFile", filepath.Join(configDir, "oidc-client-id"))
	v.SetDefault("OIDC.ClientSecretFile", filepath.Join(configDir, "oidc-client-secret"))
	v.SetDefault("Server.WebConfigFile", filepath.Join(configDir, "web-config.yaml"))
	v.SetDefault("Cache.ExportLocation", "/")
	v.SetDefault("Registry.RequireKeyChaining", true)
	// Set up the default S3 URL style to be path-style here as opposed to in the defaults.yaml becase
	// we want to be able to check if this is user-provided (which we can't do for defaults.yaml)
	viper.SetDefault("Origin.S3UrlStyle", "path")

	if IsRootExecution() {
		v.SetDefault("Origin.RunLocation", filepath.Join("/run", "pelican", "xrootd", "origin"))
		v.SetDefault("Cache.RunLocation", filepath.Join("/run", "pelican", "xrootd", "cache"))

		// To ensure Cache.DataLocation still works, we default Cache.LocalRoot to Cache.DataLocation
		// The logic is extracted from handleDeprecatedConfig as we manually set the default value here
		v.SetDefault("Cache.DataLocation", "/run/pelican/cache")
		v.SetDefault("Cache.LocalRoot", v.GetString("Cache.DataLocation"))

		if viper.IsSet("Cache.DataLocation") {
			v.SetDefault("Cache.DataLocations", []string{filepath.Join(v.GetString("Cache.DataLocation"), "data")})
			v.SetDefault("Cache.MetaLocations", []string{filepath.Join(v.GetString("Cache.DataLocation"), "meta")})
		} else {
			viper.SetDefault("Cache.DataLocations", []string{"/run/pelican/cache/data"})
			viper.SetDefault("Cache.MetaLocations", []string{"/run/pelican/cache/meta"})
		}
		v.SetDefault("LocalCache.RunLocation", filepath.Join("/run", "pelican", "localcache"))
		v.SetDefault("Origin.Multiuser", true)
		v.SetDefault("Origin.DbLocation", "/var/lib/pelican/origin.sqlite")
		v.SetDefault("Director.GeoIPLocation", "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		v.SetDefault("Registry.DbLocation", "/var/lib/pelican/registry.sqlite")
		// The lotman db will actually take this path and create the lot at /path/.lot/lotman_cpp.sqlite
		v.SetDefault("Lotman.DbLocation", "/var/lib/pelican")
		v.SetDefault("Monitoring.DataLocation", "/var/lib/pelican/monitoring/data")
		v.SetDefault("Shoveler.QueueDirectory", "/var/spool/pelican/shoveler/queue")
		v.SetDefault("Shoveler.AMQPTokenLocation", "/etc/pelican/shoveler-token")
		v.SetDefault("Origin.GlobusConfigLocation", filepath.Join("/run", "pelican", "xrootd", "origin", "globus"))
	} else {
		v.SetDefault("Origin.DbLocation", filepath.Join(configDir, "origin.sqlite"))
		v.SetDefault("Director.GeoIPLocation", filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		v.SetDefault("Registry.DbLocation", filepath.Join(configDir, "ns-registry.sqlite"))
		// Lotdb will live at <configDir>/.lot/lotman_cpp.sqlite
		v.SetDefault("Lotman.DbLocation", configDir)
		v.SetDefault("Monitoring.DataLocation", filepath.Join(configDir, "monitoring/data"))
		v.SetDefault("Shoveler.QueueDirectory", filepath.Join(configDir, "shoveler/queue"))
		v.SetDefault("Shoveler.AMQPTokenLocation", filepath.Join(configDir, "shoveler-token"))

		defaultRuntimeDir := filepath.Join(os.TempDir(), "pelican-xrootd-*") // Construct the expected path

		v.SetDefault("Origin.GlobusConfigLocation", filepath.Join(defaultRuntimeDir, "xrootd", "origin", "globus"))
		v.SetDefault("Cache.DataLocation", filepath.Join(defaultRuntimeDir, "cache"))
		v.SetDefault("Cache.LocalRoot", v.GetString("Cache.DataLocation"))

		if v.IsSet("Cache.DataLocation") {
			v.SetDefault("Cache.DataLocations", []string{filepath.Join(v.GetString("Cache.DataLocation"), "data")})
			v.SetDefault("Cache.MetaLocations", []string{filepath.Join(v.GetString("Cache.DataLocation"), "meta")})
		} else {
			v.SetDefault("Cache.DataLocations", []string{filepath.Join(defaultRuntimeDir, "pelican/cache/data")})
			v.SetDefault("Cache.MetaLocations", []string{filepath.Join(defaultRuntimeDir, "pelican/cache/meta")})
		}
		v.SetDefault("LocalCache.RunLocation", filepath.Join(defaultRuntimeDir, "cache"))
		v.SetDefault("Origin.Multiuser", false)

	}

	fcRunLocation := v.GetString("LocalCache.RunLocation")
	v.SetDefault("LocalCache.Socket", filepath.Join(fcRunLocation, "cache.sock"))
	v.SetDefault("LocalCache.DataLocation", filepath.Join(fcRunLocation, "cache"))
	v.SetDefault("Server.TLSCACertificateFile", filepath.Join(configDir, "certificates", "tlsca.pem"))

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	v.SetDefault("Server.Hostname", hostname)

	// For the rest of the function, use the hostname provided by the admin if
	// they have overridden the defaults.
	hostname = v.GetString("Server.Hostname")
	// We default to the value of Server.Hostname, which defaults to os.Hostname but can be overwritten
	v.SetDefault("Xrootd.Sitename", hostname)
	v.SetDefault("Federation.RegistryUrl", v.GetString("Server.ExternalWebUrl"))
	v.SetDefault("Federation.BrokerURL", v.GetString("Server.ExternalWebUrl"))

	return err

}

// Initialize Pelican server instance. Pass a bit mask of `currentServers` if you want to enable multiple services.
// Note not all configurations are supported: currently, if you enable both cache and origin then an error
// is thrown
func InitServer_DOES_NOT_WORK(ctx context.Context, currentServers server_structs.ServerType) error {
	setEnabledServer(currentServers)
	SetServerDefaults(viper.GetViper())

	if webConfigPath := param.Server_WebConfigFile.GetString(); webConfigPath != "" {
		if err := os.MkdirAll(filepath.Dir(webConfigPath), 0700); err != nil {
			cobra.CheckErr(errors.Wrapf(err, "failed to create directory for web config file at %s", webConfigPath))
		}
	}
	if err := setWebConfigOverride(viper.GetViper(), param.Server_WebConfigFile.GetString()); err != nil {
		cobra.CheckErr(errors.Wrapf(err, "failed to override configuration based on changes from web UI"))
	}
	viper.SetConfigType("yaml")
	if param.Cache_DataLocation.IsSet() {
		log.Warningf("Deprecated configuration key %s is set. Please migrate to use %s instead", param.Cache_DataLocation.GetName(), param.Cache_LocalRoot.GetName())
		log.Warningf("Will attempt to use the value of %s as default for %s", param.Cache_DataLocation.GetName(), param.Cache_LocalRoot.GetName())
	}

	if !IsRootExecution() {
		var runtimeDir string
		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir = filepath.Join(userRuntimeDir, "pelican")
			err := os.MkdirAll(runtimeDir, 0750)
			if err != nil {
				return err
			}

			err = setXrootdRunLocations(currentServers, runtimeDir)
			if err != nil {
				return err
			}
		} else {
			var err error
			runtimeDir, err = os.MkdirTemp("", "pelican-xrootd-*")
			if err != nil {
				return err
			}
			err = setXrootdRunLocations(currentServers, runtimeDir)
			if err != nil {
				return err
			}
			cleanupDirOnShutdown(ctx, runtimeDir)
		}

		//Update defaults based on runtimeDir

		viper.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))
		// To ensure Cache.DataLocation still works, we default Cache.LocalRoot to Cache.DataLocation
		// The logic is extracted from handleDeprecatedConfig as we manually set the default value here
		viper.SetDefault(param.Cache_DataLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		viper.SetDefault(param.Cache_LocalRoot.GetName(), param.Cache_DataLocation.GetString())
	}

	err := os.MkdirAll(param.Monitoring_DataLocation.GetString(), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the monitoring data")
	}

	err = os.MkdirAll(param.Shoveler_QueueDirectory.GetString(), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the shoveler on-disk queue")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	cachePort := viper.GetInt("Cache.Port")
	originPort := viper.GetInt("Origin.Port")
	xrootdPort := viper.GetInt("Xrootd.Port")
	xrootdPortIsSet := viper.IsSet("Xrootd.Port")
	cacheFallbackToXrootd := false
	originFallbackToXrootd := false
	if currentServers.IsEnabled(server_structs.CacheType) {
		if !viper.IsSet("Cache.Port") {
			if xrootdPortIsSet {
				cacheFallbackToXrootd = true
				cachePort = xrootdPort
			} else {
				return errors.New("the configuration Cache.Port is not set but the Cache module is enabled.  Please set Cache.Port")
			}
		}
	}
	if currentServers.IsEnabled(server_structs.OriginType) && !viper.IsSet("Origin.Port") {
		if xrootdPortIsSet {
			originFallbackToXrootd = true
			originPort = xrootdPort
		} else {
			return errors.New("the configuration Origin.Port is not set but the Origin module is enabled.  Please set Origin.Port")
		}
	}
	if cacheFallbackToXrootd && originFallbackToXrootd {
		return errors.New("neither Cache.Port nor Origin.Port is set but both modules are enabled.  Please set both variables")
	}

	viper.Set("Origin.CalculatedPort", strconv.Itoa(originPort))
	if originPort == 0 {
		viper.Set("Origin.CalculatedPort", "any")
	}
	viper.Set("Cache.CalculatedPort", strconv.Itoa(cachePort))
	if cachePort == 0 {
		viper.Set("Cache.CalculatedPort", "any")
	}
	viper.Set("Origin.Port", originPort)
	viper.Set("Cache.Port", cachePort)

	if originPort != 443 {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v:%v", param.Server_Hostname.GetString(), originPort))
	} else {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v", param.Server_Hostname.GetString()))
	}

	if cachePort != 443 {
		viper.SetDefault("Cache.Url", fmt.Sprintf("https://%v:%v", param.Server_Hostname.GetString(), cachePort))
	} else {
		viper.SetDefault("Cache.Url", fmt.Sprintf("https://%v", param.Server_Hostname.GetString()))
	}

	if currentServers.IsEnabled(server_structs.OriginType) {
		ost := param.Origin_StorageType.GetString()
		switch ost {
		case "posix":
			viper.SetDefault(param.Origin_SelfTest.GetName(), true)
			viper.SetDefault(param.Origin_DirectorTest.GetName(), true)
		case "https":
			httpSvcUrl := param.Origin_HttpServiceUrl.GetString()
			if httpSvcUrl == "" {
				return errors.New("Origin.HTTPServiceUrl may not be empty when the origin is configured with an https backend")
			}
			_, err := url.Parse(httpSvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.HTTPServiceUrl as a URL")
			}
		case "globus":
			pvd, err := GetOIDCProdiver()
			if err != nil || pvd != Globus {
				log.Info("Server OIDC provider is not Globus. Use Origin.GlobusClientIDFile instead")
			} else {
				// OIDC provider is globus
				break
			}
			// Check if ClientID and ClientSecret are valid
			clientIDPath := param.Origin_GlobusClientIDFile.GetString()
			clientSecretPath := param.Origin_GlobusClientSecretFile.GetString()
			if clientIDPath == "" {
				return errors.New("Origin.GlobusClientIDFile may not be empty with Globus storage backend ")
			}
			_, err = os.Stat(clientIDPath)
			if err != nil {
				return errors.Wrap(err, "Origin.GlobusClientIDFile is not a valid filepath")
			}
			if clientSecretPath == "" {
				return errors.New("Origin.GlobusClientSecretFile may not be empty with Globus storage backend ")
			}
			_, err = os.Stat(clientSecretPath)
			if err != nil {
				return errors.Wrap(err, "Origin.GlobusClientSecretFile is not a valid filepath")
			}
		case "xroot":
			xrootSvcUrl := param.Origin_XRootServiceUrl.GetString()
			if xrootSvcUrl == "" {
				return errors.New("Origin.XRootServiceUrl may not be empty when the origin is configured with an xroot backend")
			}
			_, err := url.Parse(xrootSvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.XrootServiceUrl as a URL")
			}
		case "s3":
			s3SvcUrl := param.Origin_S3ServiceUrl.GetString()
			if s3SvcUrl == "" {
				return errors.New("Origin.S3ServiceUrl may not be empty when the origin is configured with an s3 backend")
			}
			_, err := url.Parse(s3SvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.S3ServiceUrl as a URL")
			}
		}

		if ost != "posix" {
			if param.Origin_SelfTest.GetBool() {
				log.Warning("Origin.SelfTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
				viper.Set(param.Origin_SelfTest.GetName(), false)
			}
			if param.Origin_DirectorTest.GetBool() {
				log.Warning("Origin.DirectorTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
				viper.Set(param.Origin_DirectorTest.GetName(), false)
			}
		}
	}

	if param.Cache_LowWatermark.IsSet() || param.Cache_HighWaterMark.IsSet() {
		lowWmStr := param.Cache_LowWatermark.GetString()
		highWmStr := param.Cache_HighWaterMark.GetString()
		ok, highWmNum, err := checkWatermark(highWmStr)
		if !ok && err != nil {
			return errors.Wrap(err, "invalid Cache.HighWaterMark value")
		}
		ok, lowWmNum, err := checkWatermark(lowWmStr)
		if !ok && err != nil {
			return errors.Wrap(err, "invalid Cache.LowWatermark value")
		}
		if lowWmNum >= highWmNum {
			return fmt.Errorf("invalid Cache.HighWaterMark and  Cache.LowWatermark values. Cache.HighWaterMark must be greater than Cache.LowWaterMark. Got %s, %s", highWmStr, lowWmStr)
		}
	}

	webPort := param.Server_WebPort.GetInt()
	if webPort < 0 {
		return errors.Errorf("the Server.WebPort setting of %d is invalid; TCP ports must be greater than 0", webPort)
	}
	if webPort != 443 {
		viper.SetDefault("Server.ExternalWebUrl", fmt.Sprintf("https://%s:%d", hostname, webPort))
	} else {
		viper.SetDefault("Server.ExternalWebUrl", fmt.Sprintf("https://%s", hostname))
	}

	externalAddressStr := param.Server_ExternalWebUrl.GetString()
	parsedExtAdd, err := url.Parse(externalAddressStr)
	if err != nil {
		return errors.Wrap(err, fmt.Sprint("invalid Server.ExternalWebUrl: ", externalAddressStr))
	} else {
		// We get rid of any 443 port if present to be consistent
		if parsedExtAdd.Port() == "443" {
			parsedExtAdd.Host = parsedExtAdd.Hostname()
			viper.Set("Server.ExternalWebUrl", parsedExtAdd.String())
		}
	}

	if currentServers.IsEnabled(server_structs.DirectorType) {
		// Default to Server.ExternalWebUrl. Provided Federation.DirectorUrl will overwrite this if any
		viper.SetDefault("Federation.DirectorUrl", param.Server_ExternalWebUrl.GetString())

		minStatRes := param.Director_MinStatResponse.GetInt()
		maxStatRes := param.Director_MaxStatResponse.GetInt()
		if minStatRes <= 0 || maxStatRes <= 0 {
			return errors.New("Invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse and MinStatResponse must be positive integers")
		}
		if maxStatRes < minStatRes {
			return errors.New("Invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse is less than MinStatResponse")
		}

		switch s := (server_structs.SortType)(param.Director_CacheSortMethod.GetString()); s {
		case server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType:
			break
		case server_structs.SortType(""):
			viper.Set("Director.CacheSortMethod", server_structs.DistanceType)
		default:
			return errors.New(fmt.Sprintf("Invalid Director.CacheSortMethod. Must be one of '%s', '%s', '%s', or '%s', but you configured '%s'.",
				server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType, s))
		}
	}

	if currentServers.IsEnabled(server_structs.RegistryType) {
		viper.SetDefault("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString())
	}

	if currentServers.IsEnabled(server_structs.BrokerType) {
		viper.SetDefault("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString())
	}

	tokenRefreshInterval := param.Monitoring_TokenRefreshInterval.GetDuration()
	tokenExpiresIn := param.Monitoring_TokenExpiresIn.GetDuration()

	if tokenExpiresIn == 0 || tokenRefreshInterval == 0 || tokenRefreshInterval > tokenExpiresIn {
		viper.Set("Monitoring.TokenRefreshInterval", time.Minute*5)
		viper.Set("Monitoring.TokenExpiresIn", time.Hour*1)
		log.Warningln("Invalid Monitoring.TokenRefreshInterval or Monitoring.TokenExpiresIn. Fallback to 5m for refresh interval and 1h for valid interval")
	}

	if currentServers.IsEnabled(server_structs.OriginType) || currentServers.IsEnabled(server_structs.CacheType) {
		if param.Xrootd_ConfigFile.IsSet() {
			_, err := os.Stat(param.Xrootd_ConfigFile.GetString())
			if err != nil {
				return fmt.Errorf("fail to open the file Xrootd.ConfigFile at %s: %v", param.Xrootd_ConfigFile.GetString(), err)
			}
		}
	}

	// Unmarshal Viper config into a Go struct
	unmarshalledConfig, err := param.UnmarshalConfig()
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Reset issuerPrivateJWK to ensure test cases can use their own temp IssuerKey
	ResetIssuerJWKPtr()

	// As necessary, generate private keys, JWKS and corresponding certs

	// Note: This function will generate a private key in the location stored by the viper var "IssuerKey"
	// iff there isn't any valid private key present in that location
	_, err = GetIssuerPublicJWKS()
	if err != nil {
		return err
	}

	// Check if we have required files in place to set up TLS, or we will generate them
	err = GenerateCert()
	if err != nil {
		return err
	}

	// Generate the session secret and save it as the default value
	if err := GenerateSessionSecret(); err != nil {
		return err
	}

	// Setup the audience to use.  We may customize the Origin.URL in the future if it has
	// a `0` for the port number; to make the audience predictable (it goes into the xrootd
	// configuration but we don't know the origin's port until after xrootd has started), we
	// stash a copy of its value now.
	viper.Set("Origin.AudienceURL", param.Origin_Url.GetString())

	// After we know we have the certs we need, call setupTransport (which uses those certs for its TLSConfig)
	setupTransport()

	// Setup CSRF middleware. To use it, you need to add this middleware to your chain
	// of http handlers by calling config.GetCSRFHandler()
	setupCSRFHandler()

	// Sets up the server log filter mechanism
	initFilterLogging()

	// Sets (or resets) the federation info.  Unlike in clients, we do this at startup
	// instead of deferring it
	fedDiscoveryOnce = &sync.Once{}
	if _, err := GetFederation(ctx); err != nil {
		return err
	}

	return nil
}

// Initialize Pelican server instance. Pass a bit mask of `currentServers` if you want to enable multiple services.
// Note not all configurations are supported: currently, if you enable both cache and origin then an error
// is thrown
func InitServer(ctx context.Context, currentServers server_structs.ServerType) error {
	setEnabledServer(currentServers)

	configDir := viper.GetString("ConfigDir")

	viper.SetDefault(param.Server_WebConfigFile.GetName(), filepath.Join(viper.GetString("ConfigDir"), "web-config.yaml"))

	if webConfigPath := param.Server_WebConfigFile.GetString(); webConfigPath != "" {
		if err := os.MkdirAll(filepath.Dir(webConfigPath), 0700); err != nil {
			cobra.CheckErr(errors.Wrapf(err, "failed to create directory for web config file at %s", webConfigPath))
		}
	}

	if err := setWebConfigOverride(viper.GetViper(), param.Server_WebConfigFile.GetString()); err != nil {
		cobra.CheckErr(errors.Wrapf(err, "failed to override configuration based on changes from web UI"))
	}

	viper.SetConfigType("yaml")
	viper.SetDefault("Server.TLSCertificate", filepath.Join(configDir, "certificates", "tls.crt"))
	viper.SetDefault("Server.TLSKey", filepath.Join(configDir, "certificates", "tls.key"))
	viper.SetDefault("Server.TLSCAKey", filepath.Join(configDir, "certificates", "tlsca.key"))
	viper.SetDefault("Server.SessionSecretFile", filepath.Join(configDir, "session-secret"))
	viper.SetDefault("Xrootd.RobotsTxtFile", filepath.Join(configDir, "robots.txt"))
	viper.SetDefault("Xrootd.ScitokensConfig", filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	viper.SetDefault("Xrootd.Authfile", filepath.Join(configDir, "xrootd", "authfile"))
	viper.SetDefault("Xrootd.MacaroonsKeyFile", filepath.Join(configDir, "macaroons-secret"))
	viper.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))
	viper.SetDefault("Server.UIPasswordFile", filepath.Join(configDir, "server-web-passwd"))
	viper.SetDefault("Server.UIActivationCodeFile", filepath.Join(configDir, "server-web-activation-code"))
	viper.SetDefault("Server.SessionSecretFile", filepath.Join(configDir, "session-secret"))
	viper.SetDefault("OIDC.ClientIDFile", filepath.Join(configDir, "oidc-client-id"))
	viper.SetDefault("OIDC.ClientSecretFile", filepath.Join(configDir, "oidc-client-secret"))
	viper.SetDefault("Server.WebConfigFile", filepath.Join(configDir, "web-config.yaml"))
	viper.SetDefault("Cache.ExportLocation", "/")
	viper.SetDefault("Registry.RequireKeyChaining", true)

	// Set up the default S3 URL style to be path-style here as opposed to in the defaults.yaml becase
	// we want to be able to check if this is user-provided (which we can't do for defaults.yaml)
	viper.SetDefault("Origin.S3UrlStyle", "path")

	if param.Cache_DataLocation.IsSet() {
		log.Warningf("Deprecated configuration key %s is set. Please migrate to use %s instead", param.Cache_DataLocation.GetName(), param.Cache_LocalRoot.GetName())
		log.Warningf("Will attempt to use the value of %s as default for %s", param.Cache_DataLocation.GetName(), param.Cache_LocalRoot.GetName())
	}

	if IsRootExecution() {
		if currentServers.IsEnabled(server_structs.OriginType) {
			viper.SetDefault("Origin.RunLocation", filepath.Join("/run", "pelican", "xrootd", "origin"))
		}
		if currentServers.IsEnabled(server_structs.CacheType) {
			viper.SetDefault("Cache.RunLocation", filepath.Join("/run", "pelican", "xrootd", "cache"))
		}

		// To ensure Cache.DataLocation still works, we default Cache.LocalRoot to Cache.DataLocation
		// The logic is extracted from handleDeprecatedConfig as we manually set the default value here
		viper.SetDefault(param.Cache_DataLocation.GetName(), "/run/pelican/cache")
		viper.SetDefault(param.Cache_LocalRoot.GetName(), param.Cache_DataLocation.GetString())

		if viper.IsSet("Cache.DataLocation") {
			viper.SetDefault("Cache.DataLocations", []string{filepath.Join(param.Cache_DataLocation.GetString(), "data")})
			viper.SetDefault("Cache.MetaLocations", []string{filepath.Join(param.Cache_DataLocation.GetString(), "meta")})
		} else {
			viper.SetDefault("Cache.DataLocations", []string{"/run/pelican/cache/data"})
			viper.SetDefault("Cache.MetaLocations", []string{"/run/pelican/cache/meta"})
		}

		viper.SetDefault("LocalCache.RunLocation", filepath.Join("/run", "pelican", "localcache"))

		viper.SetDefault("Origin.Multiuser", true)
		viper.SetDefault(param.Origin_DbLocation.GetName(), "/var/lib/pelican/origin.sqlite")
		viper.SetDefault(param.Director_DbLocation.GetName(), "/var/lib/pelican/director.sqlite")
		viper.SetDefault("Director.GeoIPLocation", "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		viper.SetDefault("Registry.DbLocation", "/var/lib/pelican/registry.sqlite")
		// The lotman db will actually take this path and create the lot at /path/.lot/lotman_cpp.sqlite
		viper.SetDefault("Lotman.DbLocation", "/var/lib/pelican")
		viper.SetDefault("Monitoring.DataLocation", "/var/lib/pelican/monitoring/data")
		viper.SetDefault("Shoveler.QueueDirectory", "/var/spool/pelican/shoveler/queue")
		viper.SetDefault("Shoveler.AMQPTokenLocation", "/etc/pelican/shoveler-token")
		viper.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join("/run", "pelican", "xrootd", "origin", "globus"))
	} else {
		viper.SetDefault(param.Origin_DbLocation.GetName(), filepath.Join(configDir, "origin.sqlite"))
		viper.SetDefault(param.Director_DbLocation.GetName(), filepath.Join(configDir, "director.sqlite"))
		viper.SetDefault("Director.GeoIPLocation", filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		viper.SetDefault("Registry.DbLocation", filepath.Join(configDir, "ns-registry.sqlite"))
		// Lotdb will live at <configDir>/.lot/lotman_cpp.sqlite
		viper.SetDefault("Lotman.DbLocation", configDir)
		viper.SetDefault("Monitoring.DataLocation", filepath.Join(configDir, "monitoring/data"))
		viper.SetDefault("Shoveler.QueueDirectory", filepath.Join(configDir, "shoveler/queue"))
		viper.SetDefault("Shoveler.AMQPTokenLocation", filepath.Join(configDir, "shoveler-token"))

		var runtimeDir string
		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir = filepath.Join(userRuntimeDir, "pelican")
			err := os.MkdirAll(runtimeDir, 0750)
			if err != nil {
				return err
			}

			err = setXrootdRunLocations(currentServers, runtimeDir)
			if err != nil {
				return err
			}
		} else {
			var err error
			runtimeDir, err = os.MkdirTemp("", "pelican-xrootd-*")
			if err != nil {
				return err
			}
			err = setXrootdRunLocations(currentServers, runtimeDir)
			if err != nil {
				return err
			}
			cleanupDirOnShutdown(ctx, runtimeDir)
		}
		viper.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))
		// To ensure Cache.DataLocation still works, we default Cache.LocalRoot to Cache.DataLocation
		// The logic is extracted from handleDeprecatedConfig as we manually set the default value here
		viper.SetDefault(param.Cache_DataLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		viper.SetDefault(param.Cache_LocalRoot.GetName(), param.Cache_DataLocation.GetString())

		if viper.IsSet("Cache.DataLocation") {
			viper.SetDefault("Cache.DataLocations", []string{filepath.Join(param.Cache_DataLocation.GetString(), "data")})
			viper.SetDefault("Cache.MetaLocations", []string{filepath.Join(param.Cache_DataLocation.GetString(), "meta")})
		} else {
			viper.SetDefault("Cache.DataLocations", []string{filepath.Join(runtimeDir, "pelican/cache/data")})
			viper.SetDefault("Cache.MetaLocations", []string{filepath.Join(runtimeDir, "pelican/cache/meta")})
		}
		viper.SetDefault("LocalCache.RunLocation", filepath.Join(runtimeDir, "cache"))
		viper.SetDefault("Origin.Multiuser", false)
	}
	fcRunLocation := viper.GetString("LocalCache.RunLocation")
	viper.SetDefault("LocalCache.Socket", filepath.Join(fcRunLocation, "cache.sock"))
	viper.SetDefault("LocalCache.DataLocation", filepath.Join(fcRunLocation, "cache"))

	// Any platform-specific paths should go here
	err := InitServerOSDefaults()
	if err != nil {
		return errors.Wrapf(err, "Failure when setting up OS-specific configuration")
	}

	err = os.MkdirAll(param.Monitoring_DataLocation.GetString(), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the monitoring data")
	}

	err = os.MkdirAll(param.Shoveler_QueueDirectory.GetString(), 0750)
	if err != nil {
		return errors.Wrapf(err, "Failure when creating a directory for the shoveler on-disk queue")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	viper.SetDefault(param.Server_Hostname.GetName(), hostname)
	// For the rest of the function, use the hostname provided by the admin if
	// they have overridden the defaults.
	hostname = param.Server_Hostname.GetString()
	// We default to the value of Server.Hostname, which defaults to os.Hostname but can be overwritten
	viper.SetDefault(param.Xrootd_Sitename.GetName(), hostname)

	// XRootD port usage logic:
	// - Origin.Port and Cache.Port take precedence for their respective types
	// - If neither keys are set and Xrootd.Port is, then use that and emit a warning
	// - If neither key is set, Xrootd.Port is, and both modules are enabled, then we don't
	//   know the next steps -- throw an error
	cachePort := viper.GetInt("Cache.Port")
	originPort := viper.GetInt("Origin.Port")
	xrootdPort := viper.GetInt("Xrootd.Port")
	xrootdPortIsSet := viper.IsSet("Xrootd.Port")
	cacheFallbackToXrootd := false
	originFallbackToXrootd := false
	if currentServers.IsEnabled(server_structs.CacheType) {
		if !viper.IsSet("Cache.Port") {
			if xrootdPortIsSet {
				cacheFallbackToXrootd = true
				cachePort = xrootdPort
			} else {
				return errors.New("the configuration Cache.Port is not set but the Cache module is enabled.  Please set Cache.Port")
			}
		}
	}
	if currentServers.IsEnabled(server_structs.OriginType) && !viper.IsSet("Origin.Port") {
		if xrootdPortIsSet {
			originFallbackToXrootd = true
			originPort = xrootdPort
		} else {
			return errors.New("the configuration Origin.Port is not set but the Origin module is enabled.  Please set Origin.Port")
		}
	}
	if cacheFallbackToXrootd && originFallbackToXrootd {
		return errors.New("neither Cache.Port nor Origin.Port is set but both modules are enabled.  Please set both variables")
	}

	viper.Set("Origin.CalculatedPort", strconv.Itoa(originPort))
	if originPort == 0 {
		viper.Set("Origin.CalculatedPort", "any")
	}
	viper.Set("Cache.CalculatedPort", strconv.Itoa(cachePort))
	if cachePort == 0 {
		viper.Set("Cache.CalculatedPort", "any")
	}
	viper.Set("Origin.Port", originPort)
	viper.Set("Cache.Port", cachePort)

	if originPort != 443 {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v:%v", param.Server_Hostname.GetString(), originPort))
	} else {
		viper.SetDefault("Origin.Url", fmt.Sprintf("https://%v", param.Server_Hostname.GetString()))
	}

	if cachePort != 443 {
		viper.SetDefault("Cache.Url", fmt.Sprintf("https://%v:%v", param.Server_Hostname.GetString(), cachePort))
	} else {
		viper.SetDefault("Cache.Url", fmt.Sprintf("https://%v", param.Server_Hostname.GetString()))
	}

	if currentServers.IsEnabled(server_structs.OriginType) {
		ost := param.Origin_StorageType.GetString()
		switch ost {
		case "posix":
			viper.SetDefault(param.Origin_SelfTest.GetName(), true)
			viper.SetDefault(param.Origin_DirectorTest.GetName(), true)
		case "https":
			httpSvcUrl := param.Origin_HttpServiceUrl.GetString()
			if httpSvcUrl == "" {
				return errors.New("Origin.HTTPServiceUrl may not be empty when the origin is configured with an https backend")
			}
			_, err := url.Parse(httpSvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.HTTPServiceUrl as a URL")
			}
		case "globus":
			pvd, err := GetOIDCProdiver()
			if err != nil || pvd != Globus {
				log.Info("Server OIDC provider is not Globus. Use Origin.GlobusClientIDFile instead")
			} else {
				// OIDC provider is globus
				break
			}
			// Check if ClientID and ClientSecret are valid
			clientIDPath := param.Origin_GlobusClientIDFile.GetString()
			clientSecretPath := param.Origin_GlobusClientSecretFile.GetString()
			if clientIDPath == "" {
				return errors.New("Origin.GlobusClientIDFile may not be empty with Globus storage backend ")
			}
			_, err = os.Stat(clientIDPath)
			if err != nil {
				return errors.Wrap(err, "Origin.GlobusClientIDFile is not a valid filepath")
			}
			if clientSecretPath == "" {
				return errors.New("Origin.GlobusClientSecretFile may not be empty with Globus storage backend ")
			}
			_, err = os.Stat(clientSecretPath)
			if err != nil {
				return errors.Wrap(err, "Origin.GlobusClientSecretFile is not a valid filepath")
			}
		case "xroot":
			xrootSvcUrl := param.Origin_XRootServiceUrl.GetString()
			if xrootSvcUrl == "" {
				return errors.New("Origin.XRootServiceUrl may not be empty when the origin is configured with an xroot backend")
			}
			_, err := url.Parse(xrootSvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.XrootServiceUrl as a URL")
			}
		case "s3":
			s3SvcUrl := param.Origin_S3ServiceUrl.GetString()
			if s3SvcUrl == "" {
				return errors.New("Origin.S3ServiceUrl may not be empty when the origin is configured with an s3 backend")
			}
			_, err := url.Parse(s3SvcUrl)
			if err != nil {
				return errors.Wrap(err, "unable to parse Origin.S3ServiceUrl as a URL")
			}
		}

		if ost != "posix" {
			if param.Origin_SelfTest.GetBool() {
				log.Warning("Origin.SelfTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
				viper.Set(param.Origin_SelfTest.GetName(), false)
			}
			if param.Origin_DirectorTest.GetBool() {
				log.Warning("Origin.DirectorTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
				viper.Set(param.Origin_DirectorTest.GetName(), false)
			}
		}
	}

	if param.Cache_LowWatermark.IsSet() || param.Cache_HighWaterMark.IsSet() {
		lowWmStr := param.Cache_LowWatermark.GetString()
		highWmStr := param.Cache_HighWaterMark.GetString()
		ok, highWmNum, err := checkWatermark(highWmStr)
		if !ok && err != nil {
			return errors.Wrap(err, "invalid Cache.HighWaterMark value")
		}
		ok, lowWmNum, err := checkWatermark(lowWmStr)
		if !ok && err != nil {
			return errors.Wrap(err, "invalid Cache.LowWatermark value")
		}
		if lowWmNum >= highWmNum {
			return fmt.Errorf("invalid Cache.HighWaterMark and  Cache.LowWatermark values. Cache.HighWaterMark must be greater than Cache.LowWaterMark. Got %s, %s", highWmStr, lowWmStr)
		}
	}

	webPort := param.Server_WebPort.GetInt()
	if webPort < 0 {
		return errors.Errorf("the Server.WebPort setting of %d is invalid; TCP ports must be greater than 0", webPort)
	}
	if webPort != 443 {
		viper.SetDefault("Server.ExternalWebUrl", fmt.Sprintf("https://%s:%d", hostname, webPort))
	} else {
		viper.SetDefault("Server.ExternalWebUrl", fmt.Sprintf("https://%s", hostname))
	}
	externalAddressStr := param.Server_ExternalWebUrl.GetString()
	parsedExtAdd, err := url.Parse(externalAddressStr)
	if err != nil {
		return errors.Wrap(err, fmt.Sprint("invalid Server.ExternalWebUrl: ", externalAddressStr))
	} else {
		// We get rid of any 443 port if present to be consistent
		if parsedExtAdd.Port() == "443" {
			parsedExtAdd.Host = parsedExtAdd.Hostname()
			viper.Set("Server.ExternalWebUrl", parsedExtAdd.String())
		}
	}

	if currentServers.IsEnabled(server_structs.DirectorType) {
		// Default to Server.ExternalWebUrl. Provided Federation.DirectorUrl will overwrite this if any
		viper.SetDefault("Federation.DirectorUrl", param.Server_ExternalWebUrl.GetString())

		minStatRes := param.Director_MinStatResponse.GetInt()
		maxStatRes := param.Director_MaxStatResponse.GetInt()
		if minStatRes <= 0 || maxStatRes <= 0 {
			return errors.New("Invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse and MinStatResponse must be positive integers")
		}
		if maxStatRes < minStatRes {
			return errors.New("Invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse is less than MinStatResponse")
		}

		switch s := (server_structs.SortType)(param.Director_CacheSortMethod.GetString()); s {
		case server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType:
			break
		case server_structs.SortType(""):
			viper.Set("Director.CacheSortMethod", server_structs.DistanceType)
		default:
			return errors.New(fmt.Sprintf("Invalid Director.CacheSortMethod. Must be one of '%s', '%s', '%s', or '%s', but you configured '%s'.",
				server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType, s))
		}
	}

	if currentServers.IsEnabled(server_structs.RegistryType) {
		viper.SetDefault("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString())
	}

	if currentServers.IsEnabled(server_structs.BrokerType) {
		viper.SetDefault("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString())
	}
	tokenRefreshInterval := param.Monitoring_TokenRefreshInterval.GetDuration()
	tokenExpiresIn := param.Monitoring_TokenExpiresIn.GetDuration()

	if tokenExpiresIn == 0 || tokenRefreshInterval == 0 || tokenRefreshInterval > tokenExpiresIn {
		viper.Set("Monitoring.TokenRefreshInterval", time.Minute*5)
		viper.Set("Monitoring.TokenExpiresIn", time.Hour*1)
		log.Warningln("Invalid Monitoring.TokenRefreshInterval or Monitoring.TokenExpiresIn. Fallback to 5m for refresh interval and 1h for valid interval")
	}

	if currentServers.IsEnabled(server_structs.OriginType) || currentServers.IsEnabled(server_structs.CacheType) {
		if param.Xrootd_ConfigFile.IsSet() {
			_, err := os.Stat(param.Xrootd_ConfigFile.GetString())
			if err != nil {
				return fmt.Errorf("fail to open the file Xrootd.ConfigFile at %s: %v", param.Xrootd_ConfigFile.GetString(), err)
			}
		}
	}

	// Unmarshal Viper config into a Go struct
	unmarshalledConfig, err := param.UnmarshalConfig()
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Reset issuerPrivateJWK to ensure test cases can use their own temp IssuerKey
	ResetIssuerJWKPtr()

	// As necessary, generate private keys, JWKS and corresponding certs

	// Note: This function will generate a private key in the location stored by the viper var "IssuerKey"
	// iff there isn't any valid private key present in that location
	_, err = GetIssuerPublicJWKS()
	if err != nil {
		return err
	}

	// Check if we have required files in place to set up TLS, or we will generate them
	err = GenerateCert()
	if err != nil {
		return err
	}

	// Generate the session secret and save it as the default value
	if err := GenerateSessionSecret(); err != nil {
		return err
	}

	// Setup the audience to use.  We may customize the Origin.URL in the future if it has
	// a `0` for the port number; to make the audience predictable (it goes into the xrootd
	// configuration but we don't know the origin's port until after xrootd has started), we
	// stash a copy of its value now.
	viper.Set("Origin.AudienceURL", param.Origin_Url.GetString())

	// After we know we have the certs we need, call setupTransport (which uses those certs for its TLSConfig)
	setupTransport()

	// Setup CSRF middleware. To use it, you need to add this middleware to your chain
	// of http handlers by calling config.GetCSRFHandler()
	setupCSRFHandler()

	// Sets up the server log filter mechanism
	initFilterLogging()

	// Sets (or resets) the federation info.  Unlike in clients, we do this at startup
	// instead of deferring it
	fedDiscoveryOnce = &sync.Once{}
	if _, err := GetFederation(ctx); err != nil {
		return err
	}

	return nil
}

// This function checks if initClient has been called
func IsClientInitialized() bool {
	return clientInitialized
}

// This function resets the clientInitialized variable (mainly used for testing)
func ResetClientInitialized() {
	clientInitialized = false
}

func SetClientDefaults(v *viper.Viper) {
	configDir := v.GetString("ConfigDir")
	v.SetDefault("IssuerKey", filepath.Join(configDir, "issuer.jwk"))
	upper_prefix := GetPreferredPrefix()
	if upper_prefix == OsdfPrefix || upper_prefix == StashPrefix {
		v.SetDefault("Federation.TopologyNamespaceURL", "https://topology.opensciencegrid.org/osdf/namespaces")
	}
	// Set our default worker count
	v.SetDefault("Client.WorkerCount", 5)
	v.SetDefault("Server.TLSCACertificateFile", filepath.Join(configDir, "certificates", "tlsca.pem"))

}

func InitClient() error {
	SetClientDefaults(viper.GetViper())
	viper.AutomaticEnv()

	upper_prefix := GetPreferredPrefix()
	viper.SetEnvPrefix(string(upper_prefix))

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// Do not fail if the config file is missing
	}
	env_config_file := os.Getenv(upper_prefix.String() + "_CONFIG_FILE")
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
		if _, isSet := os.LookupEnv(prefix.String() + "_DISABLE_HTTP_PROXY"); isSet {
			viper.Set("Client.DisableHttpProxy", true)
			break
		}
	}
	for _, prefix := range prefixes_with_osg {
		if _, isSet := os.LookupEnv(prefix.String() + "_DISABLE_PROXY_FALLBACK"); isSet {
			viper.Set("Client.DisableProxyFallback", true)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_DIRECTOR_URL"); isSet {
			viper.Set("Federation.DirectorURL", val)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_NAMESPACE_URL"); isSet {
			viper.Set("Federation.RegistryUrl", val)
			break
		}
	}
	for _, prefix := range prefixes {
		if val, isSet := os.LookupEnv(prefix.String() + "_TOPOLOGY_NAMESPACE_URL"); isSet {
			viper.Set("Federation.TopologyNamespaceURL", val)
			break
		}
	}
	// Check the environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED (and all the prefix variants)
	var downloadLimit int64 = 1024 * 100
	var prefixes_with_cp []ConfigPrefix
	for _, prefix := range prefixes {
		prefixes_with_cp = append(prefixes_with_cp, prefix+"CP")
	}
	for _, prefix := range append(prefixes, prefixes_with_cp...) {
		downloadLimitStr := os.Getenv(prefix.String() + "_MINIMUM_DOWNLOAD_SPEED")
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
	unmarshalledConfig, err := param.UnmarshalConfig()
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Sets (or resets) the deferred federation lookup
	fedDiscoveryOnce = &sync.Once{}

	clientInitialized = true

	return nil
}

// This function resets most states for test cases, including 1. viper settings, 2. preferred prefix, 3. transport object, 4. Federation metadata back to their default
func ResetConfig() {
	viper.Reset()

	// Clear cached preferred prefix
	testingPreferredPrefix = ""

	// Clear cached transport object
	onceTransport = sync.Once{}
	transport = nil

	// Reset federation metadata
	fedDiscoveryOnce = &sync.Once{}
	globalFedInfo = pelican_url.FederationDiscovery{}
	globalFedErr = nil

	ResetIssuerJWKPtr()
	ResetClientInitialized()

	// other than what's above, resetting Origin exports will be done by ResetTestState() in server_utils pkg
}
