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
	"reflect"
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

	"github.com/pelicanplatform/pelican/docs"
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

	clientInitialized     = false
	printClientConfigOnce sync.Once
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

func getConfigBase() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// We currently don't handle this case in Windows (and it may not even occur)
		// This will be revisited in the future
		log.Warningln("No home directory found for user -- will check for configuration yaml in /etc/pelican/")
		return filepath.Join("/etc", "pelican")
	}

	return filepath.Join(home, ".config", "pelican")
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
	if caCert, err := LoadCertificate(param.Server_TLSCACertificateFile.GetString()); err == nil {
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

// Get singleton global validate method for field validation
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

// For the given Viper instance, load up the default YAML files.
func SetBaseDefaultsInConfig(v *viper.Viper) {
	//Load defaults.yaml
	v.SetConfigType("yaml")
	err := v.MergeConfig(strings.NewReader(defaultsYaml))
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
		err := v.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			cobra.CheckErr(err)
		}
	}

}

// For the given Viper instance, set the default config directory.
func InitConfigDir(v *viper.Viper) {

	configDir := v.GetString("ConfigDir")
	if configDir == "" {
		if IsRootExecution() {
			configDir = "/etc/pelican" // We currently don't handle this case in windows, will be revisted in the future
		} else {
			configDir = getConfigBase()
		}
		v.SetDefault("ConfigDir", configDir)
	}
	v.SetConfigName("pelican")
}

// InitConfig sets up the global Viper instance by loading defaults and
// user-defined config files, validates config params, and initializes logging.
func InitConfig() {

	// Enable BindStruct to allow unmarshal env into a nested struct
	viper.SetOptions(viper.ExperimentalBindStruct())

	// Set default values in the global Viper instance
	SetBaseDefaultsInConfig(viper.GetViper())

	InitConfigDir(viper.GetViper())

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
				cobra.CheckErr(fmt.Errorf("failed to access/create specified directory: %w", err))
			}
		}

		// Note: logrus handles file closure, so no need to close manually
		f, err := os.OpenFile(logLocation, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			cobra.CheckErr(fmt.Errorf("failed to access specified log file: %w", err))
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
		cobra.CheckErr(fmt.Errorf("failed to set up translation for the validator: %w", err))
	}
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
	rawConfig, err := param.UnmarshalConfig(viper.GetViper())
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetComponentConfig filters the full config and returns only the config parameters related to the given component.
// The filtering is based on whether the given component is part of the components in docs.parameters.yaml.
func GetComponentConfig(component string) (map[string]interface{}, error) {
	rawConfig, err := param.UnmarshalConfig(viper.GetViper())
	if err != nil {
		return nil, err
	}
	value, hasValue := filterConfigRecursive(reflect.ValueOf(rawConfig), "", component)
	if hasValue {
		return (*value).(map[string]interface{}), nil
	}
	return nil, nil
}

// filterConfigRecursive is a helper function for GetComponentConfig.
// It recursively creates a nested config map of the parameters that relate to the given component.
func filterConfigRecursive(v reflect.Value, currentPath string, component string) (*interface{}, bool) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		result := make(map[string]interface{})
		hasField := false
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := t.Field(i)
			if !fieldType.IsExported() {
				continue
			}

			fieldName := strings.ToLower(fieldType.Name)

			var newPath string
			if currentPath == "" {
				newPath = fieldName
			} else {
				newPath = currentPath + "." + fieldName
			}

			fieldValue, fieldHasValue := filterConfigRecursive(field, newPath, component)
			if fieldHasValue && fieldValue != nil {
				result[fieldName] = *fieldValue
				hasField = true
			}
		}
		if hasField {
			resultInterface := interface{}(result)
			return &resultInterface, true
		}
		return nil, false
	default:
		lowerPath := strings.ToLower(currentPath)
		paramDoc, exists := docs.ParsedParameters[lowerPath]
		if exists && contains(paramDoc.Components, component) {
			resultValue := v.Interface()
			resultInterface := interface{}(resultValue)
			return &resultInterface, true
		}
		return nil, false
	}
}

// PrintClientConfig prints the client config in JSON format to stderr.
func PrintClientConfig() error {
	clientConfig, err := GetComponentConfig("client")
	if err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(clientConfig, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr,
		"================ Pelican Client Configuration ================\n",
		string(bytes),
		"\n",
		"============= End of Pelican Client Configuration ============")
	return nil
}

func SetServerDefaults(v *viper.Viper) error {
	configDir := v.GetString("ConfigDir")
	v.SetConfigType("yaml")

	v.SetDefault(param.Server_WebConfigFile.GetName(), filepath.Join(configDir, "web-config.yaml"))
	v.SetDefault(param.Server_TLSCertificateChain.GetName(), filepath.Join(configDir, "certificates", "tls.crt"))
	v.SetDefault(param.Server_TLSKey.GetName(), filepath.Join(configDir, "certificates", "tls.key"))
	v.SetDefault(param.Server_TLSCAKey.GetName(), filepath.Join(configDir, "certificates", "tlsca.key"))
	v.SetDefault(param.Server_SessionSecretFile.GetName(), filepath.Join(configDir, "session-secret"))
	v.SetDefault(param.Xrootd_RobotsTxtFile.GetName(), filepath.Join(configDir, "robots.txt"))
	v.SetDefault(param.Xrootd_ScitokensConfig.GetName(), filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	v.SetDefault(param.Xrootd_Authfile.GetName(), filepath.Join(configDir, "xrootd", "authfile"))
	v.SetDefault(param.Xrootd_MacaroonsKeyFile.GetName(), filepath.Join(configDir, "macaroons-secret"))
	v.SetDefault(param.IssuerKey.GetName(), filepath.Join(configDir, "issuer.jwk"))
	v.SetDefault(param.Server_UIPasswordFile.GetName(), filepath.Join(configDir, "server-web-passwd"))
	v.SetDefault(param.Server_UIActivationCodeFile.GetName(), filepath.Join(configDir, "server-web-activation-code"))
	v.SetDefault(param.OIDC_ClientIDFile.GetName(), filepath.Join(configDir, "oidc-client-id"))
	v.SetDefault(param.OIDC_ClientSecretFile.GetName(), filepath.Join(configDir, "oidc-client-secret"))
	v.SetDefault(param.Cache_ExportLocation.GetName(), "/")
	v.SetDefault(param.Registry_RequireKeyChaining.GetName(), true)
	v.SetDefault(param.Origin_StorageType.GetName(), "posix")
	v.SetDefault(param.Origin_SelfTest.GetName(), true)
	v.SetDefault(param.Origin_DirectorTest.GetName(), true)
	// Set up the default S3 URL style to be path-style here as opposed to in the defaults.yaml because
	// we want to be able to check if this is user-provided (which we can't do for defaults.yaml)
	v.SetDefault(param.Origin_S3UrlStyle.GetName(), "path")

	if IsRootExecution() {
		v.SetDefault(param.Origin_RunLocation.GetName(), filepath.Join("/run", "pelican", "xrootd", "origin"))
		v.SetDefault(param.Cache_RunLocation.GetName(), filepath.Join("/run", "pelican", "xrootd", "cache"))

		// Several deprecated keys point to Cache.StorageLocation, and by the time we reach this section of code, we should
		// have already mapped those keys in handleDeprecatedConfig(). To prevent overriding potentially-mapped deprecated keys,
		// we only re-set he default here if this key is not set.
		if !v.IsSet(param.Cache_StorageLocation.GetName()) {
			v.SetDefault(param.Cache_StorageLocation.GetName(), filepath.Join("/run", "pelican", "cache"))
		}
		v.SetDefault(param.Cache_NamespaceLocation.GetName(), filepath.Join(param.Cache_StorageLocation.GetString(), "namespace"))
		v.SetDefault(param.Cache_DataLocations.GetName(), []string{filepath.Join(param.Cache_StorageLocation.GetString(), "data")})
		v.SetDefault(param.Cache_MetaLocations.GetName(), []string{filepath.Join(param.Cache_StorageLocation.GetString(), "meta")})

		v.SetDefault(param.LocalCache_RunLocation.GetName(), filepath.Join("/run", "pelican", "localcache"))
		v.SetDefault(param.Origin_Multiuser.GetName(), true)
		v.SetDefault(param.Origin_DbLocation.GetName(), "/var/lib/pelican/origin.sqlite")
		v.SetDefault(param.Director_GeoIPLocation.GetName(), "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		v.SetDefault(param.Registry_DbLocation.GetName(), "/var/lib/pelican/registry.sqlite")
		v.SetDefault(param.Director_DbLocation.GetName(), "/var/lib/pelican/director.sqlite")
		// The lotman db will actually take this path and create the lot at /path/.lot/lotman_cpp.sqlite
		v.SetDefault(param.Lotman_DbLocation.GetName(), "/var/lib/pelican")
		v.SetDefault(param.Monitoring_DataLocation.GetName(), "/var/lib/pelican/monitoring/data")
		v.SetDefault(param.Shoveler_QueueDirectory.GetName(), "/var/spool/pelican/shoveler/queue")
		v.SetDefault(param.Shoveler_AMQPTokenLocation.GetName(), "/etc/pelican/shoveler-token")
		v.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join("/run", "pelican", "xrootd", "origin", "globus"))
	} else {
		v.SetDefault(param.Origin_DbLocation.GetName(), filepath.Join(configDir, "origin.sqlite"))
		v.SetDefault(param.Director_GeoIPLocation.GetName(), filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		v.SetDefault(param.Registry_DbLocation.GetName(), filepath.Join(configDir, "ns-registry.sqlite"))
		v.SetDefault(param.Director_DbLocation.GetName(), filepath.Join(configDir, "director.sqlite"))
		// Lotdb will live at <configDir>/.lot/lotman_cpp.sqlite
		v.SetDefault(param.Lotman_DbLocation.GetName(), configDir)
		v.SetDefault(param.Monitoring_DataLocation.GetName(), filepath.Join(configDir, "monitoring/data"))
		v.SetDefault(param.Shoveler_QueueDirectory.GetName(), filepath.Join(configDir, "shoveler/queue"))
		v.SetDefault(param.Shoveler_AMQPTokenLocation.GetName(), filepath.Join(configDir, "shoveler-token"))

		runtimeDir := filepath.Join(os.TempDir(), "pelican-xrootd-*") // Construct the expected path

		if v == viper.GetViper() && os.Getenv("XDG_RUNTIME_DIR") != "" {
			runtimeDir = filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "pelican")
		}

		if !v.IsSet(param.Cache_RunLocation.GetName()) {
			if v.IsSet(param.Xrootd_RunLocation.GetName()) {
				v.SetDefault(param.Cache_RunLocation.GetName(), v.GetString(param.Xrootd_RunLocation.GetName()))
			} else {
				v.SetDefault(param.Cache_RunLocation.GetName(), filepath.Join(runtimeDir, "cache"))
			}
		}

		if !v.IsSet(param.Origin_RunLocation.GetName()) {
			if v.IsSet(param.Xrootd_RunLocation.GetName()) {
				v.SetDefault(param.Origin_RunLocation.GetName(), v.GetString(param.Xrootd_RunLocation.GetName()))
			} else {
				v.SetDefault(param.Origin_RunLocation.GetName(), filepath.Join(runtimeDir, "origin"))
			}
		}

		v.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))

		// Several deprecated keys point to Cache.StorageLocation, and by the time we reach this section of code, we should
		// have already mapped those keys in handleDeprecatedConfig(). To prevent overriding potentially-mapped deprecated keys,
		// we only re-set he default here if this key is not set.
		if !viper.IsSet(param.Cache_StorageLocation.GetName()) {
			viper.SetDefault(param.Cache_StorageLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		}
		viper.SetDefault(param.Cache_NamespaceLocation.GetName(), filepath.Join(param.Cache_StorageLocation.GetString(), "namespace"))
		viper.SetDefault(param.Cache_DataLocations.GetName(), []string{filepath.Join(param.Cache_StorageLocation.GetString(), "data")})
		viper.SetDefault(param.Cache_MetaLocations.GetName(), []string{filepath.Join(param.Cache_StorageLocation.GetString(), "meta")})

		v.SetDefault(param.LocalCache_RunLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		v.SetDefault(param.Origin_Multiuser.GetName(), false)
	}

	fcRunLocation := v.GetString(param.LocalCache_RunLocation.GetName())
	v.SetDefault(param.LocalCache_Socket.GetName(), filepath.Join(fcRunLocation, "cache.sock"))
	v.SetDefault(param.LocalCache_DataLocation.GetName(), filepath.Join(fcRunLocation, "cache"))

	// Any platform-specific paths should go here
	err := InitServerOSDefaults(v)
	if err != nil {
		return errors.Wrapf(err, "Failure when setting up OS-specific configuration")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	v.SetDefault(param.Server_Hostname.GetName(), hostname)
	// For the rest of the function, use the hostname provided by the admin if
	// they have overridden the defaults.
	hostname = v.GetString("Server.Hostname")
	// We default to the value of Server.Hostname, which defaults to os.Hostname but can be overwritten
	v.SetDefault(param.Xrootd_Sitename.GetName(), hostname)

	cachePort := v.GetInt("Cache.Port")
	originPort := v.GetInt("Origin.Port")
	xrootdPort := v.GetInt("Xrootd.Port")
	xrootdPortIsSet := v.IsSet("Xrootd.Port")
	if !v.IsSet("Cache.Port") {
		if xrootdPortIsSet {
			cachePort = xrootdPort
		}
	}

	if !v.IsSet(param.Origin_Port.GetName()) && xrootdPortIsSet {
		originPort = xrootdPort
	}

	v.SetDefault("Origin.CalculatedPort", strconv.Itoa(originPort))
	if originPort == 0 {
		v.SetDefault("Origin.CalculatedPort", "any")
	}
	v.SetDefault("Cache.CalculatedPort", strconv.Itoa(cachePort))
	if cachePort == 0 {
		v.SetDefault("Cache.CalculatedPort", "any")
	}

	v.SetDefault(param.Origin_Port.GetName(), originPort)
	v.SetDefault(param.Cache_Port.GetName(), cachePort)

	if originPort != 443 {
		v.SetDefault(param.Origin_Url.GetName(), fmt.Sprintf("https://%v:%v", v.GetString(param.Server_Hostname.GetName()), originPort))
	} else {
		v.SetDefault(param.Origin_Url.GetName(), fmt.Sprintf("https://%v", v.GetString(param.Server_Hostname.GetName())))
	}

	if cachePort != 443 {
		v.SetDefault(param.Cache_Url.GetName(), fmt.Sprintf("https://%v:%v", v.GetString(param.Server_Hostname.GetName()), cachePort))
	} else {
		v.SetDefault(param.Cache_Url.GetName(), fmt.Sprintf("https://%v", v.GetString(param.Server_Hostname.GetName())))
	}

	webPort := v.GetInt(param.Server_WebPort.GetName())
	if webPort < 0 {
		return errors.Errorf("the Server.WebPort setting of %d is invalid; TCP ports must be greater than 0", webPort)
	}

	if webPort != 443 {
		v.SetDefault(param.Server_ExternalWebUrl.GetName(), fmt.Sprintf("https://%s:%d", hostname, webPort))
	} else {
		v.SetDefault(param.Server_ExternalWebUrl.GetName(), fmt.Sprintf("https://%s", hostname))
	}

	externalAddressStr := v.GetString(param.Server_ExternalWebUrl.GetName())
	parsedExtAdd, err := url.Parse(externalAddressStr)
	if err != nil {
		return errors.Wrap(err, fmt.Sprint("invalid Server.ExternalWebUrl: ", externalAddressStr))
	} else if parsedExtAdd.Port() == "443" {
		parsedExtAdd.Host = parsedExtAdd.Hostname()
		v.Set(param.Server_ExternalWebUrl.GetName(), parsedExtAdd.String())
	}

	// Setup the audience to use.  We may customize the Origin.URL in the future if it has
	// a `0` for the port number; to make the audience predictable (it goes into the xrootd
	// configuration but we don't know the origin's port until after xrootd has started), we
	// stash a copy of its value now.
	v.SetDefault("Origin.AudienceURL", v.GetString(param.Origin_Url.GetName()))

	// Set defaults for Director, Registry, and Broker URLs only if the Discovery URL is not set.
	// This is necessary because, in Viper, there is currently no way to check if a value is coming
	// from the default or was explicitly set by the user. Therefore, if the DiscoveryURL is present,
	// when populating the Director, Registry, and Broker URLs, the discoverFederationImpl function
	// checks if these values are empty. An empty value indicates that the URLs were not explicitly
	// set, so values obtained through the discovery process should be used.
	//
	// If we set default values now, there would be no way for discoverFederationImpl to determine
	// whether the values are defaults (and should be overridden) or were explicitly set by the user
	// (and should not be overridden).
	// A feature request to address this issue has already been submitted to the Viper repository by our team:
	// https://github.com/spf13/viper/issues/1814
	if !v.IsSet(param.Federation_DiscoveryUrl.GetName()) {
		v.SetDefault("Federation.RegistryUrl", v.GetString(param.Server_ExternalWebUrl.GetName()))
		v.SetDefault("Federation.BrokerURL", v.GetString(param.Server_ExternalWebUrl.GetName()))
		v.SetDefault("Federation_DirectorUrl", v.GetString(param.Server_ExternalWebUrl.GetName()))
	}

	return err
}

// Initialize Pelican server instance. Pass a bit mask of `currentServers` if you want to enable multiple services.
// Note not all configurations are supported: currently, if you enable both cache and origin then an error
// is thrown
func InitServer(ctx context.Context, currentServers server_structs.ServerType) error {

	setEnabledServer(currentServers)

	// Output warnings before the defaults are set. The SetServerDefaults function sets the default values
	// of Origin.StorageType to "posix" and Origin.SelfTest to true. After these defaults are applied,
	// it becomes impossible to determine if the values are coming from the default settings or from user input.
	if currentServers.IsEnabled(server_structs.OriginType) && param.Origin_StorageType.GetString() != "posix" {
		if param.Origin_SelfTest.GetBool() {
			log.Warning("Origin.SelfTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
			viper.Set(param.Origin_SelfTest.GetName(), false)
		}
		if param.Origin_DirectorTest.GetBool() {
			log.Warning("Origin.DirectorTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
			viper.Set(param.Origin_DirectorTest.GetName(), false)
		}
	}

	if err := SetServerDefaults(viper.GetViper()); err != nil {
		return err
	}

	webConfigPath := param.Server_WebConfigFile.GetString()
	if webConfigPath != "" {
		if err := os.MkdirAll(filepath.Dir(webConfigPath), 0700); err != nil {
			cobra.CheckErr(errors.Wrapf(err, "failed to create directory for web config file at %s", webConfigPath))
		}
	}
	if err := setWebConfigOverride(viper.GetViper(), webConfigPath); err != nil {
		cobra.CheckErr(errors.Wrapf(err, "failed to override configuration based on changes from web UI"))
	}

	if !IsRootExecution() {
		var runtimeDir string
		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir = filepath.Join(userRuntimeDir, "pelican")
			if err := os.MkdirAll(runtimeDir, 0750); err != nil {
				return err
			}
		} else {
			var err error
			runtimeDir, err = os.MkdirTemp("", "pelican-xrootd-*")
			if err != nil {
				return err
			}
			cleanupDirOnShutdown(ctx, runtimeDir)
		}
		if !param.Cache_RunLocation.IsSet() && !param.Origin_RunLocation.IsSet() && param.Xrootd_RunLocation.IsSet() {
			return errors.New("Xrootd.RunLocation is set, but both modules are enabled. Please set Cache.RunLocation and Origin.RunLocation or disable Xrootd.RunLocation so the default location can be used.")
		}
	}

	if err := os.MkdirAll(param.Monitoring_DataLocation.GetString(), 0750); err != nil {
		return errors.Wrapf(err, "failure when creating a directory for the monitoring data")
	}

	if err := os.MkdirAll(param.Shoveler_QueueDirectory.GetString(), 0750); err != nil {
		return errors.Wrapf(err, "failure when creating a directory for the shoveler on-disk queue")
	}
	if currentServers.IsEnabled(server_structs.OriginType) {
		ost := param.Origin_StorageType.GetString()
		switch ost {
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
	}

	if currentServers.IsEnabled(server_structs.CacheType) && !param.Cache_Port.IsSet() && !param.Xrootd_Port.IsSet() {
		return errors.New("the configuration Cache.Port is not set but the Cache module is enabled. Please set Cache.Port")
	}
	if currentServers.IsEnabled(server_structs.OriginType) && !param.Origin_Port.IsSet() && !param.Xrootd_Port.IsSet() {
		return errors.New("the configuration Origin.Port is not set but the Origin module is enabled. Please set Origin.Port")
	}

	if currentServers.IsEnabled(server_structs.CacheType) && currentServers.IsEnabled(server_structs.OriginType) && param.Cache_Port.GetInt() == param.Origin_Port.GetInt() && param.Xrootd_Port.IsSet() {
		return errors.New("neither Cache.Port nor Origin.Port is set but both modules are enabled. Please set both variables")
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
			return fmt.Errorf("invalid Cache.HighWaterMark and Cache.LowWatermark values. Cache.HighWaterMark must be greater than Cache.LowWaterMark. Got %s, %s", highWmStr, lowWmStr)
		}
	}

	if currentServers.IsEnabled(server_structs.DirectorType) {
		viper.SetDefault("Federation.DirectorUrl", param.Server_ExternalWebUrl.GetString())
		minStatRes := param.Director_MinStatResponse.GetInt()
		maxStatRes := param.Director_MaxStatResponse.GetInt()
		if minStatRes <= 0 || maxStatRes <= 0 {
			return errors.New("invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse and MinStatResponse must be positive integers")
		}
		if maxStatRes < minStatRes {
			return errors.New("invalid Director.MinStatResponse and Director.MaxStatResponse. MaxStatResponse is less than MinStatResponse")
		}

		switch s := (server_structs.SortType)(param.Director_CacheSortMethod.GetString()); s {
		case server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType:
			break
		case server_structs.SortType(""):
			viper.Set(param.Director_CacheSortMethod.GetName(), server_structs.DistanceType)
		default:
			return errors.New(fmt.Sprintf("invalid Director.CacheSortMethod. Must be one of '%s', '%s', '%s', or '%s', but you configured '%s'.",
				server_structs.DistanceType, server_structs.DistanceAndLoadType, server_structs.RandomType, server_structs.AdaptiveType, s))
		}
	} else {
		viper.SetDefault("Federation.DirectorUrl", "")
	}

	if currentServers.IsEnabled(server_structs.RegistryType) {
		viper.SetDefault("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString())
	} else {
		viper.SetDefault("Federation.RegistryUrl", "")
	}

	if currentServers.IsEnabled(server_structs.BrokerType) {
		viper.SetDefault("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString())
	} else {
		viper.SetDefault("Federation.BrokerURL", "")
	}

	tokenRefreshInterval := param.Monitoring_TokenRefreshInterval.GetDuration()
	tokenExpiresIn := param.Monitoring_TokenExpiresIn.GetDuration()

	if tokenExpiresIn == 0 || tokenRefreshInterval == 0 || tokenRefreshInterval > tokenExpiresIn {
		viper.Set(param.Monitoring_TokenRefreshInterval.GetName(), time.Minute*5)
		viper.Set(param.Monitoring_TokenExpiresIn.GetName(), time.Hour*1)
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
	unmarshalledConfig, err := param.UnmarshalConfig(viper.GetViper())
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

func SetClientDefaults(v *viper.Viper) error {
	configDir := v.GetString("ConfigDir")

	v.SetDefault(param.IssuerKey.GetName(), filepath.Join(configDir, "issuer.jwk"))
	upperPrefix := GetPreferredPrefix()
	if upperPrefix == OsdfPrefix || upperPrefix == StashPrefix {
		v.SetDefault("Federation.TopologyNamespaceURL", "https://topology.opensciencegrid.org/osdf/namespaces")
	}
	// Set our default worker count
	v.SetDefault(param.Client_WorkerCount.GetName(), 5)
	v.SetDefault(param.Server_TLSCACertificateFile.GetName(), filepath.Join(configDir, "certificates", "tlsca.pem"))

	var downloadLimit int64 = 1024 * 100
	v.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), downloadLimit)
	if v == viper.GetViper() {
		viper.AutomaticEnv()
		upperPrefix := GetPreferredPrefix()
		viper.SetEnvPrefix(string(upperPrefix))

		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		err := viper.ReadInConfig()
		if err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return err
			}
			// Do not fail if the config file is missing
		}
		env_config_file := os.Getenv(upperPrefix.String() + "_CONFIG_FILE")
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
				viper.Set(param.Client_DisableHttpProxy.GetName(), true)
				break
			}
		}
		for _, prefix := range prefixes_with_osg {
			if _, isSet := os.LookupEnv(prefix.String() + "_DISABLE_PROXY_FALLBACK"); isSet {
				viper.Set(param.Client_DisableProxyFallback.GetName(), true)
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
		if param.MinimumDownloadSpeed.IsSet() {
			viper.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), param.MinimumDownloadSpeed.GetInt())
		} else {
			viper.Set(param.Client_MinimumDownloadSpeed.GetName(), downloadLimit)
		}
		// Handle more legacy config options
		if param.DisableProxyFallback.IsSet() {
			viper.SetDefault(param.Client_DisableProxyFallback.GetName(), param.DisableProxyFallback.GetBool())
		}
		if param.DisableHttpProxy.IsSet() {
			viper.SetDefault(param.Client_DisableHttpProxy.GetName(), param.DisableHttpProxy.GetBool())
		}

	}
	return nil
}

func InitClient() error {
	if err := SetClientDefaults(viper.GetViper()); err != nil {
		return err
	}

	setupTransport()

	// Unmarshal Viper config into a Go struct
	unmarshalledConfig, err := param.UnmarshalConfig(viper.GetViper())
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Sets (or resets) the deferred federation lookup
	fedDiscoveryOnce = &sync.Once{}

	clientInitialized = true

	var printClientConfigErr error
	printClientConfigOnce.Do(func() {
		if log.GetLevel() == log.DebugLevel {
			printClientConfigErr = PrintClientConfig()
		}
	})

	// Return any error encountered during PrintClientConfig
	if printClientConfigErr != nil {
		return printClientConfigErr
	}

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
