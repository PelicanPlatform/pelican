/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-kit/log/term"
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
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/docs"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/version"
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

	ClearServerAdsFunc func()
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
	TokenWrite TokenOperation = 1 << iota
	TokenRead
	TokenSharedWrite
	TokenSharedRead
	TokenDelete
	TokenList
)

// Set sets a new operation to the Operation instance
func (o *TokenOperation) Set(newOp TokenOperation) {
	*o |= newOp
}

// IsEnabled checks if a testOp is in the Operation instance
func (o TokenOperation) IsEnabled(testOp TokenOperation) bool {
	return o&testOp == testOp
}

// Clear all values in an operation
func (o *TokenOperation) Clear() {
	*o = TokenOperation(0)
}

// Create a new, empty operation
func NewOperation() TokenOperation {
	return TokenOperation(0)
}

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

	// Global discovery info.  Using the "once" allows us to delay discovery
	// until it's first needed, avoiding a web lookup for invoking configuration
	// Note the 'once' object is a pointer so we can reset the client multiple
	// times during unit tests
	fedDiscoveryOnce *sync.Once
	globalFedInfo    atomic.Pointer[pelican_url.FederationDiscovery]
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

	// Some config parsing tools will init both client and server config, but both
	// warn about several config params. Only warn once per process.
	warnDeprecatedOnce sync.Once
	warnDebugOnce      sync.Once

	RestartFlag  = make(chan any) // A channel flag to restart the server instance that launcher listens to (including cache)
	ShutdownFlag = make(chan any) // A channel flag to shutdown the server instance that launcher listens to (including cache)

	validPrefixes = map[ConfigPrefix]bool{
		PelicanPrefix: true,
		OsdfPrefix:    true,
		StashPrefix:   true,
		"":            true,
	}

	clientInitialized     = false
	printClientConfigOnce sync.Once

	// This variable will be set by another package (director) to clear the server ads
	ClearServerAdsCallback ClearServerAdsFunc

	// sysConfigLocation is the system-wide configuration directory.
	// This is a variable (not const) to allow unit tests to mock the
	// /etc/pelican location without requiring filesystem permissions.
	// Production code should NOT modify this value.
	sysConfigLocation string = filepath.Join("/etc", "pelican")
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
	return version.GetVersion()
}

// Overrides the version of the current binary
//
// Intended mainly for use in unit tests
func SetVersion(newVersion string) {
	version.SetVersion(newVersion)
}

func GetBuiltCommit() string {
	return version.GetBuiltCommit()
}

func SetBuiltCommit(newCommit string) {
	version.SetBuiltCommit(newCommit)
}

func GetBuiltDate() string {
	return version.GetBuiltDate()
}

func SetBuiltDate(builtDate string) {
	version.SetBuiltDate(builtDate)
}

func GetBuiltBy() string {
	return version.GetBuiltBy()
}

func SetBuiltBy(newBuiltBy string) {
	version.SetBuiltBy(newBuiltBy)
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

// ValidateServerType checks if any currently enabled server matches the allowed server types slice.
func ValidateServerType(allowedServerTypes []server_structs.ServerType) bool {
	if len(allowedServerTypes) == 0 {
		return false
	}

	enabledServers := GetEnabledServerString(true)
	if len(enabledServers) == 0 {
		return false
	}

	allowed := make(map[string]struct{}, len(allowedServerTypes))
	for _, serverType := range allowedServerTypes {
		allowed[strings.ToLower(serverType.String())] = struct{}{}
	}

	for _, enabled := range enabledServers {
		if _, ok := allowed[enabled]; ok {
			return true
		}
	}

	return false
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
	// The fact that we don't overwrite http:// with https:// appears to be an artifact from testing.
	// In a future where we have time to get to the little things, we should address this since an http
	// central service is a terrible idea, and we shouldn't make it possible just for the sake of testing...
	if len(urlStr) > 0 && !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
		log.Debugf("The configured URL %s did not have an understood scheme ('https://' or 'http://'); will assume https", urlStr)
	}
	return urlStr
}

// Strip port 443 from a URL string if present
func stripPort443(urlStr string) string {
	if urlStr == "" {
		return urlStr
	}

	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return urlStr // Return original if we can't parse it
	}

	if parsedUrl.Port() == "443" {
		parsedUrl.Host = parsedUrl.Hostname()
		return parsedUrl.String()
	}

	return urlStr
}

// Validate that the federation Discovery URL does not contain a path and is otherwise a valid URL.
func validateDiscoveryUrl(discUrlStr string) (*url.URL, error) {
	errPrfx := fmt.Sprintf("invalid federation discovery url of '%s' (config parameter %s):", discUrlStr, param.Federation_DiscoveryUrl.GetName())

	discUrlStr = wrapWithHttpsIfNeeded(discUrlStr)
	discUrl, err := url.Parse(discUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, errPrfx)
	}

	// In some strange cases, URL parsing may render a path but no host
	// (at least, this appears to be an assumption the original author of this logic
	// made, but at time of functionalizing the knowledge as to how that happens is lost).
	// Here, we want to ensure that if there is a host, there is no path.
	if len(discUrl.Path) > 0 && len(discUrl.Host) > 0 {
		return nil, errors.New(errPrfx + fmt.Sprintf(": Discovery URLs cannot contain a URL path, but yours parses as '%s'", discUrl.Path))
	}

	// If we end up with a path but no host, we use the path as the host.
	if len(discUrl.Path) > 0 && len(discUrl.Host) == 0 {
		discUrl.Host = discUrl.Path
		discUrl.Path = ""
	}

	return discUrl, nil
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
		if fedInfo.DirectorAdvertiseEndpoints == nil && enabledServers.IsEnabled(server_structs.DirectorType) {
			fedInfo.DirectorAdvertiseEndpoints = []string{externalUrlStr}
		}

		// Some services in the Director, like federation tokens, may require a defined federation root (discovery URL)
		// so for these to have a chance at working in places where a Director truly is acting as the fed root (e.g.
		// fed-in-box unit tests), we need to set the discovery endpoint to the director endpoint.
		if fedInfo.DiscoveryEndpoint == "" && enabledServers.IsEnabled(server_structs.DirectorType) {
			fedInfo.DiscoveryEndpoint = fedInfo.DirectorEndpoint
		}

		// Make sure any values in global federation metadata are url-parseable
		fedInfo.DiscoveryEndpoint = stripPort443(wrapWithHttpsIfNeeded(fedInfo.DiscoveryEndpoint))
		fedInfo.DirectorEndpoint = stripPort443(wrapWithHttpsIfNeeded(fedInfo.DirectorEndpoint))
		fedInfo.RegistryEndpoint = stripPort443(wrapWithHttpsIfNeeded(fedInfo.RegistryEndpoint))
		fedInfo.JwksUri = stripPort443(wrapWithHttpsIfNeeded(fedInfo.JwksUri))
		fedInfo.BrokerEndpoint = stripPort443(wrapWithHttpsIfNeeded(fedInfo.BrokerEndpoint))
		for i, advUrl := range fedInfo.DirectorAdvertiseEndpoints {
			fedInfo.DirectorAdvertiseEndpoints[i] = stripPort443(wrapWithHttpsIfNeeded(advUrl))
		}
	}()

	// Set each of the fed values to anything we got from config.
	log.Debugln("Configured federation URL:", federationStr)
	fedInfo.DiscoveryEndpoint = federationStr
	fedInfo.DirectorEndpoint = viper.GetString("Federation.DirectorUrl")
	fedInfo.RegistryEndpoint = viper.GetString("Federation.RegistryUrl")
	fedInfo.JwksUri = viper.GetString("Federation.JwkUrl")
	fedInfo.BrokerEndpoint = viper.GetString("Federation.BrokerUrl")

	// The only time we'll ever skip discovery is if we already have all the values.
	// Note that the discovery endpoint itself is required because it acts as the
	// federation's issuer.
	//
	// It's unclear whether director advertise endpoints should also be included here --
	// outside of federations with HA Directors, even the discovered slice will be empty
	// and it doesn't seem like we should enforce its presence.
	if fedInfo.DiscoveryEndpoint != "" && fedInfo.DirectorEndpoint != "" &&
		fedInfo.RegistryEndpoint != "" && fedInfo.JwksUri != "" && fedInfo.BrokerEndpoint != "" {
		return
	}

	federationStr = wrapWithHttpsIfNeeded(federationStr)
	federationUrl, err := validateDiscoveryUrl(federationStr)
	if err != nil {
		return
	}

	// If we have no locally-configured discovery URL but we do have a Director, we may still be able to discover
	// services via the Director's hosting of the metadata. In this case, even though we discover services via the Director,
	// we populate our fed info object's discovery URL with what's discovered, NOT the Director itself. The reason we
	// do this is that the returned fed object's discovery URL acts as the federation's issuer, so it MUST match what the
	// Director sees -- the Director may sign tokens with what it sees as the discovery URL.
	//
	// The awkwardness in this stems from failing to separate out the concepts of federation issuer from discovery URL, but
	// these metadata objects are too established to change easily.
	if federationUrl.String() == "" && fedInfo.DirectorEndpoint != "" {
		log.Debugf("No federation discovery URL was configured; will attempt to fall back to discovering services via the configured Director URL of %s", fedInfo.DirectorEndpoint)
		federationUrl, err = validateDiscoveryUrl(wrapWithHttpsIfNeeded(fedInfo.DirectorEndpoint))
		if err != nil {
			// An error here means there is no valid discovery URL and we couldn't parse the Director URL;
			// we're out of options for discovery
			err = errors.Wrap(err, "could not determine federation discovery URL and was unable to fallback to metadata discovery via the configured Director URL")
			return
		}
		federationStr = federationUrl.String()

		// Unset the discovery endpoint -- in this case we'll try to learn the federation's
		// real discovery URL from the Director
		fedInfo.DiscoveryEndpoint = ""
	}

	var metadata pelican_url.FederationDiscovery
	if federationStr == externalUrlStr {
		log.Debugln("Current web engine hosts the federation; skipping auto-discovery of services")
	} else if federationStr == "" {
		log.Debugln("No federation discovery URL configured; skipping auto-discovery of services")
	} else {
		log.Debugln("Attempting to discover federation services via URL:", federationStr)
		httpClient := GetClient()
		if httpClient == nil {
			err = errors.New("no HTTP client available to perform federation discovery")
			return
		}

		// We can't really know the service here, so set to generic Pelican
		ua := "pelican/" + GetVersion()
		metadata, err = pelican_url.DiscoverFederation(ctx, httpClient, ua, federationUrl)
		if err != nil {
			err = errors.Wrapf(err, "could not discover federation services from '%s'", federationUrl.String())
			return
		}
	}

	// Set our globals
	if fedInfo.DiscoveryEndpoint == "" {
		log.Debugln("Setting global discovery url to", metadata.DiscoveryEndpoint)
		fedInfo.DiscoveryEndpoint = metadata.DiscoveryEndpoint
	}
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
	if fedInfo.DirectorAdvertiseEndpoints == nil && metadata.DirectorAdvertiseEndpoints != nil {
		fedInfo.DirectorAdvertiseEndpoints = metadata.DirectorAdvertiseEndpoints
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
		var fedInfo pelican_url.FederationDiscovery
		fedInfo, globalFedErr = discoverFederationImpl(ctx)
		globalFedInfo.Store(&fedInfo)
	})
	loadedInfo := globalFedInfo.Load()
	if loadedInfo == nil {
		return pelican_url.FederationDiscovery{}, globalFedErr
	}
	return *loadedInfo, globalFedErr
}

// Set the current global federation metadata
func SetFederation(fd pelican_url.FederationDiscovery) {
	// Best-effort update of config state; this should not fail under normal circumstances
	if err := param.MultiSet(map[string]interface{}{
		param.Federation_DiscoveryUrl.GetName(): fd.DiscoveryEndpoint,
		"Federation.DirectorUrl":                fd.DirectorEndpoint,
		"Federation.RegistryUrl":                fd.RegistryEndpoint,
		"Federation.BrokerUrl":                  fd.BrokerEndpoint,
		"Federation.JwkUrl":                     fd.JwksUri,
		"Federation.DirectorAdvertiseEndpoints": fd.DirectorAdvertiseEndpoints,
	}); err != nil {
		log.WithError(err).Warn("Failed to update federation configuration")
	}

	globalFedInfo.Store(&fd)
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

// getConfigBase returns where Pelican will look for its configuration files by default.
// It does not handle setting fallback locations for system config in the event that the
// user's home directory doesn't actually contain config.
func getConfigBase() string {
	if IsRootExecution() {
		os := runtime.GOOS
		if os == "windows" {
			return filepath.Join("C:", "ProgramData", "pelican")
		} else {
			return sysConfigLocation
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		os := runtime.GOOS
		if os == "windows" {
			windowsPath := filepath.Join("C:", "ProgramData", "pelican")
			log.Warningln("No home directory found for user -- will check for configuration yaml in ", windowsPath)
			return windowsPath
		}
		log.Warningf("No home directory found for user -- will check for configuration yaml in %q", sysConfigLocation)
		return sysConfigLocation
	}

	return filepath.Join(home, ".config", "pelican")
}

// GetServerIssuerURL tries to determine the correct issuer URL for the server in order of precedence:
// - Server.IssuerUrl
// - Server.IssuerHostname and Server.IssuerPort
// - Server.ExternalWebUrl
// In general, functions should avoid using `param.Server_IssuerUrl.GetString()` directly and use this function instead.
func GetServerIssuerURL() (issuerUrl string, err error) {
	// Even though we prefer using this function, we'll populate the config param
	// based on whatever we determine here.
	defer func() {
		if err == nil && param.Server_IssuerUrl.GetString() == "" {
			if setErr := param.Set(param.Server_IssuerUrl.GetName(), issuerUrl); setErr != nil {
				log.WithError(setErr).Debugf("Failed to cache %s", param.Server_IssuerUrl.GetName())
			}
		}
	}()

	// Prefer the concretely configured param
	if issuerUrl = param.Server_IssuerUrl.GetString(); issuerUrl != "" {
		if _, err := url.Parse(issuerUrl); err != nil {
			return "", errors.Wrapf(err, "failed to parse %q as issuer URL from config param %q",
				param.Server_IssuerUrl.GetString(), param.Server_IssuerUrl.GetName())
		}
		log.Debugf("Populating server's issuer URL as %q from config param %q", issuerUrl, param.Server_IssuerUrl.GetName())
		return issuerUrl, nil
	}

	// Next, try to piece it together based on concretely configured hostname:port
	if param.Server_IssuerHostname.GetString() != "" {
		if param.Server_IssuerPort.GetInt() == 0 {
			return "", errors.Errorf("if %q is configured, you must also configure a valid port via %q",
				param.Server_IssuerHostname.GetName(), param.Server_IssuerPort.GetName())
		}

		// We assume any issuer is running https
		issuerUrl := fmt.Sprintf("https://%s:%d", param.Server_IssuerHostname.GetString(), param.Server_IssuerPort.GetInt())
		if _, err := url.Parse(issuerUrl); err != nil {
			return "", errors.Wrapf(err, "failed to parse %q as issuer URL from config params %q and %q",
				issuerUrl, param.Server_IssuerHostname.GetName(), param.Server_IssuerPort.GetName())
		}
		log.Debugf("Populating server's issuer URL as %q from configured values of %q and %q",
			issuerUrl, param.Server_IssuerHostname.GetName(), param.Server_IssuerPort.GetName())
		return issuerUrl, nil
	}

	// Finally, fall back to the external web URL
	issuerUrl = param.Server_ExternalWebUrl.GetString()
	if _, err := url.Parse(issuerUrl); err != nil {
		return "", errors.Wrapf(err, "failed to parse %q as the issuer URL generated from config param %q",
			issuerUrl, param.Server_ExternalWebUrl.GetName())
	}
	log.Debugf("Populating server's issuer URL as %q from configured value of %q", issuerUrl, param.Server_ExternalWebUrl.GetName())
	return issuerUrl, nil
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
	warnDeprecatedOnce.Do(func() {
		deprecatedMap := param.GetDeprecated()
		for deprecated, replacement := range deprecatedMap {
			if viper.IsSet(deprecated) {
				if replacement[0] == "none" {
					log.Warningf("Deprecated configuration key %s is set. This is being removed in future release", deprecated)
				} else if deprecated == param.Debug.GetName() {
					// Special case for the Debug key; we handle mapping it to Logging.Level: debug in
					// `setLoggingInternal()` because that has already been executed by the time we get here.
					log.Warningf("The configuration key %q is being deprecated. While your setting for debug logging has been applied, you should set %q to 'debug' to achieve this behavior in the future.", param.Debug.GetName(), param.Logging_Level.GetName())
				} else {
					for _, rep := range replacement {
						if viper.IsSet(rep) {
							log.Warningf("The configuration key %q is deprecated. The value from its replacement %q will be used instead, and the value of the deprecated configuration key %q will be ignored.", deprecated, rep, deprecated)
						} else {
							log.Warningf("The configuration key %q is deprecated. Please use %q instead. Will use the value of deprecated config key %q for the new config key %q.", deprecated, rep, deprecated, rep)
							value := viper.Get(deprecated)
							if err := param.Set(rep, value); err != nil {
								log.WithError(err).Warnf("Failed to set replacement config key %q from deprecated key %q", rep, deprecated)
							}
						}
					}
				}
			}
		}
	})
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
	if configPath == "" {
		return nil
	}

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

	// Keep the param package's cached config in sync with viper after overrides.
	// Without this, subsequent reads via `param.*.GetString()` may see stale values.
	if _, err := param.Refresh(); err != nil {
		return err
	}

	// Use any new viper keys to re-set
	// the logging level.
	if err = setLoggingInternal(); err != nil {
		return err
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

// Helper func that uses configured params to toggle the correct logging level
// in the log library
func setLoggingInternal() error {
	// If the user has not set an explicit log level but they're using the old
	// `Debug` config param, we set the log level to debug. This override behavior
	// is legacy until we remove the `Debug` config param in a future release.
	if param.Debug.GetBool() {
		warnDebugOnce.Do(func() {
			log.Warnf("The config param %q is set in your configuration, which will override any values set for %q ", param.Debug.GetName(), param.Logging_Level.GetName())
		})
		if err := param.Set(param.Logging_Level.GetName(), "debug"); err != nil {
			return err
		}
	}

	logLevel := param.Logging_Level.GetString()
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return errors.Wrapf(err, "failed to parse value of config param %s: %q", param.Logging_Level.GetName(), logLevel)
	}
	SetLogging(level)

	// Initialize the log level manager with our custom functions after setting up logging
	logging.InitLogLevelManager(nil, nil, SetLogging, GetEffectiveLogLevel)

	return nil
}

// For the given Viper instance, set the default config directory.
func InitConfigDir(v *viper.Viper) {
	if configDir := v.GetString("ConfigDir"); configDir == "" {
		v.SetDefault("ConfigDir", getConfigBase())
	}
	v.SetConfigName("pelican")
}

// InitConfigInternal sets up the global Viper instance by loading defaults and
// user-defined config files, validates config params, and initializes logging.
func InitConfigInternal(logLevel log.Level) {
	// Set a prefix so Viper knows how to parse PELICAN_* env vars
	// This must happen before config dir initialization so that Pelican
	// can pick up setting the config dir with PELICAN_CONFIGDIR
	viper.SetEnvPrefix("pelican")
	viper.AutomaticEnv()

	// Log level defaults are set outside of Set{Server/Client}Defaults because
	// logging is needed before those functions are called. They're also set directly
	// in those functions so that the viper objects they generate are consistent.
	//
	// Note that we do the WarnLevel -> "warn" mapping because logrus converts the
	// WarnLevel to "warning" when calling String(), but we want to keep "warn", which
	// is what Pelican uses. For more information, see:
	// https://github.com/PelicanPlatform/pelican/pull/2712
	logString := logLevel.String()
	if logLevel == log.WarnLevel {
		logString = "warn"
	}
	viper.SetDefault(param.Logging_Level.GetName(), logString)

	// Enable BindStruct to allow unmarshal env into a nested struct
	viper.SetOptions(viper.ExperimentalBindStruct())

	// Set default values in the global Viper instance
	SetBaseDefaultsInConfig(viper.GetViper())
	// Refresh the cached param config now that base defaults are loaded.
	// Some callers may touch `param.*` during init; without this, the cache can
	// remain an empty struct and cause missing defaults later (e.g. in InitServer).
	if _, err := param.Refresh(); err != nil {
		cobra.CheckErr(err)
	}

	InitConfigDir(viper.GetViper())

	if configFile := viper.GetString("config"); configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath(viper.GetString("ConfigDir"))

		// Add /etc/pelican as a fallback path for all configs
		// Note that viper only grabs the first config file it finds
		// after checking the paths in the order they were added.
		if !IsRootExecution() {
			viper.AddConfigPath(sysConfigLocation)
		}
	}

	// Load environment variables into the config
	bindNonPelicanEnv() // Deprecate OSDF env prefix but be compatible for now

	// This line allows viper to use an env var like ORIGIN_VALUE to override the viper string "Origin.Value"
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	if err := viper.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			cobra.CheckErr(err)
		}
	}

	// Handle config file specified via <PREFIX>_CONFIG_FILE environment variable
	// This supports PELICAN_CONFIG_FILE, OSDF_CONFIG_FILE, STASH_CONFIG_FILE
	upperPrefix := GetPreferredPrefix()
	if envConfigFile := os.Getenv(upperPrefix.String() + "_CONFIG_FILE"); envConfigFile != "" {
		fp, err := os.Open(envConfigFile)
		if err != nil {
			if !os.IsNotExist(err) {
				cobra.CheckErr(errors.Wrapf(err, "failed to open config file specified via %s_CONFIG_FILE", upperPrefix.String()))
			}
			// If file doesn't exist, continue without it
		} else {
			defer fp.Close()
			if err := viper.MergeConfig(fp); err != nil {
				cobra.CheckErr(errors.Wrapf(err, "failed to read config file specified via %s_CONFIG_FILE", upperPrefix.String()))
			}
		}
	}
	// Handle any extra yaml configurations specified in the ConfigLocations key
	err := handleContinuedCfg()
	if err != nil {
		cobra.CheckErr(err)
	}

	// Now that defaults + config files + env (including continued configs) have
	// been applied to viper, refresh the cached param config struct used by
	// generated accessors.
	if _, err := param.Refresh(); err != nil {
		cobra.CheckErr(err)
	}

	// Use configuration to set the logging level, which must be fed to
	// the logging library and isn't accessed directly through viper
	err = setLoggingInternal()
	if err != nil {
		cobra.CheckErr(err)
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

// printConfigHelper is a helper function for PrintConfig and PrintClientConfig
func printConfigHelper(bytes []byte) {
	originalFormatter := log.StandardLogger().Formatter

	// Defer resetting to the original formatter
	defer func() {
		log.SetFormatter(originalFormatter)
	}()

	isStdout := param.Logging_LogLocation.GetString() == "" && term.IsTerminal(log.StandardLogger().Out)

	log.SetFormatter(&log.TextFormatter{
		DisableQuote:           true,
		DisableTimestamp:       true,
		DisableLevelTruncation: true,
		ForceColors:            isStdout,
	})

	// Log the formatted YAML
	log.Info("\n================ Pelican Configuration ================\n" +
		string(bytes) +
		"============= End of Pelican Configuration ============")
}

// PrintConfig logs the full config dump in YAML format.
func PrintConfig() error {
	rawConfig, err := param.UnmarshalConfig()
	if err != nil {
		return err
	}
	bytes, err := yaml.Marshal(rawConfig)
	if err != nil {
		return err
	}

	printConfigHelper(bytes)

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
	rawConfig, err := param.UnmarshalConfig()
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

			fieldName := fieldType.Name

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

// PrintClientConfig logs the client config in YAML format.
func PrintClientConfig() error {
	clientConfig, err := GetComponentConfig("client")
	if err != nil {
		return err
	}

	bytes, err := yaml.Marshal(clientConfig)
	if err != nil {
		return err
	}

	printConfigHelper(bytes)

	return nil
}

// ensureRuntimeDir populates the runtime directory configuration and indicates whether
// the directory should be cleaned up on shutdown. If the runtime directory is already
// set in the provided viper instance, the existing configuration is returned.
const runtimeDirCleanupKey = "runtimeDirCleanupInternal"

func ensureRuntimeDir(v *viper.Viper) (string, bool, error) {
	if runtimeDir := v.GetString(param.RuntimeDir.GetName()); runtimeDir != "" {
		return runtimeDir, v.GetBool(runtimeDirCleanupKey), nil
	}

	if IsRootExecution() {
		runtimeDir := filepath.Join("/run", "pelican")
		v.SetDefault(param.RuntimeDir.GetName(), runtimeDir)
		v.Set(param.RuntimeDir.GetName(), runtimeDir)
		v.Set(runtimeDirCleanupKey, false)
		return runtimeDir, false, nil
	}

	if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
		runtimeDir := filepath.Join(userRuntimeDir, "pelican")
		v.SetDefault(param.RuntimeDir.GetName(), runtimeDir)
		v.Set(param.RuntimeDir.GetName(), runtimeDir)
		v.Set(runtimeDirCleanupKey, false)
		return runtimeDir, false, nil
	}

	runtimeDir, err := os.MkdirTemp("", "pelican-xrootd-*")
	if err != nil {
		return "", false, errors.Wrap(err, "Failed to create temporary runtime directory for Pelican")
	}
	// Temporary runtime directories are cleaned up on shutdown.
	v.SetDefault(param.RuntimeDir.GetName(), runtimeDir)
	v.Set(param.RuntimeDir.GetName(), runtimeDir)
	v.Set(runtimeDirCleanupKey, true)
	return runtimeDir, true, nil
}

// ComputeExternalWebUrl computes the Server.ExternalWebUrl if not explicitly set.
// This is extracted from SetServerDefaults so it can be called independently
// by client commands that need to determine the server's web URL.
// It sets the default based on Server.Hostname and Server.WebPort if not already configured.
func ComputeExternalWebUrl(v *viper.Viper) error {
	// Only compute if not already set
	if !v.IsSet(param.Server_ExternalWebUrl.GetName()) {
		// Get or set default hostname
		hostname := v.GetString(param.Server_Hostname.GetName())
		if hostname == "" {
			osHostname, err := os.Hostname()
			if err != nil {
				return errors.Wrap(err, "failed to determine hostname")
			}
			hostname = osHostname
		}

		// Get web port
		webPort := v.GetInt(param.Server_WebPort.GetName())
		if webPort == 0 {
			webPort = 8444 // Default web port
		}

		// Compute External Web URL
		if webPort != 443 {
			v.SetDefault(param.Server_ExternalWebUrl.GetName(), fmt.Sprintf("https://%s:%d", hostname, webPort))
		} else {
			v.SetDefault(param.Server_ExternalWebUrl.GetName(), fmt.Sprintf("https://%s", hostname))
		}
	}

	// Strip port 443 if present (even if URL was explicitly set)
	externalAddressStr := v.GetString(param.Server_ExternalWebUrl.GetName())
	parsedExtAdd, err := url.Parse(externalAddressStr)
	if err != nil {
		return errors.Wrap(err, fmt.Sprint("invalid Server.ExternalWebUrl: ", externalAddressStr))
	} else if parsedExtAdd.Port() == "443" {
		parsedExtAdd.Host = parsedExtAdd.Hostname()
		v.Set(param.Server_ExternalWebUrl.GetName(), parsedExtAdd.String())
	}

	return nil
}

// Set all defaults relevant to servers (defaults can be set only for active servers)
// but only for the passed viper instance.
// We operate on the passed viper instance instead of the global because it lets us
// construct two config instances for comparing defaults and overrides in the config
// tool. As such, you SHOULD NOT do a `viper.Set()` or a `param.<some param>.Get*()`
// here as part of the logic for setting defaults on the passed `v` because you'll be
// operating on two different config structs!
func SetServerDefaults(v *viper.Viper) error {
	configDir := v.GetString("ConfigDir")
	v.SetConfigType("yaml")

	// Duplicate setting a default logging level so that this function picks picks up
	// the one case where we need to set client/server defaults differently directly in
	// InitConfigInternal. We need to do that because internal logging levels are set by
	// InitServer/InitClient before we call SetClientDefaults/SetServerDefaults.
	v.SetDefault(param.Logging_Level.GetName(), "info")
	v.SetDefault(param.Server_WebConfigFile.GetName(), filepath.Join(configDir, "web-config.yaml"))
	v.SetDefault(param.Server_TLSCertificateChain.GetName(), filepath.Join(configDir, "certificates", "tls.crt"))
	v.SetDefault(param.Server_TLSKey.GetName(), filepath.Join(configDir, "certificates", "tls.key"))
	v.SetDefault(param.Server_TLSCAKey.GetName(), filepath.Join(configDir, "certificates", "tlsca.key"))
	v.SetDefault(param.Server_SessionSecretFile.GetName(), filepath.Join(configDir, "session-secret"))
	v.SetDefault(param.Xrootd_RobotsTxtFile.GetName(), filepath.Join(configDir, "robots.txt"))
	v.SetDefault(param.Xrootd_ScitokensConfig.GetName(), filepath.Join(configDir, "xrootd", "scitokens.cfg"))
	v.SetDefault(param.Xrootd_Authfile.GetName(), filepath.Join(configDir, "xrootd", "authfile"))
	v.SetDefault(param.Xrootd_MacaroonsKeyFile.GetName(), filepath.Join(configDir, "macaroons-secret"))
	v.SetDefault(param.Xrootd_ShutdownTimeout.GetName(), 1*time.Minute)
	v.SetDefault(param.Xrootd_HttpMaxDelay.GetName(), "9s")
	v.SetDefault(param.Xrootd_MaxThreads.GetName(), 20000)
	v.SetDefault(param.Cache_EvictionMonitoringInterval.GetName(), "60s")
	v.SetDefault(param.Cache_EvictionMonitoringMaxDepth.GetName(), 1)
	v.SetDefault(param.IssuerKey.GetName(), filepath.Join(configDir, "issuer.jwk"))
	v.SetDefault(param.IssuerKeysDirectory.GetName(), filepath.Join(configDir, "issuer-keys"))
	v.SetDefault(param.Server_UIPasswordFile.GetName(), filepath.Join(configDir, "server-web-passwd"))
	v.SetDefault(param.Server_UIActivationCodeFile.GetName(), filepath.Join(configDir, "server-web-activation-code"))
	v.SetDefault(param.OIDC_ClientIDFile.GetName(), filepath.Join(configDir, "oidc-client-id"))
	v.SetDefault(param.OIDC_ClientSecretFile.GetName(), filepath.Join(configDir, "oidc-client-secret"))
	v.SetDefault(param.Server_EnablePKCS11.GetName(), false)
	v.SetDefault(param.Cache_ExportLocation.GetName(), "/")
	v.SetDefault(param.Registry_RequireKeyChaining.GetName(), true)
	v.SetDefault(param.Origin_StorageType.GetName(), "posix")
	v.SetDefault(param.Origin_SelfTest.GetName(), true)
	v.SetDefault(param.Origin_SelfTestInterval.GetName(), 15*time.Second)
	v.SetDefault(param.Cache_SelfTestInterval.GetName(), 15*time.Second)
	// Defaults for XRootD authfile, scitokens config, and self-test staleness checks
	v.SetDefault(param.Xrootd_AutoShutdownEnabled.GetName(), true)
	v.SetDefault(param.Xrootd_ConfigUpdateFailureTimeout.GetName(), 1*time.Hour)

	// Set fed token locations for cache/origin. Note that fed tokens aren't yet used by the
	// Origin (2026-02-05), but they may be soon for things like third party copy.
	v.SetDefault(param.Origin_FedTokenLocation.GetName(), filepath.Join(configDir, "fed-token", "origin-fed-token"))
	v.SetDefault(param.Cache_FedTokenLocation.GetName(), filepath.Join(configDir, "fed-token", "cache-fed-token"))

	runtimeDir, _, err := ensureRuntimeDir(v)
	if err != nil {
		return err
	}
	v.SetDefault(param.Origin_SelfTestMaxAge.GetName(), 1*time.Hour)
	v.SetDefault(param.Cache_SelfTestMaxAge.GetName(), 1*time.Hour)
	// Set up the default S3 URL style to be path-style here as opposed to in the defaults.yaml because
	// we want to be able to check if this is user-provided (which we can't do for defaults.yaml)
	v.SetDefault(param.Origin_S3UrlStyle.GetName(), "path")

	// At the time of this comment, Pelican's default log level is set to "info" for servers. However, that's still
	// too verbose for some XRootD parameters. Because we generally want to use Pelican's configured log level as a
	// default for the XRootD parameters, we only set the corrected default values for these special XRootD directives
	// when Pelican is running in its own default Error level. Otherwise we use Pelican's configured log level as a
	// default for other params.
	defaultLevel := GetEffectiveLogLevel().String()
	// Logrus parses "warn" and converts it to "warning". Pelican uses "warn" in its config and docs,
	// so we map it back here. This makes sure that something like `param.Logging_Origin_Cms.GetString()`
	// returns a pelican-compatible log level.
	if defaultLevel == log.WarnLevel.String() {
		defaultLevel = "warn"
	}
	for _, param := range []param.StringParam{
		param.Logging_Origin_Cms,
		param.Logging_Origin_Xrd,
		param.Logging_Origin_Ofs,
		param.Logging_Origin_Oss,
		param.Logging_Origin_Http,
		param.Logging_Cache_Ofs,
		param.Logging_Cache_Pss,
		param.Logging_Cache_PssSetOpt,
		param.Logging_Cache_Http,
		param.Logging_Cache_Xrd,
		param.Logging_Cache_Xrootd,
		param.Logging_Cache_Lotman,
	} {
		v.SetDefault(param.GetName(), defaultLevel)
	}

	// If Pelican is at its default info level, do our custom mapping
	if defaultLevel == log.InfoLevel.String() {
		v.SetDefault(param.Logging_Origin_Scitokens.GetName(), "fatal")
		v.SetDefault(param.Logging_Origin_Xrootd.GetName(), "info")
		v.SetDefault(param.Logging_Cache_Scitokens.GetName(), "fatal")
		v.SetDefault(param.Logging_Cache_Pfc.GetName(), "info")
	} else { // Otherwise treat them as any other log level
		for _, param := range []param.StringParam{
			param.Logging_Origin_Scitokens,
			param.Logging_Origin_Xrootd,
			param.Logging_Cache_Scitokens,
			param.Logging_Cache_Pfc,
		} {
			v.SetDefault(param.GetName(), defaultLevel)
		}
	}

	if IsRootExecution() {
		v.SetDefault(param.Origin_RunLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin"))
		v.SetDefault(param.Cache_RunLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "cache"))

		v.SetDefault(param.Cache_StorageLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		v.SetDefault(param.Cache_NamespaceLocation.GetName(), filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "namespace"))
		v.SetDefault(param.Cache_DataLocations.GetName(), []string{filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "data")})
		v.SetDefault(param.Cache_MetaLocations.GetName(), []string{filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "meta")})

		v.SetDefault(param.LocalCache_RunLocation.GetName(), filepath.Join(runtimeDir, "localcache"))
		v.SetDefault(param.Origin_Multiuser.GetName(), true)
		v.SetDefault(param.Origin_DbLocation.GetName(), "/var/lib/pelican/origin.sqlite")
		v.SetDefault(param.Director_GeoIPLocation.GetName(), "/var/cache/pelican/maxmind/GeoLite2-City.mmdb")
		v.SetDefault(param.Registry_DbLocation.GetName(), "/var/lib/pelican/registry.sqlite")
		v.SetDefault(param.Director_DbLocation.GetName(), "/var/lib/pelican/director.sqlite")
		v.SetDefault(param.Cache_DbLocation.GetName(), "/var/lib/pelican/cache.sqlite")
		v.SetDefault(param.Server_DbLocation.GetName(), "/var/lib/pelican/pelican.sqlite")
		// The lotman db will actually take this path and create the lot at /path/.lot/lotman_cpp.sqlite
		v.SetDefault(param.Lotman_LotHome.GetName(), "/var/lib/lotman")
		v.SetDefault(param.Monitoring_DataLocation.GetName(), "/var/lib/pelican/monitoring/data")
		v.SetDefault(param.Shoveler_QueueDirectory.GetName(), "/var/spool/pelican/shoveler/queue")
		v.SetDefault(param.Shoveler_AMQPTokenLocation.GetName(), "/etc/pelican/shoveler-token")
		v.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))
	} else {
		v.SetDefault(param.Origin_DbLocation.GetName(), filepath.Join(configDir, "origin.sqlite"))
		v.SetDefault(param.Director_GeoIPLocation.GetName(), filepath.Join(configDir, "maxmind", "GeoLite2-City.mmdb"))
		v.SetDefault(param.Registry_DbLocation.GetName(), filepath.Join(configDir, "ns-registry.sqlite"))
		v.SetDefault(param.Director_DbLocation.GetName(), filepath.Join(configDir, "director.sqlite"))
		v.SetDefault(param.Cache_DbLocation.GetName(), filepath.Join(configDir, "cache.sqlite"))
		v.SetDefault(param.Server_DbLocation.GetName(), filepath.Join(configDir, "pelican.sqlite"))
		// Lotdb will live at <configDir>/.lot/lotman_cpp.sqlite
		v.SetDefault(param.Lotman_LotHome.GetName(), configDir)
		v.SetDefault(param.Monitoring_DataLocation.GetName(), filepath.Join(configDir, "monitoring/data"))
		v.SetDefault(param.Shoveler_QueueDirectory.GetName(), filepath.Join(configDir, "shoveler/queue"))
		v.SetDefault(param.Shoveler_AMQPTokenLocation.GetName(), filepath.Join(configDir, "shoveler-token"))

		v.SetDefault(param.Cache_RunLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		v.SetDefault(param.Origin_RunLocation.GetName(), filepath.Join(runtimeDir, "origin"))

		v.SetDefault(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))

		v.SetDefault(param.Cache_StorageLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		v.SetDefault(param.Cache_NamespaceLocation.GetName(), filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "namespace"))
		v.SetDefault(param.Cache_DataLocations.GetName(), []string{filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "data")})
		v.SetDefault(param.Cache_MetaLocations.GetName(), []string{filepath.Join(v.GetString(param.Cache_StorageLocation.GetName()), "meta")})

		v.SetDefault(param.LocalCache_RunLocation.GetName(), filepath.Join(runtimeDir, "cache"))
		v.SetDefault(param.Origin_Multiuser.GetName(), false)
	}

	v.SetDefault(param.Director_EnableFederationMetadataHosting.GetName(), true)
	v.SetDefault(param.Director_CheckOriginPresence.GetName(), true)
	v.SetDefault(param.Director_CheckCachePresence.GetName(), true)

	v.SetDefault(param.Origin_EnablePublicReads.GetName(), false)
	v.SetDefault(param.Origin_EnableReads.GetName(), true)
	v.SetDefault(param.Origin_EnableWrites.GetName(), true)
	v.SetDefault(param.Origin_EnableListings.GetName(), true)
	v.SetDefault(param.Origin_EnableDirectReads.GetName(), true)
	v.SetDefault(param.Origin_EnableAtomicUploads.GetName(), false)

	v.SetDefault(param.Cache_ClientStatisticsLocation.GetName(), filepath.Join(v.GetString(param.Cache_RunLocation.GetName()), "xrootd.stats"))

	fcRunLocation := v.GetString(param.LocalCache_RunLocation.GetName())
	v.SetDefault(param.LocalCache_Socket.GetName(), filepath.Join(fcRunLocation, "cache.sock"))
	v.SetDefault(param.LocalCache_DataLocation.GetName(), filepath.Join(fcRunLocation, "cache"))

	// Set the default for Origin.UploadTempLocation
	originStorageType, err := server_structs.ParseOriginStorageType(v.GetString(param.Origin_StorageType.GetName()))
	if err != nil {
		return errors.Wrapf(err, "failed to parse Origin.StorageType: %s", v.GetString(param.Origin_StorageType.GetName()))
	}

	if originStorageType == server_structs.OriginStoragePosix {
		v.SetDefault(param.Origin_UploadTempLocation.GetName(), filepath.Join(v.GetString(param.Origin_RunLocation.GetName()), "in-progress"))
	}

	// Any platform-specific paths should go here
	err = InitServerOSDefaults(v)
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
	hostname = v.GetString(param.Server_Hostname.GetName())
	// We default to the value of Server.Hostname, which defaults to os.Hostname but can be overwritten
	v.SetDefault(param.Xrootd_Sitename.GetName(), hostname)

	v.SetDefault(param.Origin_Port.GetName(), 8443)
	v.SetDefault(param.Cache_Port.GetName(), 8442)

	xrootdPort := v.GetInt(param.Xrootd_Port.GetName())
	if !v.IsSet(param.Origin_Port.GetName()) && xrootdPort != 0 {
		v.SetDefault(param.Origin_Port.GetName(), xrootdPort)
	}
	if !v.IsSet(param.Cache_Port.GetName()) && xrootdPort != 0 {
		v.SetDefault(param.Cache_Port.GetName(), xrootdPort)
	}

	originPort := v.GetInt(param.Origin_Port.GetName())
	if originPort != 443 {
		v.SetDefault(param.Origin_Url.GetName(), fmt.Sprintf("https://%v:%v", v.GetString(param.Server_Hostname.GetName()), originPort))
	} else {
		v.SetDefault(param.Origin_Url.GetName(), fmt.Sprintf("https://%v", v.GetString(param.Server_Hostname.GetName())))
	}

	cachePort := v.GetInt(param.Cache_Port.GetName())
	if cachePort != 443 {
		v.SetDefault(param.Cache_Url.GetName(), fmt.Sprintf("https://%v:%v", v.GetString(param.Server_Hostname.GetName()), cachePort))
	} else {
		v.SetDefault(param.Cache_Url.GetName(), fmt.Sprintf("https://%v", v.GetString(param.Server_Hostname.GetName())))
	}

	webPort := v.GetInt(param.Server_WebPort.GetName())
	if webPort < 0 {
		return errors.Errorf("the Server.WebPort setting of %d is invalid; TCP ports must be greater than 0", webPort)
	}

	// Compute Server.ExternalWebUrl
	if err := ComputeExternalWebUrl(v); err != nil {
		return err
	}

	if originConcurrency := v.GetInt(param.Origin_Concurrency.GetName()); originConcurrency < 0 {
		return errors.Errorf("invalid value of '%d' for config param %s; must be greater than or equal to 0, where 0 disables the feature",
			originConcurrency, param.Origin_Concurrency.GetName())
	}
	v.SetDefault(param.Origin_ConcurrencyDegradedThreshold.GetName(), 90)
	if originConcThreshold := v.GetInt(param.Origin_ConcurrencyDegradedThreshold.GetName()); originConcThreshold < 0 || originConcThreshold > 100 {
		return errors.Errorf("invalid value of '%d' for config param %s; must be between 0 and 100",
			originConcThreshold, param.Origin_ConcurrencyDegradedThreshold.GetName())
	}

	if cacheConcurrency := v.GetInt(param.Cache_Concurrency.GetName()); cacheConcurrency < 0 {
		return errors.Errorf("invalid value of '%d' for config param %s; must be greater than or equal to 0, where 0 disables the feature",
			cacheConcurrency, param.Cache_Concurrency.GetName())
	}
	v.SetDefault(param.Cache_ConcurrencyDegradedThreshold.GetName(), 90)
	if cacheConcThreshold := v.GetInt(param.Cache_ConcurrencyDegradedThreshold.GetName()); cacheConcThreshold < 0 || cacheConcThreshold > 100 {
		return errors.Errorf("invalid value of '%d' for config param %s; must be between 0 and 100",
			cacheConcThreshold, param.Cache_ConcurrencyDegradedThreshold.GetName())
	}

	if directorStatusWeightTimeConstant := v.GetDuration(param.Director_AdaptiveSortEWMATimeConstant.GetName()); directorStatusWeightTimeConstant <= 0 {
		duration := v.GetDuration(param.Director_AdaptiveSortEWMATimeConstant.GetName())
		p := param.Director_AdaptiveSortEWMATimeConstant
		log.Warningf("Invalid value of %q for config param %s; must be greater than 0. Resetting to default", duration.String(), p.GetName())
		v.Set(p.GetName(), 5*time.Minute)
	}

	// By default, set adaptive sort truncate to the same number of servers the Director expects to send.
	// Cannot be set below 3 because Pelican clients expect to try that many servers.
	v.SetDefault(param.Director_AdaptiveSortTruncateConstant.GetName(), 6)
	if adaptiveSortTruncateConst := v.GetInt(param.Director_AdaptiveSortTruncateConstant.GetName()); adaptiveSortTruncateConst < 3 {
		log.Warningf("Invalid value of '%d' for config param %s; must be greater than or equal to 3. Resetting to default of %d",
			adaptiveSortTruncateConst, param.Director_AdaptiveSortTruncateConstant.GetName(), 6)
		v.Set(param.Director_AdaptiveSortTruncateConstant.GetName(), 6)
	}

	v.SetDefault(param.Monitoring_DataRetentionSize.GetName(), "0B")

	// Setup the audience to use.  We may customize the Origin.URL in the future if it has
	// a `0` for the port number; to make the audience predictable (it goes into the xrootd
	// configuration but we don't know the origin's port until after xrootd has started), we
	// stash a copy of its value now.
	v.SetDefault(param.Origin_TokenAudience.GetName(), v.GetString(param.Origin_Url.GetName()))

	// Set defaults for Director and Registry URLs only if the Discovery URL is not set.
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
		v.SetDefault("Federation_DirectorUrl", v.GetString(param.Server_ExternalWebUrl.GetName()))
	}

	return err
}

// Initialize Pelican server instance. Pass a bit mask of `currentServers` if you want to enable multiple services.
// Note not all configurations are supported: currently, if you enable both cache and origin then an error
// is thrown
func InitServer(ctx context.Context, currentServers server_structs.ServerType) error {
	InitConfigInternal(log.InfoLevel)

	// Bind any legacy env vars to their new config params -- will generate warnings about deprecated env vars
	bindLegacyServerEnv()

	setEnabledServer(currentServers)

	// Output warnings before the defaults are set. The SetServerDefaults function sets the default values
	// of Origin.StorageType to "posix" and Origin.SelfTest to true. After these defaults are applied,
	// it becomes impossible to determine if the values are coming from the default settings or from user input.
	if currentServers.IsEnabled(server_structs.OriginType) && param.Origin_StorageType.GetString() != "posix" {
		updates := make(map[string]interface{})
		if param.Origin_SelfTest.GetBool() {
			log.Warning("Origin.SelfTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
			updates[param.Origin_SelfTest.GetName()] = false
		}
		if param.Origin_DirectorTest.GetBool() {
			log.Warning("Origin.DirectorTest may not be enabled when the origin is configured with non-posix backends. Turning off...")
			updates[param.Origin_DirectorTest.GetName()] = false
		}
		if len(updates) > 0 {
			if err := param.MultiSet(updates); err != nil {
				logging.FlushLogs(true)
				return err
			}
		}
	}

	if err := SetServerDefaults(viper.GetViper()); err != nil {
		logging.FlushLogs(true)
		return err
	}
	if _, err := param.Refresh(); err != nil {
		logging.FlushLogs(true)
		return err
	}

	webConfigPath := param.Server_WebConfigFile.GetString()
	if webConfigPath != "" {
		if err := os.MkdirAll(filepath.Dir(webConfigPath), 0700); err != nil {
			logging.FlushLogs(true)
			cobra.CheckErr(errors.Wrapf(err, "failed to create directory for web config file at %s", webConfigPath))
		}
	}
	if err := setWebConfigOverride(viper.GetViper(), webConfigPath); err != nil {
		logging.FlushLogs(true)
		cobra.CheckErr(errors.Wrapf(err, "failed to override configuration based on changes from web UI"))
	}

	// Flush logs only after we potentially ingest changes from the web UI. This must
	// be done in sequence because the web UI may change the log location.
	logging.FlushLogs(true)

	runtimeDir, cleanupRuntimeDir, err := ensureRuntimeDir(viper.GetViper())
	if err != nil {
		return err
	}

	if !IsRootExecution() {
		if err := os.MkdirAll(runtimeDir, 0750); err != nil {
			return err
		}
		if cleanupRuntimeDir {
			cleanupDirOnShutdown(ctx, runtimeDir)
		}
		if !param.Cache_RunLocation.IsSet() && !param.Origin_RunLocation.IsSet() && param.Xrootd_RunLocation.IsSet() {
			return errors.New("Xrootd.RunLocation is set, but both modules are enabled. Please set Cache.RunLocation and Origin.RunLocation or disable Xrootd.RunLocation so the default location can be used.")
		}
	} else if param.Server_DropPrivileges.GetBool() {
		puser, err := GetPelicanUser()
		if err != nil {
			return errors.Wrapf(err, "set to drop privileges but no target OS username found for %s", param.Server_UnprivilegedUser.GetString())
		}
		// Set up the directories for the server to run as a non-root user;
		// for the most part, we need to recursively chown and chmod the directory
		// so either root or pelican can access it.
		pelicanLocationsNoRecursive := []string{
			param.Server_DbLocation.GetString(),
		}
		if (currentServers.IsEnabled(server_structs.OriginType) || currentServers.IsEnabled(server_structs.CacheType)) && param.Shoveler_Enable.GetBool() {
			pelicanLocationsNoRecursive = append(pelicanLocationsNoRecursive, param.Shoveler_AMQPTokenLocation.GetString())
		}
		if currentServers.IsEnabled(server_structs.CacheType) {
			tokLoc := param.Cache_FedTokenLocation.GetString()
			tokDir := filepath.Dir(tokLoc)
			dir := filepath.Dir(tokDir)
			tempTokDir := filepath.Join(dir, "fed-token-temp")
			pelicanLocationsNoRecursive = append(pelicanLocationsNoRecursive, tempTokDir)
		}
		if err = setFileAndDirPerms(pelicanLocationsNoRecursive, 0750, 0640, puser.Uid, 0, false); err != nil {
			return errors.Wrap(err, "failure when setting up the file permissions for pelican")
		}

		pelicanLocationsSingleFiles := []string{
			param.Server_UIPasswordFile.GetString(),
			param.IssuerKey.GetString(), // Backward compatibility for legacy key file
		}
		if err = setFilePerms(pelicanLocationsSingleFiles, 0640, puser.Uid, 0); err != nil {
			return errors.Wrap(err, "failure when setting up the file permissions for pelican")
		}

		pelicanDirs := []string{
			param.Monitoring_DataLocation.GetString(),
			param.IssuerKeysDirectory.GetString(),
		}
		if currentServers.IsEnabled(server_structs.LocalCacheType) {
			pelicanDirs = append(pelicanDirs, param.LocalCache_RunLocation.GetString())
		}
		if currentServers.IsEnabled(server_structs.CacheType) && param.Cache_EnableLotman.GetBool() {
			pelicanDirs = append(pelicanDirs, param.Lotman_LotHome.GetString())
		}
		if (currentServers.IsEnabled(server_structs.OriginType) || currentServers.IsEnabled(server_structs.CacheType)) && param.Shoveler_Enable.GetBool() {
			pelicanDirs = append(pelicanDirs, param.Shoveler_QueueDirectory.GetString())
		}
		// Note: Origin_GlobusConfigLocation is intentionally NOT added here.
		// It's under Origin_RunLocation (e.g. /run/pelican/xrootd/origin/) which should be owned by xrootd, not pelican.
		// InitGlobusBackend() handles creating and chowning the Globus directories properly.
		if err = setDirPerms(pelicanDirs, 0750, 0640, puser.Uid, puser.Gid, true); err != nil {
			return errors.Wrap(err, "failure when setting up the directory permissions for pelican")
		}
	}

	user, err := GetPelicanUser()
	if err != nil {
		return errors.Wrap(err, "no OS user found for pelican")
	}
	if err := MkdirAll(param.Monitoring_DataLocation.GetString(), 0750, user.Uid, user.Gid); err != nil {
		return errors.Wrapf(err, "failure when creating a directory for the monitoring data")
	}

	if currentServers.IsEnabled(server_structs.OriginType) || currentServers.IsEnabled(server_structs.CacheType) {
		if err := MkdirAll(param.Shoveler_QueueDirectory.GetString(), 0750, user.Uid, user.Gid); err != nil {
			return errors.Wrapf(err, "failure when creating a directory for the shoveler on-disk queue")
		}
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
			pvd, err := GetOIDCProvider()
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
		lowWm, lwmIsAbs, err := utils.ValidateWatermark(param.Cache_LowWatermark.GetName(), false)
		if err != nil {
			return err
		}
		highWm, hwmIsAbs, err := utils.ValidateWatermark(param.Cache_HighWaterMark.GetName(), false)
		if err != nil {
			return err
		}
		if lwmIsAbs == hwmIsAbs && lowWm >= highWm {
			// Use config strings in error to present the configured values (as opposed to whatever conversion we get from validation)
			return errors.Errorf("invalid Cache.HighWaterMark/LowWaterMark values. The high watermark must be greater than the low "+
				"watermark. Got %s (low) and %s (high)", param.Cache_LowWatermark.GetString(), param.Cache_HighWaterMark.GetString())
		}
	}

	if param.Cache_FilesBaseSize.IsSet() || param.Cache_FilesNominalSize.IsSet() || param.Cache_FilesMaxSize.IsSet() {
		// Must have high/low watermarks
		if !param.Cache_LowWatermark.IsSet() || !param.Cache_HighWaterMark.IsSet() {
			return errors.New("If any of Cache parameters 'FilesBaseSize', 'FilesNominalSize', or 'FilesMaxSize' is set, then Cache.LowWatermark " +
				"and Cache.HighWatermark must also be set")
		}

		// Further, if one is set, all three must be set
		if !param.Cache_FilesBaseSize.IsSet() || !param.Cache_FilesNominalSize.IsSet() || !param.Cache_FilesMaxSize.IsSet() {
			return errors.New("If any of Cache parameters 'FilesBaseSize', 'FilesNominalSize', or 'FilesMaxSize' is set, all three must be set")
		}

		var base, nominal, max float64
		var err error
		// Watermark validation will error if these parameters are not absolute, so we can ignore that output
		if base, _, err = utils.ValidateWatermark(param.Cache_FilesBaseSize.GetName(), true); err != nil {
			return err
		}
		if nominal, _, err = utils.ValidateWatermark(param.Cache_FilesNominalSize.GetName(), true); err != nil {
			return err
		}
		if max, _, err = utils.ValidateWatermark(param.Cache_FilesMaxSize.GetName(), true); err != nil {
			return err
		}
		if base >= nominal || nominal >= max {
			return errors.Errorf("invalid Cache.FilesBaseSize/FilesNominalSize/FilesMaxSize values. The base size must be less than the "+
				"nominal size, and the nominal size must be less than the max size. Got %s (base), %s (nominal), and %s (max)",
				param.Cache_FilesBaseSize.GetString(), param.Cache_FilesNominalSize.GetString(), param.Cache_FilesMaxSize.GetString())
		}

		// File sizes must also be less than the low watermark, but that's not straightforward to check, especially when the cache spread across
		// multiple disks and the low watermark is configured as a relative value. If such bad config is passed, xrootd will fail to startup with
		// a message about what to do, and as much as I'd like to handle that early, I'll leave it to xrootd for now.
	}
	if param.Cache_EnableLotman.GetBool() {
		// pfc.diskusage file directives _must_ be set.
		// We already validate that one means all three, but I'm duplicating that here to make this safer in the case we switch orders
		// in the future.
		if !param.Cache_FilesBaseSize.IsSet() || !param.Cache_FilesNominalSize.IsSet() || !param.Cache_FilesMaxSize.IsSet() ||
			!param.Cache_LowWatermark.IsSet() || !param.Cache_HighWaterMark.IsSet() {
			return errors.New("If Cache.EnableLotman is true, the following Cache parameters must also be set: HighWaterMark, LowWaterMark, " +
				"FilesBaseSize, FilesNominalSize, FilesMaxSize")
		}
	}

	if currentServers.IsEnabled(server_structs.DirectorType) {
		refreshInterval := param.Director_RegistryQueryInterval.GetDuration()
		if refreshInterval < 1*time.Second {
			log.Warnf("Director.RegistryQueryInterval is set to: %v, which is too low. Falling back to default: 1m", refreshInterval)
			if err := param.Set(param.Director_RegistryQueryInterval.GetName(), "1m"); err != nil {
				return err
			}
		}

		if adTTL := param.Director_AdvertisementTTL.GetDuration(); adTTL <= 0 {
			log.Warningf("Invalid value of %q for config param %s; must be greater than 0, falling back to default of 15 minutes",
				adTTL, param.Director_AdvertisementTTL.GetName())
			if err := param.Set(param.Director_AdvertisementTTL.GetName(), "15m"); err != nil {
				return err
			}
		}

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
			if err := param.Set(param.Director_CacheSortMethod.GetName(), server_structs.DistanceType); err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("invalid Director.CacheSortMethod. Must be one of %q, %q, %q, or %q, but you configured %q.",
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
		if err := param.MultiSet(map[string]interface{}{
			param.Monitoring_TokenRefreshInterval.GetName(): time.Minute * 5,
			param.Monitoring_TokenExpiresIn.GetName():       time.Hour * 1,
		}); err != nil {
			return err
		}
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

	// Fallback `SelfTestInterval` to 15 seconds, if user sets a very small value
	if currentServers.IsEnabled(server_structs.OriginType) {
		if param.Origin_SelfTestInterval.GetDuration() < 1*time.Second {
			if err := param.Set(param.Origin_SelfTestInterval.GetName(), "15s"); err != nil {
				return err
			}
			log.Warningf("Invalid %s value of %s. Falling back to 15s", param.Origin_SelfTestInterval.GetName(), param.Origin_SelfTestInterval.GetDuration().String())
		}
	}
	if currentServers.IsEnabled(server_structs.CacheType) {
		if param.Cache_SelfTestInterval.GetDuration() < 1*time.Second {
			if err := param.Set(param.Cache_SelfTestInterval.GetName(), "15s"); err != nil {
				return err
			}
			log.Warningf("Invalid %s value of %s. Falling back to 15s", param.Cache_SelfTestInterval.GetName(), param.Cache_SelfTestInterval.GetDuration().String())
		}
	}

	// Unmarshal Viper config into a Go struct
	unmarshalledConfig, err := param.UnmarshalConfig()
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Reset IssuerKeys to ensure test cases can use their own temp IssuerKeysDirectory
	ResetIssuerPrivateKeys()

	// As necessary, generate private keys, JWKS and corresponding certs

	// Note: This function will generate a private key in the location stored by the viper var "IssuerKeysDirectory"
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

	// When drop privileges is enabled, ensure the pelican user can read TLS credentials.
	// XRootD does not need direct access to these files as Pelican copies them to a runtime location.
	if param.Server_DropPrivileges.GetBool() {
		if err = CheckTLSCredsForDropPrivileges(); err != nil {
			return err
		}
	}

	// The certificate was either generated or has been provided by now. Verify that any configured
	// hostnames are valid w.r.t the given certificate.
	//
	// We'll always check both Server.Hostname, Server.ExternalWebUrl because we don't enforce that
	// these point to the same hostname (maybe we should?), and we'll conditionally check
	// Origin.Url/Cache.Url, depending on whether the origin/cache servers are enabled.
	// See https://github.com/PelicanPlatform/pelican/issues/1802 for a description of why we check
	// these particular hostnames.
	if param.Server_Hostname.IsSet() {
		serverHostname := param.Server_Hostname.GetString()
		if err := ValidateHostCertificateHostname(serverHostname); err != nil {
			return errors.Wrapf(err, "unable to validate server hostname %q configured via %s against the TLS certificate"+
				" configured via %s",
				serverHostname, param.Server_Hostname.GetName(), param.Server_TLSCertificateChain.GetName())
		}
	}

	// Helper func to deal with params that may include ports, which must be parsed so
	// we can grab only the hostname
	validateUrlHostname := func(urlParam param.StringParam) error {
		urlStr := urlParam.GetString()
		parsed, err := url.Parse(urlStr)
		if err != nil {
			return errors.Wrapf(err, "unable to parse %s as a URL", urlParam.GetName())
		} else if parsed == nil {
			return errors.New(fmt.Sprintf("the url configured via %s was parsed as nil; is it set?", urlParam.GetName()))
		}

		if err := ValidateHostCertificateHostname(parsed.Hostname()); err != nil {
			return errors.Wrapf(err, "unable to validate hostname %q configured via %s against the TLS certificate"+
				" configured via %s",
				parsed.Hostname(), urlParam.GetName(), param.Server_TLSCertificateChain.GetName())
		}
		return nil
	}

	if param.Server_ExternalWebUrl.IsSet() {
		if err = validateUrlHostname(param.Server_ExternalWebUrl); err != nil {
			return err
		}
	}

	// While I (Justin) cannot currently fathom a situation where the hostname of the Cache.Url
	// or Origin.Url would not match either the Server.Hostname or the Server.ExternalWebUrl,
	// we still validate them just in case.
	if currentServers.IsEnabled(server_structs.CacheType) && param.Cache_Url.IsSet() {
		if err = validateUrlHostname(param.Cache_Url); err != nil {
			return err
		}
	}
	if currentServers.IsEnabled(server_structs.OriginType) && param.Origin_Url.IsSet() {
		if err = validateUrlHostname(param.Origin_Url); err != nil {
			return err
		}
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

	// Set up the log filter mechanisms, e.g., for sensitive secrets
	initFilterLogging()

	// Register callback for runtime log level changes
	RegisterLoggingCallback()

	// Sets (or resets) the federation info. Unlike in clients, we do this at startup
	// instead of deferring it.
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

// Set all defaults relevant to the client but only for the passed viper instance.
// We operate on the passed viper instance instead of the global because it lets us
// construct two config instances for comparing defaults and overrides in the config
// tool. As such, you SHOULD NOT do a `viper.Set()` or a `param.<some param>.Get*()`
// here as part of the logic for setting defaults on the passed `v` because you'll be
// operating on two different config structs!
func SetClientDefaults(v *viper.Viper) error {
	configDir := v.GetString("ConfigDir")

	// Duplicate setting a default logging level so that this function picks picks up
	// the one case where we need to set client/server defaults differently directly in
	// InitConfigInternal. We need to do that because internal logging levels are set by
	// InitServer/InitClient before we call SetClientDefaults/SetServerDefaults.
	v.SetDefault(param.Logging_Level.GetName(), "warn")
	v.SetDefault(param.IssuerKey.GetName(), filepath.Join(configDir, "issuer.jwk"))
	v.SetDefault(param.IssuerKeysDirectory.GetName(), filepath.Join(configDir, "issuer-keys"))

	upperPrefix := GetPreferredPrefix()
	if upperPrefix == OsdfPrefix || upperPrefix == StashPrefix {
		v.SetDefault("Federation.TopologyNamespaceURL", "https://topology.opensciencegrid.org/osdf/namespaces")
	}
	// Set our default worker count
	v.SetDefault(param.Client_WorkerCount.GetName(), 5)
	v.SetDefault(param.Server_TLSCACertificateFile.GetName(), filepath.Join(configDir, "certificates", "tlsca.pem"))

	// Default is set outside of defaults.yaml to allow SetDefault call below to override
	v.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), 102400)
	if v.IsSet(param.MinimumDownloadSpeed.GetName()) {
		v.SetDefault(param.Client_MinimumDownloadSpeed.GetName(), v.GetInt(param.MinimumDownloadSpeed.GetName()))
	}
	// Some client actions may take different defaults depending on whether we detect the plugin
	v.SetDefault(param.Client_IsPlugin.GetName(), false)
	v.SetDefault(param.Client_DirectorRetries.GetName(), 5)
	if v.GetBool(param.Client_IsPlugin.GetName()) {
		// If we _are_ the plugin, be more aggressive about retries
		v.Set(param.Client_DirectorRetries.GetName(), 2*v.GetInt(param.Client_DirectorRetries.GetName()))
	}

	if v.GetInt(param.Client_DirectorRetries.GetName()) < 1 {
		log.Warningf("Client.DirectorRetries was set to %d, but it must be at least 1. Falling back to default of 5.", param.Client_DirectorRetries.GetInt())
		v.Set(param.Client_DirectorRetries.GetName(), 5)
	}

	return nil
}

func InitClient() error {
	InitConfigInternal(log.WarnLevel)
	logging.FlushLogs(true)

	// Bind legacy client environment variables (e.g., STASHCP_*, OSG_*, NEAREST_CACHE)
	// This must happen after InitConfigInternal but before SetClientDefaults
	bindLegacyClientEnv()

	// Bind configuration from HTCondor job ClassAd (e.g., PelicanCfg_* attributes)
	// This should happen after legacy env binding but before SetClientDefaults
	bindClassAdConfig()

	if err := SetClientDefaults(viper.GetViper()); err != nil {
		return err
	}

	// Compute Server.ExternalWebUrl so client commands can access it if needed
	// (e.g., for server management commands like set-logging-level)
	if err := ComputeExternalWebUrl(viper.GetViper()); err != nil {
		log.Debugln("Failed to compute Server.ExternalWebUrl:", err)
	}

	setupTransport()

	// Unmarshal Viper config into a Go struct
	unmarshalledConfig, err := param.UnmarshalConfig()
	if err != nil || unmarshalledConfig == nil {
		return err
	}

	// Set (or reset) the deferred federation lookup
	fedDiscoveryOnce = &sync.Once{}

	// Set up the log filter mechanisms, e.g., for sensitive secrets
	initFilterLogging()

	clientInitialized = true

	var printClientConfigErr error
	printClientConfigOnce.Do(func() {
		if GetEffectiveLogLevel() >= log.DebugLevel {
			LogPelicanVersion()
			printClientConfigErr = PrintClientConfig()
		}
	})

	// Return any error encountered during PrintClientConfig
	if printClientConfigErr != nil {
		return printClientConfigErr
	}

	return nil
}

// Clear all in-memory server ads in the Director. It delegates the call to the registered callback.
// The real implementation is in the Director package. This design is to avoid circular dependencies.
func ClearServerAds() {
	if ClearServerAdsCallback != nil {
		ClearServerAdsCallback()
	} else {
		log.Info("Unable to clear server ads: no callback registered")
	}
}

// This function resets most states for test cases, including 1. viper settings, 2. preferred prefix, 3. transport object, 4. Federation metadata back to their default
func ResetConfig() {
	// Close any open log files and reset logger output
	logging.CloseLogger()
	if err := param.Reset(); err != nil {
		log.WithError(err).Warn("Failed to reset configuration")
	}

	// Clear cached preferred prefix
	testingPreferredPrefix = ""
	logging.ResetLogFlush()

	// Clear cached transport object
	onceTransport = sync.Once{}
	transport = nil
	basicTransport = nil

	// Clear the instance ID information for generated server ads
	server_structs.Reset()

	// Clear out director's ad cache
	ClearServerAds()

	// Reset federation metadata
	fedDiscoveryOnce = &sync.Once{}
	globalFedInfo.Store(&pelican_url.FederationDiscovery{})
	globalFedErr = nil

	warnDeprecatedOnce = sync.Once{}
	warnDebugOnce = sync.Once{}

	setServerOnce = sync.Once{}

	ResetIssuerPrivateKeys()

	ResetClientInitialized()

	// There are other test state resets in server_utils.ResetTestState()
}
