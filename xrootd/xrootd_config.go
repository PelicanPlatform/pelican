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

package xrootd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	builtin_errors "errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	//go:embed resources/xrootd-origin.cfg
	xrootdOriginCfg string
	//go:embed resources/xrootd-cache.cfg
	xrootdCacheCfg string
	//go:embed resources/robots.txt
	robotsTxt string

	errBadKeyPair error = errors.New("Bad X509 keypair")
)

const (
	clientPluginDefault = `
url = pelican://*
lib = libXrdClPelican.so
enable = true
`

	clientPluginMac = `
url = pelican://*
lib = libXrdClPelican.dylib
enable = true
`
)

type (
	OriginConfig struct {
		Multiuser         bool
		EnableCmsd        bool
		EnableMacaroons   bool
		EnableVoms        bool
		EnablePublicReads bool
		EnableListings    bool
		SelfTest          bool
		CalculatedPort    string
		FederationPrefix  string
		HttpServiceUrl    string
		HttpAuthTokenFile string
		XRootServiceUrl   string
		RunLocation       string
		StorageType       string

		// S3 specific options that are kept top-level because
		// they aren't specific to each export
		S3Region     string
		S3ServiceUrl string
		S3UrlStyle   string
		Exports      []server_utils.OriginExport
	}

	CacheConfig struct {
		UseCmsd        bool
		EnableVoms     bool
		CalculatedPort string
		HighWaterMark  string
		LowWatermark   string
		ExportLocation string
		RunLocation    string
		DataLocations  []string
		MetaLocations  []string
		LocalRoot      string
		PSSOrigin      string
		Concurrency    int
	}

	XrootdOptions struct {
		Port                   int
		ManagerHost            string
		ManagerPort            string
		ConfigFile             string
		MacaroonsKeyFile       string
		RobotsTxtFile          string
		Sitename               string
		SummaryMonitoringHost  string
		SummaryMonitoringPort  int
		DetailedMonitoringHost string
		DetailedMonitoringPort int
		Authfile               string
		AuthRefreshInterval    int // In the raw config we use a duration, but Xrootd needs this as a seconds integer. Conversion happens during the unmarshal
		ScitokensConfig        string
		Mount                  string
		LocalMonitoringPort    int
	}

	ServerConfig struct {
		TLSCertificate            string
		TLSKey                    string
		TLSCACertificateDirectory string
		TLSCACertificateFile      string
	}

	LoggingConfig struct {
		OriginCms       string
		OriginHttp      string
		OriginOfs       string
		OriginOss       string
		OriginScitokens string
		OriginXrd       string
		OriginXrootd    string
		CacheHttp       string
		CacheOfs        string
		CachePfc        string
		CachePss        string
		PssSetOptCache  string
		CacheScitokens  string
		CacheXrd        string
		CacheXrootd     string
	}

	XrootdConfig struct {
		Server  ServerConfig
		Origin  OriginConfig
		Xrootd  XrootdOptions
		Cache   CacheConfig
		Logging LoggingConfig
	}

	loggingMap struct {
		Trace string
		Debug string
		Info  string
		Warn  string
		Error string
		Fatal string
		Panic string
	}
)

// CheckOriginXrootdEnv is almost a misnomer -- it does both checking and configuring. In partcicular,
// it is responsible for setting up the exports and handling all the symlinking we use
// to export our directories.
func CheckOriginXrootdEnv(exportPath string, server server_structs.XRootDServer, uid int, gid int, groupname string) error {
	// First we check if our config yaml contains the Exports block. If it does, we use that instead of the older legacy
	// options for all this configuration
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}

	backendType, err := server_utils.ParseOriginStorageType(param.Origin_StorageType.GetString())
	if err != nil {
		return err
	}
	if backendType == server_utils.OriginStoragePosix {
		// For each export, we symlink the exported directory, currently at /var/run/pelican/export/<export.FederationPrefix>,
		// to the actual data source, which is what we get from the Export object's StoragePrefix
		for _, export := range originExports {
			destPath := path.Clean(filepath.Join(exportPath, export.FederationPrefix))
			err := config.MkdirAll(filepath.Dir(destPath), 0755, uid, gid)
			if err != nil {
				return errors.Wrapf(err, "Unable to create export directory %v",
					filepath.Dir(destPath))
			}

			err = os.Symlink(export.StoragePrefix, destPath)
			if err != nil {
				return errors.Wrapf(err, "Failed to create export symlink of %v to %v", export.StoragePrefix, destPath)
			}
		}
		// Set the mount to our export path now that everything is symlinked
		viper.Set("Xrootd.Mount", exportPath)
	}

	if param.Origin_SelfTest.GetBool() {
		if err := origin.ConfigureXrootdMonitoringDir(); err != nil {
			return err
		}
	}
	// If macaroons secret does not exist, create one
	macaroonsSecret := param.Xrootd_MacaroonsKeyFile.GetString()
	if _, err := os.Open(macaroonsSecret); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = config.MkdirAll(path.Dir(macaroonsSecret), 0755, -1, gid)
			if err != nil {
				return errors.Wrapf(err, "Unable to create directory %v",
					path.Dir(macaroonsSecret))
			}
			file, err := os.OpenFile(macaroonsSecret, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
			if err != nil {
				return errors.Wrap(err, "Failed to create a new macaroons key")
			}
			defer file.Close()
			buf := make([]byte, 64)
			_, err = rand.Read(buf)
			if err != nil {
				return err
			}
			encoded := base64.StdEncoding.EncodeToString(buf) + "\n"
			if _, err = file.WriteString(encoded); err != nil {
				return errors.Wrap(err, "Failed to write out a macaroons key")
			}
		} else {
			return err
		}
	}
	if err := os.Chown(macaroonsSecret, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of macaroons secret %v"+
			" to desired daemon group %v", macaroonsSecret, groupname)
	}
	// If the scitokens.cfg does not exist, create one
	if originServer, ok := server.(*origin.OriginServer); ok {
		authedPrefixes, err := originServer.GetAuthorizedPrefixes()
		if err != nil {
			return err
		}
		err = WriteOriginScitokensConfig(authedPrefixes)
		if err != nil {
			return err
		}
	}
	if err := origin.ConfigureXrootdMonitoringDir(); err != nil {
		return err
	}

	return nil
}

func CheckCacheXrootdEnv(exportPath string, server server_structs.XRootDServer, uid int, gid int) (string, error) {
	viper.Set("Xrootd.Mount", exportPath)
	filepath.Join(exportPath, "/")
	err := config.MkdirAll(exportPath, 0775, uid, gid)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to create export directory %v",
			filepath.Dir(exportPath))
	}

	localRoot := param.Cache_LocalRoot.GetString()

	localRoot = filepath.Clean(localRoot)
	err = config.MkdirAll(localRoot, 0775, uid, gid)

	if err != nil {
		return "", errors.Wrapf(err, "Unable to create local root %v",
			filepath.Dir(localRoot))
	}

	dataPaths := param.Cache_DataLocations.GetStringSlice()
	for _, dPath := range dataPaths {
		dataPath := filepath.Clean(dPath)
		err = config.MkdirAll(dataPath, 0775, uid, gid)

		if err != nil {
			return "", errors.Wrapf(err, "Unable to create data directory %v",
				filepath.Dir(dataPath))
		}
	}

	metaPaths := param.Cache_MetaLocations.GetStringSlice()
	for _, mPath := range metaPaths {
		metaPath := filepath.Clean(mPath)
		err = config.MkdirAll(metaPath, 0775, uid, gid)

		if err != nil {
			return "", errors.Wrapf(err, "Unable to create meta directory %v",
				filepath.Dir(metaPath))
		}
	}

	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return "", errors.Wrap(err, "Failed to pull information from the federation")
	}

	if discoveryUrlStr := param.Federation_DiscoveryUrl.GetString(); discoveryUrlStr != "" {
		discoveryUrl, err := url.Parse(discoveryUrlStr)
		if err == nil {
			log.Debugln("Parsing discovery URL for 'pss.origin' setting:", discoveryUrlStr)
			if len(discoveryUrl.Path) > 0 && len(discoveryUrl.Host) == 0 {
				discoveryUrl.Host = discoveryUrl.Path
				discoveryUrl.Path = ""
			} else if discoveryUrl.Path != "" && discoveryUrl.Path != "/" {
				return "", errors.New("The Federation.DiscoveryUrl's path is non-empty, ensure the Federation.DiscoveryUrl has the format <host>:<port>")
			}
			discoveryUrl.Scheme = "pelican"
			discoveryUrl.Path = ""
			discoveryUrl.RawQuery = ""
			viper.Set("Cache.PSSOrigin", discoveryUrl.String())
		} else {
			return "", errors.Wrapf(err, "Failed to parse discovery URL %s", discoveryUrlStr)
		}
	}

	if directorUrlStr := fedInfo.DirectorEndpoint; directorUrlStr != "" {
		directorUrl, err := url.Parse(directorUrlStr)
		if err == nil {
			log.Debugln("Parsing director URL for 'pss.origin' setting:", directorUrlStr)
			if directorUrl.Path != "" && directorUrl.Path != "/" {
				return "", errors.New("The Federation.DirectorUrl's path is non-empty, ensure the Federation.DirectorUrl has the format <host>:<port>")
			}
			directorUrl.Scheme = "pelican"
			viper.Set("Cache.PSSOrigin", directorUrl.String())
		} else {
			return "", errors.Wrapf(err, "Failed to parse director URL %s", directorUrlStr)
		}
	}

	if viper.GetString("Cache.PSSOrigin") == "" {
		return "", errors.New("One of Federation.DiscoveryUrl or Federation.DirectorUrl must be set to configure a cache")
	}

	if cacheServer, ok := server.(*cache.CacheServer); ok {
		err := WriteCacheScitokensConfig(cacheServer.GetNamespaceAds())
		if err != nil {
			return "", errors.Wrap(err, "Failed to create scitokens configuration for the cache")
		}
	}

	return exportPath, nil
}

func CheckXrootdEnv(server server_structs.XRootDServer) error {
	uid, err := config.GetDaemonUID()
	if err != nil {
		return err
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}
	username, err := config.GetDaemonUser()
	if err != nil {
		return err
	}
	groupname, err := config.GetDaemonGroup()
	if err != nil {
		return err
	}

	// Ensure the runtime directory exists
	runtimeDir := param.Origin_RunLocation.GetString()
	if server.GetServerType().IsEnabled(config.CacheType) {
		runtimeDir = param.Cache_RunLocation.GetString()
	}

	err = config.MkdirAll(runtimeDir, 0755, uid, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create runtime directory %v", runtimeDir)
	}
	if err = os.Chown(runtimeDir, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of runtime directory %v"+
			" to desired daemon user %v", runtimeDir, username)
	}

	// The scitokens library will write its JWKS cache into the user's home direct by
	// default.  By setting $XDG_CACHE_HOME, we move the JWKS cache into our runtime dir.
	// This makes the Pelican instance more self-contained inside the runtime dir -- and two
	// Pelican instances (such as parallel unit tests) don't end up sharing the JWKS caches,
	// or sharing JWKS caches between test runs
	cacheDir := filepath.Join(runtimeDir, "jwksCache")
	if err = config.MkdirAll(cacheDir, 0700, uid, gid); err != nil {
		return errors.Wrapf(err, "Unable to create cache directory %v", cacheDir)
	}
	if err = os.Chown(cacheDir, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of the cache directory %v"+
			" to desired daemon user %v", cacheDir, username)
	}
	if err = os.Setenv("XDG_CACHE_HOME", cacheDir); err != nil {
		return errors.Wrap(err, "Unable to set $XDG_CACHE_HOME for scitokens library")
	}

	if server.GetServerType().IsEnabled(config.CacheType) {
		clientPluginsDir := filepath.Join(runtimeDir, "cache-client.plugins.d")
		if err = os.MkdirAll(clientPluginsDir, os.FileMode(0755)); err != nil {
			return errors.Wrap(err, "Unable to create cache client plugins directory")
		}
		if runtime.GOOS == "darwin" {
			err = os.WriteFile(filepath.Join(clientPluginsDir, "pelican-plugin.conf"), []byte(clientPluginMac), os.FileMode(0644))
		} else {
			err = os.WriteFile(filepath.Join(clientPluginsDir, "pelican-plugin.conf"), []byte(clientPluginDefault), os.FileMode(0644))
		}
		if err != nil {
			return errors.Wrap(err, "Unable to configure cache client plugin")
		}
	}

	exportPath := filepath.Join(runtimeDir, "export")
	if _, err := os.Stat(exportPath); err == nil {
		if err = os.RemoveAll(exportPath); err != nil {
			return errors.Wrap(err, "Failure when cleaning up temporary export tree")
		}
	}

	if err = CopyXrootdCertificates(server); err != nil {
		return err
	}

	if server.GetServerType().IsEnabled(config.OriginType) {
		err = CheckOriginXrootdEnv(exportPath, server, uid, gid, groupname)
	} else {
		exportPath, err = CheckCacheXrootdEnv(exportPath, server, uid, gid)
	}
	if err != nil {
		return err
	}

	xServerUrl := param.Origin_Url.GetString()
	if server.GetServerType().IsEnabled(config.CacheType) {
		xServerUrl = param.Cache_Url.GetString()
	}
	if err = EmitIssuerMetadata(exportPath, xServerUrl); err != nil {
		return err
	}

	// If no robots.txt, create a ephemeral one for xrootd to use
	robotsTxtFile := param.Xrootd_RobotsTxtFile.GetString()
	if _, err := os.Open(robotsTxtFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			newPath := filepath.Join(runtimeDir, "robots.txt")
			err = config.MkdirAll(path.Dir(newPath), 0755, -1, gid)
			if err != nil {
				return errors.Wrapf(err, "Unable to create directory %v",
					path.Dir(newPath))
			}
			file, err := os.OpenFile(newPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return errors.Wrap(err, "Failed to create a default robots.txt file")
			}
			defer file.Close()
			if _, err := file.WriteString(robotsTxt); err != nil {
				return errors.Wrap(err, "Failed to write out a default robots.txt file")
			}
			viper.Set("Xrootd.RobotsTxtFile", newPath)
		} else {
			return err
		}
	}

	// If the authfile does not exist, create one.
	authfile := param.Xrootd_Authfile.GetString()
	err = config.MkdirAll(path.Dir(authfile), 0755, -1, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create directory %v",
			path.Dir(authfile))
	}
	// For user-provided authfile, we don't chmod to daemon group as EmitAuthfile will
	// make a copy of it and save it to xrootd run location
	if file, err := os.OpenFile(authfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := EmitAuthfile(server); err != nil {
		return err
	}

	return nil
}

// Copies the server certificate/key files into the XRootD runtime
// directory.  Combines the two files into a single one so the new
// certificate shows up atomically from XRootD's perspective.
// Adjusts the ownership and mode to match that expected
// by the XRootD framework.
func CopyXrootdCertificates(server server_structs.XRootDServer) error {
	user, err := config.GetDaemonUserInfo()
	if err != nil {
		return errors.Wrap(err, "Unable to copy certificates to xrootd runtime directory; failed xrootd user lookup")
	}

	certFile := param.Server_TLSCertificate.GetString()
	certKey := param.Server_TLSKey.GetString()
	if _, err = tls.LoadX509KeyPair(certFile, certKey); err != nil {
		return builtin_errors.Join(err, errBadKeyPair)
	}

	destination := filepath.Join(param.Origin_RunLocation.GetString(), "copied-tls-creds.crt")
	if server.GetServerType().IsEnabled(config.CacheType) {
		destination = filepath.Join(param.Cache_RunLocation.GetString(), "copied-tls-creds.crt")
	}
	tmpName := destination + ".tmp"
	destFile, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(0400))
	if err != nil {
		return errors.Wrap(err, "Failure when opening temporary certificate key pair file for xrootd")
	}
	defer destFile.Close()

	if err = os.Chown(tmpName, user.Uid, user.Gid); err != nil {
		return errors.Wrap(err, "Failure when chown'ing certificate key pair file for xrootd")
	}

	srcFile, err := os.Open(param.Server_TLSCertificate.GetString())
	if err != nil {
		return errors.Wrap(err, "Failure when opening source certificate for xrootd")
	}
	defer srcFile.Close()

	if _, err = io.Copy(destFile, srcFile); err != nil {
		return errors.Wrapf(err, "Failure when copying source certificate for xrootd")
	}

	if _, err = destFile.Write([]byte{'\n', '\n'}); err != nil {
		return errors.Wrap(err, "Failure when writing into copied key pair for xrootd")
	}

	srcKeyFile, err := os.Open(param.Server_TLSKey.GetString())
	if err != nil {
		return errors.Wrap(err, "Failure when opening source key for xrootd")
	}
	defer srcKeyFile.Close()

	if _, err = io.Copy(destFile, srcKeyFile); err != nil {
		return errors.Wrapf(err, "Failure when copying source key for xrootd")
	}

	if err = os.Rename(tmpName, destination); err != nil {
		return errors.Wrapf(err, "Failure when moving key pair for xrootd")
	}

	return nil
}

// Launch a separate goroutine that performs the XRootD maintenance tasks.
// For maintenance that is periodic, `sleepTime` is the maintenance period.
func LaunchXrootdMaintenance(ctx context.Context, server server_structs.XRootDServer, sleepTime time.Duration) {
	server_utils.LaunchWatcherMaintenance(
		ctx,
		[]string{
			filepath.Dir(param.Server_TLSCertificate.GetString()),
			filepath.Dir(param.Xrootd_Authfile.GetString()),
			filepath.Dir(param.Xrootd_ScitokensConfig.GetString()),
		},
		"xrootd maintenance",
		sleepTime,
		func(notifyEvent bool) error {
			err := CopyXrootdCertificates(server)
			if notifyEvent && errors.Is(err, errBadKeyPair) {
				log.Debugln("Bad keypair encountered when doing xrootd certificate maintenance:", err)
				return nil
			} else {
				log.Debugln("Successfully updated the Xrootd TLS certificates")
			}
			lastErr := err
			if err := EmitAuthfile(server); err != nil {
				if lastErr != nil {
					log.Errorln("Failure when generating authfile:", err)
				}
				lastErr = err
			} else {
				log.Debugln("Successfully updated the Xrootd authfile")
			}
			if err := EmitScitokensConfig(server); err != nil {
				if lastErr != nil {
					log.Errorln("Failure when emitting the scitokens.cfg:", err)
				}
				lastErr = err
			} else {
				log.Debugln("Successfully updated the Xrootd scitokens configuration")
			}
			return lastErr
		},
	)
}

// The default config has `Xrootd.AuthRefreshInterval: 5m`, which we need to convert
// to an integer representation of seconds for our XRootD configuration. This hook
// handles that conversion during unmarshalling, as well as some sanitization of user inputs.
func authRefreshStrToSecondsHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		// Filter out underlying data we don't want to risk manipulating
		if t.Kind() != reflect.Struct || f.Kind() != reflect.Map || t.Name() != "XrootdOptions" {
			return data, nil
		}

		// Get the value, load as a time.Duration, and then update the value with seconds as an int
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			return nil, errors.New("data is not a map[string]interface{}")
		}

		durStr, ok := dataMap["authrefreshinterval"].(string)
		if !ok {
			return nil, errors.New("authrefreshinterval is not a string")
		}

		// Sanitize the input to guarantee we have a unit
		suffixes := []string{"s", "m", "h"}
		hasSuffix := false
		for _, suffix := range suffixes {
			if strings.HasSuffix(durStr, suffix) {
				hasSuffix = true
				break
			}
		}
		if !hasSuffix {
			log.Warningf("'Xrootd.AuthRefreshInterval' does not have a time unit (s, m, h). Interpreting as seconds")
			durStr = durStr + "s"
		}

		duration, err := time.ParseDuration(durStr)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse 'Xrootd.AuthRefreshInterval' of %s as a duration", durStr)
		}

		if duration < 60*time.Second {
			log.Warningf("'Xrootd.AuthRefreshInterval' of %s appears as less than 60s. Using fallback of 5m", durStr)
			duration = time.Minute * 5
		}

		dataMap["authrefreshinterval"] = int(duration.Seconds())
		return data, nil
	}
}

// A wrapper to combine multiple decoder hook functions for XRootD cfg unmarshalling
func combinedDecodeHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		data, err := authRefreshStrToSecondsHookFunc()(f, t, data)
		if err != nil {
			return data, err
		}
		return server_utils.StringListToCapsHookFunc()(f, t, data)
	}
}

func ConfigXrootd(ctx context.Context, isOrigin bool) (string, error) {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	var xrdConfig XrootdConfig
	xrdConfig.Xrootd.LocalMonitoringPort = -1
	if err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc())); err != nil {
		return "", errors.Wrap(err, "failed to unmarshal xrootd config")
	}

	// For cache. convert integer percentage value [0,100] to decimal fraction [0.00, 1.00]
	if !isOrigin {
		if num, err := strconv.Atoi(xrdConfig.Cache.HighWaterMark); err == nil {
			if num <= 100 && num > 0 {
				xrdConfig.Cache.HighWaterMark = strconv.FormatFloat(float64(num)/100, 'f', 2, 64)
			}
		}
		if num, err := strconv.Atoi(xrdConfig.Cache.LowWatermark); err == nil {
			if num <= 100 && num > 0 {
				xrdConfig.Cache.LowWatermark = strconv.FormatFloat(float64(num)/100, 'f', 2, 64)
			}
		}
	}

	// To make sure we get the correct exports, we overwrite the exports in the xrdConfig struct with the exports
	// we get from the server_structs.GetOriginExports() function. Failure to do so will cause us to hit viper again,
	// which in the case of tests prevents us from overwriting some exports with temp dirs.
	if isOrigin {
		originExports, err := server_utils.GetOriginExports()
		if err != nil {
			return "", errors.Wrap(err, "failed to generate Origin export list for xrootd config")
		}
		xrdConfig.Origin.Exports = originExports
	}

	switch xrdConfig.Origin.StorageType {
	case "https":
		if xrdConfig.Origin.HttpServiceUrl == "" {
			xrdConfig.Origin.HttpServiceUrl = param.Origin_HttpServiceUrl.GetString()
		}
		if xrdConfig.Origin.FederationPrefix == "" {
			xrdConfig.Origin.FederationPrefix = param.Origin_FederationPrefix.GetString()
		}
	case "globus":
		// There's no real globus backend for xrd yet! We use https as the real backend
		xrdConfig.Origin.StorageType = "https"
		// Set activeOnly to false so that we can use the inactive ones as placeholders
		globusExports := origin.GetGlobusExportsValues(false)
		// If there's no activated Globus collection, then set the Http config to empty
		if len(globusExports) == 0 {
			// If there's no export, we fail the start
			return "", errors.New("failed to configure XRootD: no Globus collection exported")
		} else if len(globusExports) > 0 {
			if globusExports[0].HttpsServer == "" {
				// FIXME: Once the xrd-http plugin allows the empty server URL, remove this line
				// For now, put a placeholder here to allow XRootD start without error
				xrdConfig.Origin.HttpServiceUrl = "https://pelicanplatform.org"
			} else {
				xrdConfig.Origin.HttpServiceUrl = globusExports[0].HttpsServer
			}
			xrdConfig.Origin.FederationPrefix = globusExports[0].FederationPrefix

			if globusExports[0].Status == origin.GlobusActivated {
				// Check the contents of $(Origin.GlobusConfigLocation)/tokens and grab the first `.tok` file
				// Feed this to the HTTP Plugin as the auth token file
				tknFldr := filepath.Join(param.Origin_GlobusConfigLocation.GetString(), "tokens")
				tokenFiles, err := os.ReadDir(tknFldr)
				if err != nil {
					return "", errors.Wrap(err, "failed to read Globus token directory for token files")
				}

				if len(tokenFiles) == 0 {
					return "", errors.Errorf("failed to find a Globus auth token in %s", tknFldr)
				}
				var tFileName string
				for _, tFile := range tokenFiles {
					if ext := filepath.Ext(tFile.Name()); ext == origin.GlobusTokenFileExt {
						tFileName = tFile.Name()
						break
					}
				}
				if tFileName == "" {
					return "", errors.Errorf("no Globus auth tokens ending in %s could be found in %s", origin.GlobusTokenFileExt, tknFldr)
				}
				xrdConfig.Origin.HttpAuthTokenFile = filepath.Join(param.Origin_GlobusConfigLocation.GetString(), "tokens", tFileName)
			}
		}
	}

	// Map out xrootd logs
	err = mapXrootdLogLevels(&xrdConfig)
	if err != nil {
		return "", err
	}

	runtimeCAs := filepath.Join(param.Origin_RunLocation.GetString(), "ca-bundle.crt")
	if !isOrigin {
		runtimeCAs = filepath.Join(param.Cache_RunLocation.GetString(), "ca-bundle.crt")
	}
	caCount, err := utils.LaunchPeriodicWriteCABundle(ctx, runtimeCAs, 2*time.Minute)
	if err != nil {
		return "", errors.Wrap(err, "Failed to setup the runtime CA bundle")
	}
	log.Debugf("A total of %d CA certificates were written", caCount)
	if caCount > 0 {
		xrdConfig.Server.TLSCACertificateFile = runtimeCAs
	}

	if isOrigin {
		if xrdConfig.Origin.Multiuser {
			ok, err := config.HasMultiuserCaps()
			if err != nil {
				return "", errors.Wrap(err, "failed to determine if the origin can run in multiuser mode")
			}
			if !ok {
				return "", errors.New("Origin.Multiuser is set to `true` but the command was run without sufficient privilege; was it launched as root?")
			}
		}

		// Legacy caches may attempt to reach out to the origin using the xroot protocol, which
		// determines the origin's host via reverse DNS. Since we don't want that, we use the
		// XRDHOST env var at the origin to override xroot's behavior. See the following issue
		// https://github.com/PelicanPlatform/pelican/issues/1110
		if config.GetPreferredPrefix() == config.OsdfPrefix {
			externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
			if err != nil {
				return "", errors.Wrapf(err, "Failed to parse external web URL: %s", externalWebUrl)
			}

			// Strip the scheme and port number from the URL and use to set XRDHOST
			if err := os.Setenv("XRDHOST", externalWebUrl.Hostname()); err != nil {
				return "", err
			}
		}
	} else if xrdConfig.Cache.PSSOrigin != "" {
		// Workaround for a bug in XRootD 5.6.3: if the director URL is missing a port number, then
		// XRootD crashes.
		urlParsed, err := url.Parse(xrdConfig.Cache.PSSOrigin)
		if err != nil {
			return "", errors.Errorf("Director URL (%s) does not parse as a URL", xrdConfig.Cache.PSSOrigin)
		}
		if !strings.Contains(urlParsed.Host, ":") {
			switch urlParsed.Scheme {
			case "http":
				urlParsed.Host += ":80"
			case "https":
				urlParsed.Host += ":443"
			case "pelican":
				urlParsed.Host += ":443"
			default:
				log.Warningf("The Director URL (%s) does not contain an explicit port number; XRootD 5.6.3 and earlier are known to segfault in thie case", xrdConfig.Cache.PSSOrigin)
			}
			xrdConfig.Cache.PSSOrigin = urlParsed.String()
		}
	}

	var xrootdCfg string
	if isOrigin {
		xrootdCfg = xrootdOriginCfg
	} else {
		xrootdCfg = xrootdCacheCfg
	}

	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))

	configPath := filepath.Join(param.Origin_RunLocation.GetString(), "xrootd.cfg")
	if !isOrigin {
		configPath = filepath.Join(param.Cache_RunLocation.GetString(), "xrootd.cfg")
	}
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return "", err
	}
	if err = os.Chown(configPath, -1, gid); err != nil {
		return "", errors.Wrapf(err, "Unable to change ownership of configuration file %v"+
			" to desired daemon gid %v", configPath, gid)
	}

	defer file.Close()

	err = templ.Execute(file, xrdConfig)
	if err != nil {
		return "", err
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		buffer := new(bytes.Buffer)
		err = templ.Execute(buffer, xrdConfig)
		if err != nil {
			return "", err
		}
		log.Debugln("XRootD configuration file contents:\n", buffer.String())
	}

	return configPath, nil
}

// Set up xrootd monitoring
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
// goroutine and `wg` is the wait group to notify when the clean up goroutine finishes
func SetUpMonitoring(ctx context.Context, egrp *errgroup.Group) error {
	monitorPort, err := metrics.ConfigureMonitoring(ctx, egrp)
	if err != nil {
		return err
	}

	// If shoveler is enabled, shoveler will send a forwarding UDP stream to metrics handler above
	// and shoveler will start a new UDP server to listen to XRootD stream
	if param.Shoveler_Enable.GetBool() {
		monitorPort, err = metrics.LaunchShoveler(ctx, egrp, monitorPort)
		if err != nil {
			return err
		}
	}

	viper.Set("Xrootd.LocalMonitoringPort", monitorPort)

	return nil
}

func genLoggingConfig(config string, xrdConfig *XrootdConfig, configVal string, logMap loggingMap) (string, error) {
	xrootdConfigLogLevel, err := log.ParseLevel(configVal)
	if err != nil {
		return "", errors.Wrapf(err, "Error parsing specified log level for %s, proper values include: panic, fatal, error, warn, info, debug, trace", config)
	}

	var previousValue string

	// Iterate thru the map struct to see what values are set
	logStruct := reflect.TypeOf(logMap)
	logValue := reflect.ValueOf(logMap)
	for i := 0; i < logStruct.NumField(); i++ {
		field := logStruct.Field(i)
		value := logValue.Field(i)
		strValue := value.String()

		// We get the logLevel of the field and check if it is the level we want
		fieldLogLevel, err := log.ParseLevel(field.Name)
		if err != nil {
			return "", errors.Wrap(err, "Not a valid log level within logMap")
		}

		// If we have a match we assign the value to xrootd config (the value should never be "")
		if fieldLogLevel == xrootdConfigLogLevel && strValue != "" {
			return strValue, nil
		} else if fieldLogLevel == xrootdConfigLogLevel && strValue == "" {
			// if we have no previous value, we return an error
			if previousValue == "" {
				if i > 1 {
					// if we have room to get more previous levels, get them
					return genLoggingConfig(config, xrdConfig, (xrootdConfigLogLevel + 1).String(), logMap)
				}
				return "", errors.New("Unset specified log level without a previous value, loggingMap passed to function needs fixing")
			} else {
				// If we have no value, get the previous
				return previousValue, nil
			}
		} else {
			// else we continue and set the previous value
			previousValue = strValue
		}

	}
	return "", errors.New("No set log levels within loggingMap that match desired log level")
}

// mapXrootdLogLevels is utilized to map Pelican config values to Xrootd ones
// this is used to keep our log levels for Xrootd simple, so one does not need
// to be an Xrootd expert to understand the inconsistent logs within Xrootd
func mapXrootdLogLevels(xrdConfig *XrootdConfig) error {

	/////////////////////////ORIGIN/////////////////////////////
	// Origin Cms
	// https://xrootd.slac.stanford.edu/doc/dev54/cms_config.htm
	var err error
	xrdConfig.Logging.OriginCms, err = genLoggingConfig("cms", xrdConfig, param.Logging_Origin_Cms.GetString(), loggingMap{
		Trace: "debug",
		Debug: "debug",
		Info:  "all",
		Error: "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Origin_Cms")
	}

	// Origin Scitokens
	// https://github.com/xrootd/xrootd/blob/8f8498d66aa583c54c0875bb1cfe432f4be040f4/src/XrdSciTokens/XrdSciTokensAccess.cc#L951-L963
	xrdConfig.Logging.OriginScitokens, err = genLoggingConfig("scitokens", xrdConfig, param.Logging_Origin_Scitokens.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug info warning error",
		Info:  "info warning error",
		Warn:  "warning error",
		Error: "error",
		Fatal: "none",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Origin_Scitokens")
	}

	// Origin Xrd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	xrdConfig.Logging.OriginXrd, err = genLoggingConfig("xrd", xrdConfig, param.Logging_Origin_Xrd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Origin_Xrd")
	}

	// Origin Xrootd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	xrdConfig.Logging.OriginXrootd, err = genLoggingConfig("xrootd", xrdConfig, param.Logging_Origin_Xrootd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "emsg login stall redirect", // what we had set originally
		Warn:  "emsg",                      // errors sent back to the client
		Error: "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Origin_Xrootd")
	}

	// Origin Ofs
	// https://xrootd.slac.stanford.edu/doc/dev56/ofs_config.htm
	xrdConfig.Logging.OriginOfs, err = genLoggingConfig("ofs", xrdConfig, param.Logging_Origin_Ofs.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "info",
		Warn:  "most",
		Error: "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Logging.Origin.Ofs")
	}

	// Origin Oss
	xrdConfig.Logging.OriginOss, err = genLoggingConfig("oss", xrdConfig, param.Logging_Origin_Oss.GetString(), loggingMap{
		Trace: "all",
		Info:  "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Logging.Origin.Oss")
	}

	// Origin HTTP
	xrdConfig.Logging.OriginHttp, err = genLoggingConfig("http", xrdConfig, param.Logging_Origin_Http.GetString(), loggingMap{
		Debug: "all",
		Info:  "none",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Logging.Origin.Http")
	}

	//////////////////////////CACHE/////////////////////////////
	// Cache Ofs
	// https://xrootd.slac.stanford.edu/doc/dev56/ofs_config.htm
	xrdConfig.Logging.CacheOfs, err = genLoggingConfig("Ofs", xrdConfig, param.Logging_Cache_Ofs.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "info",
		Warn:  "most",
		Error: "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Ofs")
	}

	// Cache Pfc
	// https://xrootd.slac.stanford.edu/doc/dev56/pss_config.htm
	xrdConfig.Logging.CachePfc, err = genLoggingConfig("pfc", xrdConfig, param.Logging_Cache_Pfc.GetString(), loggingMap{
		Trace: "dump",
		Debug: "debug",
		Info:  "info",
		Warn:  "warning",
		Error: "error",
		Fatal: "none",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Pfc")
	}

	// Cache PssSetOptCache and Cache Pss
	// https://xrootd.slac.stanford.edu/doc/dev56/pss_config.htm
	// Note: pss has interesting config options:
	// all     informational events.
	// on      warning events.
	// debug   error events.
	// Therefore the following pss.trace I came up with is what follows:
	xrdConfig.Logging.CachePss, err = genLoggingConfig("pss", xrdConfig, param.Logging_Cache_Pss.GetString(), loggingMap{
		Trace: "all",
		Info:  "on",
		Warn:  "debug",
		Error: "off",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Pss")
	}

	// Setopt:
	xrdConfig.Logging.PssSetOptCache, err = genLoggingConfig("pss", xrdConfig, param.Logging_Cache_Pss.GetString(), loggingMap{
		Trace: "DebugLevel 4",
		Info:  "DebugLevel 3",
		Warn:  "DebugLevel 2",
		Error: "DebugLevel 1",
		Fatal: "DebugLevel 0",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Pss")
	}

	// Cache HTTP
	xrdConfig.Logging.CacheHttp, err = genLoggingConfig("http", xrdConfig, param.Logging_Cache_Http.GetString(), loggingMap{
		Debug: "all",
		Info:  "none",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Logging.Cache.Http")
	}

	// Cache Scitokens
	// https://github.com/xrootd/xrootd/blob/8f8498d66aa583c54c0875bb1cfe432f4be040f4/src/XrdSciTokens/XrdSciTokensAccess.cc#L951-L963
	xrdConfig.Logging.CacheScitokens, err = genLoggingConfig("scitokens", xrdConfig, param.Logging_Cache_Scitokens.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug info warning error",
		Info:  "info warning error",
		Warn:  "warning error",
		Error: "error",
		Fatal: "none",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Scitokens")
	}

	// Cache Xrd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	xrdConfig.Logging.CacheXrd, err = genLoggingConfig("xrd", xrdConfig, param.Logging_Cache_Xrd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Xrd")
	}

	// Cache Xrootd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	xrdConfig.Logging.CacheXrootd, err = genLoggingConfig("xrootd", xrdConfig, param.Logging_Cache_Xrootd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "emsg login stall redirect", // what we had set originally
		Warn:  "emsg",                      // errors sent back to the client
		Error: "-all",
	})
	if err != nil {
		return errors.Wrap(err, "Error parsing specified log level for Cache_Xrootd")
	}

	return nil
}
