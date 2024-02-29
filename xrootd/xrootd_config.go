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
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
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
		Multiuser        bool
		EnableCmsd       bool
		EnableMacaroons  bool
		EnableVoms       bool
		EnableDirListing bool
		SelfTest         bool
		CalculatedPort   string
		NamespacePrefix  string
		Mode             string
		S3Bucket         string
		S3Region         string
		S3ServiceName    string
		S3ServiceUrl     string
		S3AccessKeyfile  string
		S3SecretKeyfile  string
	}

	CacheConfig struct {
		UseCmsd        bool
		EnableVoms     bool
		CalculatedPort string
		ExportLocation string
		DataLocation   string
		PSSOrigin      string
		Concurrency    int
	}

	XrootdOptions struct {
		Port                   int
		ManagerHost            string
		ManagerPort            string
		MacaroonsKeyFile       string
		RobotsTxtFile          string
		Sitename               string
		SummaryMonitoringHost  string
		SummaryMonitoringPort  int
		DetailedMonitoringHost string
		DetailedMonitoringPort int
		RunLocation            string
		Authfile               string
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
		CacheScitokens  string
		CachePss        string
		CacheOfs        string
		CacheXrd        string
		PssSetOptCache  string
		OriginScitokens string
		OriginPss       string
		OriginPfc       string
		OriginCms       string
		OriginXrootd    string
		PssSetOptOrigin string
	}

	XrootdConfig struct {
		Server  ServerConfig
		Origin  OriginConfig
		Xrootd  XrootdOptions
		Cache   CacheConfig
		Logging LoggingConfig
	}
)

func CheckOriginXrootdEnv(exportPath string, server server_utils.XRootDServer, uid int, gid int, groupname string) (string, error) {
	originMode := param.Origin_Mode.GetString()
	if originMode == "posix" {
		// If we use "volume mount" style options, configure the export directories.
		volumeMount := param.Origin_ExportVolume.GetString()
		if volumeMount != "" {
			volumeMount, err := filepath.Abs(volumeMount)
			if err != nil {
				return exportPath, err
			}
			volumeMountSrc := volumeMount
			volumeMountDst := volumeMount
			volumeMountInfo := strings.SplitN(volumeMount, ":", 2)
			if len(volumeMountInfo) == 2 {
				volumeMountSrc = volumeMountInfo[0]
				volumeMountDst = volumeMountInfo[1]
			}
			volumeMountDst = filepath.Clean(volumeMountDst)
			if volumeMountDst == "" {
				return exportPath, fmt.Errorf("export volume %v has empty destination path", volumeMount)
			}
			if volumeMountDst[0:1] != "/" {
				return "", fmt.Errorf("export volume %v has a relative destination path",
					volumeMountDst)
			}
			destPath := path.Clean(filepath.Join(exportPath, volumeMountDst[1:]))
			err = config.MkdirAll(filepath.Dir(destPath), 0755, uid, gid)
			if err != nil {
				return exportPath, errors.Wrapf(err, "Unable to create export directory %v",
					filepath.Dir(destPath))
			}
			err = os.Symlink(volumeMountSrc, destPath)
			if err != nil {
				return exportPath, errors.Wrapf(err, "Failed to create export symlink")
			}
			viper.Set("Origin.NamespacePrefix", volumeMountDst)
		} else {
			mountPath := param.Xrootd_Mount.GetString()
			namespacePrefix := param.Origin_NamespacePrefix.GetString()
			if mountPath == "" || namespacePrefix == "" {
				return exportPath, errors.New(`
	The origin should have parsed export information prior to this point, but has failed to do so.
	Was the mount passed via the command line flag:

		-v /mnt/foo:/bar

	or via the parameters.yaml file:

		# Option 1
		Origin.ExportVolume: /mnt/foo:/bar

		# Option 2
		Xrootd
			Mount: /mnt/foo
		Origin:
			NamespacePrefix: /bar
				`)
			}
			mountPath, err := filepath.Abs(mountPath)
			if err != nil {
				return exportPath, err
			}
			mountPath = filepath.Clean(mountPath)
			namespacePrefix = filepath.Clean(namespacePrefix)
			if namespacePrefix[0:1] != "/" {
				return exportPath, fmt.Errorf("namespace prefix %v must have an absolute path",
					namespacePrefix)
			}
			destPath := path.Clean(filepath.Join(exportPath, namespacePrefix[1:]))
			err = config.MkdirAll(filepath.Dir(destPath), 0755, uid, gid)
			if err != nil {
				return exportPath, errors.Wrapf(err, "Unable to create export directory %v",
					filepath.Dir(destPath))
			}
			srcPath := filepath.Join(mountPath, namespacePrefix[1:])
			err = os.Symlink(srcPath, destPath)
			if err != nil {
				return exportPath, errors.Wrapf(err, "Failed to create export symlink")
			}
		}
		viper.Set("Xrootd.Mount", exportPath)
	} else if originMode == "s3" {
		// Our "namespace prefix" is actually just
		// /<Origin.S3ServiceName>/<Origin.S3Region>/<Origin.S3Bucket>
		nsPrefix := filepath.Join("/", param.Origin_S3ServiceName.GetString(),
			param.Origin_S3Region.GetString(), param.Origin_S3Bucket.GetString())
		viper.Set("Origin.NamespacePrefix", nsPrefix)
	}

	if param.Origin_SelfTest.GetBool() {
		if err := origin_ui.ConfigureXrootdMonitoringDir(); err != nil {
			return exportPath, err
		}
	}
	// If macaroons secret does not exist, create one
	macaroonsSecret := param.Xrootd_MacaroonsKeyFile.GetString()
	if _, err := os.Open(macaroonsSecret); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = config.MkdirAll(path.Dir(macaroonsSecret), 0755, -1, gid)
			if err != nil {
				return exportPath, errors.Wrapf(err, "Unable to create directory %v",
					path.Dir(macaroonsSecret))
			}
			file, err := os.OpenFile(macaroonsSecret, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
			if err != nil {
				return exportPath, errors.Wrap(err, "Failed to create a new macaroons key")
			}
			defer file.Close()
			buf := make([]byte, 64)
			_, err = rand.Read(buf)
			if err != nil {
				return exportPath, err
			}
			encoded := base64.StdEncoding.EncodeToString(buf) + "\n"
			if _, err = file.WriteString(encoded); err != nil {
				return exportPath, errors.Wrap(err, "Failed to write out a macaroons key")
			}
		} else {
			return exportPath, err
		}
	}
	if err := os.Chown(macaroonsSecret, -1, gid); err != nil {
		return exportPath, errors.Wrapf(err, "Unable to change ownership of macaroons secret %v"+
			" to desired daemon group %v", macaroonsSecret, groupname)
	}
	// If the scitokens.cfg does not exist, create one
	if originServer, ok := server.(*origin_ui.OriginServer); ok {
		err := WriteOriginScitokensConfig(originServer.GetAuthorizedPrefixes())
		if err != nil {
			return exportPath, err
		}
	}
	if err := origin_ui.ConfigureXrootdMonitoringDir(); err != nil {
		return exportPath, err
	}

	return exportPath, nil
}

func CheckCacheXrootdEnv(exportPath string, server server_utils.XRootDServer, uid int, gid int) (string, error) {
	viper.Set("Xrootd.Mount", exportPath)
	filepath.Join(exportPath, "/")
	err := config.MkdirAll(exportPath, 0775, uid, gid)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to create export directory %v",
			filepath.Dir(exportPath))
	}
	dataPath := filepath.Join(param.Cache_DataLocation.GetString(), "data/")
	dataPath = filepath.Clean(dataPath)
	err = config.MkdirAll(dataPath, 0775, uid, gid)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to create data directory %v",
			filepath.Dir(dataPath))
	}
	metaPath := filepath.Join(param.Cache_DataLocation.GetString(), "meta/")
	metaPath = filepath.Clean(metaPath)
	err = config.MkdirAll(metaPath, 0775, uid, gid)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to create meta directory %v",
			filepath.Dir(metaPath))
	}

	err = config.DiscoverFederation()
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

	if directorUrlStr := param.Federation_DirectorUrl.GetString(); directorUrlStr != "" {
		directorUrl, err := url.Parse(param.Federation_DirectorUrl.GetString())
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

	if cacheServer, ok := server.(*cache_ui.CacheServer); ok {
		err := WriteCacheScitokensConfig(cacheServer.GetNamespaceAds())
		if err != nil {
			return "", errors.Wrap(err, "Failed to create scitokens configuration for the cache")
		}
	}
	return exportPath, nil
}

func CheckXrootdEnv(server server_utils.XRootDServer) error {
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
	runtimeDir := param.Xrootd_RunLocation.GetString()
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

	if err = CopyXrootdCertificates(); err != nil {
		return err
	}

	if server.GetServerType().IsEnabled(config.OriginType) {
		exportPath, err = CheckOriginXrootdEnv(exportPath, server, uid, gid, groupname)
	} else {
		exportPath, err = CheckCacheXrootdEnv(exportPath, server, uid, gid)
	}
	if err != nil {
		return err
	}

	if err = EmitIssuerMetadata(exportPath); err != nil {
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
func CopyXrootdCertificates() error {
	user, err := config.GetDaemonUserInfo()
	if err != nil {
		return errors.Wrap(err, "Unable to copy certificates to xrootd runtime directory; failed xrootd user lookup")
	}

	certFile := param.Server_TLSCertificate.GetString()
	certKey := param.Server_TLSKey.GetString()
	if _, err = tls.LoadX509KeyPair(certFile, certKey); err != nil {
		return builtin_errors.Join(err, errBadKeyPair)
	}

	destination := filepath.Join(param.Xrootd_RunLocation.GetString(), "copied-tls-creds.crt")
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
func LaunchXrootdMaintenance(ctx context.Context, server server_utils.XRootDServer, sleepTime time.Duration) {
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
			err := CopyXrootdCertificates()
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

func ConfigXrootd(ctx context.Context, origin bool) (string, error) {

	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	var xrdConfig XrootdConfig
	xrdConfig.Xrootd.LocalMonitoringPort = -1
	if err := viper.Unmarshal(&xrdConfig); err != nil {
		return "", err
	}

	// Map out xrootd logs
	mapXrootdLogLevels(&xrdConfig)

	runtimeCAs := filepath.Join(param.Xrootd_RunLocation.GetString(), "ca-bundle.crt")
	caCount, err := utils.LaunchPeriodicWriteCABundle(ctx, runtimeCAs, 2*time.Minute)
	if err != nil {
		return "", errors.Wrap(err, "Failed to setup the runtime CA bundle")
	}
	log.Debugf("A total of %d CA certificates were written", caCount)
	if caCount > 0 {
		xrdConfig.Server.TLSCACertificateFile = runtimeCAs
	}

	if origin {
		if xrdConfig.Origin.Multiuser {
			ok, err := config.HasMultiuserCaps()
			if err != nil {
				return "", errors.Wrap(err, "Failed to determine if the origin can run in multiuser mode")
			}
			if !ok {
				return "", errors.New("Origin.Multiuser is set to `true` but the command was run without sufficient privilege; was it launched as root?")
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
	if origin {
		xrootdCfg = xrootdOriginCfg
	} else {
		xrootdCfg = xrootdCacheCfg
	}

	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))

	xrootdRun := param.Xrootd_RunLocation.GetString()
	configPath := filepath.Join(xrootdRun, "xrootd.cfg")
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

// mapXrootdLogLevels is utilized to map Pelican config values to Xrootd ones
// this is used to keep our log levels for Xrootd simple, so one does not need
// to be an Xrootd expert to understand the inconsistent logs within Xrootd
func mapXrootdLogLevels(xrdConfig *XrootdConfig) {
	// Origin Scitokens
	originScitokensConfig := param.Logging_Origin_Scitokens.GetString()
	if originScitokensConfig == "debug" {
		xrdConfig.Logging.OriginScitokens = "all"
	} else if originScitokensConfig == "info" {
		xrdConfig.Logging.OriginScitokens = "info"
	} else if originScitokensConfig == "error" {
		xrdConfig.Logging.OriginScitokens = "none"
	} else { // Default is error
		log.Errorln("Unrecognized log-level for Origin_Scitokens, setting to default (error) setting.")
		xrdConfig.Logging.OriginScitokens = "none"
	}

	// pssSetOptOrigin and pssOrigin
	pssSetOptOrigin := param.Logging_Origin_Pss.GetString()
	if pssSetOptOrigin == "debug" {
		xrdConfig.Logging.PssSetOptOrigin = "DebugLevel 3"
		xrdConfig.Logging.OriginPss = "all"
	} else if pssSetOptOrigin == "info" {
		xrdConfig.Logging.PssSetOptOrigin = "DebugLevel 2"
		xrdConfig.Logging.OriginPss = "on"
	} else if pssSetOptOrigin == "error" {
		xrdConfig.Logging.PssSetOptOrigin = "DebugLevel 1"
		xrdConfig.Logging.OriginPss = "off"
	} else {
		log.Errorln("Unrecognized log-level for Origin_Pss, setting to default (error) setting.")
		xrdConfig.Logging.PssSetOptOrigin = "DebugLevel 1"
		xrdConfig.Logging.OriginPss = "off"
	}

	// Origin Pfc
	originPfcConfig := param.Logging_Origin_Pfc.GetString()
	if originPfcConfig == "debug" {
		xrdConfig.Logging.OriginPfc = "all"
	} else if originPfcConfig == "error" {
		xrdConfig.Logging.OriginPfc = "none"
	} else if originPfcConfig == "info" { // Default is info
		xrdConfig.Logging.OriginPfc = "info"
	} else {
		log.Errorln("Unrecognized log-level for Origin_Pfc, setting to default (info) setting.")
		xrdConfig.Logging.OriginPfc = "info"
	}

	// Origin Cms
	originCmsConfig := param.Logging_Origin_Cms.GetString()
	if originCmsConfig == "debug" {
		xrdConfig.Logging.OriginCms = "all"
	} else if originCmsConfig == "info" {
		xrdConfig.Logging.OriginCms = "-all" // Not super sure what to do for info on this one
	} else if originCmsConfig == "error" {
		xrdConfig.Logging.OriginCms = "-all"
	} else {
		log.Errorln("Unrecognized log-level for Origin_Cms, setting to default (error) setting.")
		xrdConfig.Logging.OriginCms = "-all"
	}

	// Origin Xrootd
	// Have this for now with the regular config options, not sure what to do to make it more
	// user-friendly since our/osg's defaults are pretty specific
	originXrootdConfig := param.Logging_Origin_Xrootd.GetString()

	// Want to make sure everything specified is a valid config value:
	allowedVariables := map[string]bool{
		"all":      true,
		"auth":     true,
		"debug":    true,
		"emsg":     true,
		"fs":       true,
		"fsaio":    true,
		"fsio":     true,
		"login":    true,
		"mem":      true,
		"off":      true,
		"pgcserr":  true,
		"redirect": true,
		"request":  true,
		"response": true,
		"stall":    true,
	}

	configValues := strings.Fields(originXrootdConfig)
	validConfig := true
	for _, value := range configValues {
		if _, exists := allowedVariables[value]; !exists {
			log.Errorln("Unrecognized log-level found for Origin_Xrootd, setting to default (emsg login stall redirect) setting.")
			xrdConfig.Logging.OriginXrootd = "emsg login stall redirect"
			validConfig = false
			break
		}
	}
	if validConfig {
		xrdConfig.Logging.OriginXrootd = originXrootdConfig
	}

	// Cache Scitokens
	cacheScitokensConfig := param.Logging_Cache_Scitokens.GetString()
	if cacheScitokensConfig == "debug" {
		xrdConfig.Logging.CacheScitokens = "all"
	} else if cacheScitokensConfig == "info" {
		xrdConfig.Logging.CacheScitokens = "info"
	} else if cacheScitokensConfig == "error" {
		xrdConfig.Logging.CacheScitokens = "none"
	} else { // Default is error
		log.Errorln("Unrecognized log-level for Cache_Scitokens, setting to default (error) setting.")
		xrdConfig.Logging.CacheScitokens = "none"
	}

	// Cache PssSetOptCache and Cache Pss
	cachePssConfig := param.Logging_Cache_Pss.GetString()
	if cachePssConfig == "debug" {
		xrdConfig.Logging.PssSetOptCache = "DebugLevel 3"
		xrdConfig.Logging.CachePss = "all"
	} else if cachePssConfig == "info" {
		xrdConfig.Logging.PssSetOptCache = "DebugLevel 2"
		xrdConfig.Logging.CachePss = "on"
	} else if cachePssConfig == "error" {
		xrdConfig.Logging.PssSetOptCache = "DebugLevel 1"
		xrdConfig.Logging.CachePss = "off"
	} else {
		log.Errorln("Unrecognized log-level for Cache_Pss, setting to default (error) setting.")
		xrdConfig.Logging.PssSetOptOrigin = "DebugLevel 1"
		xrdConfig.Logging.CachePss = "off"
	}

	// Cache Ofs
	cacheOfsConfig := param.Logging_Cache_Ofs.GetString()
	if cacheOfsConfig == "debug" {
		xrdConfig.Logging.CacheOfs = "all"
	} else if cacheOfsConfig == "info" {
		xrdConfig.Logging.CacheOfs = "-all" // Not super sure what to do for info on this one
	} else if cacheOfsConfig == "error" {
		xrdConfig.Logging.CacheOfs = "-all"
	} else {
		log.Errorln("Unrecognized log-level for Cache_Ofs, setting to default (error) setting.")
		xrdConfig.Logging.CacheOfs = "-all"
	}

	// Cache Xrd
	cacheXrdConfig := param.Logging_Cache_Xrd.GetString()
	if cacheXrdConfig == "debug" {
		xrdConfig.Logging.CacheXrd = "all -sched"
	} else if cacheXrdConfig == "info" {
		xrdConfig.Logging.CacheXrd = "-all" // Not super sure what to do for info on this one
	} else if cacheXrdConfig == "error" {
		xrdConfig.Logging.CacheXrd = "-all"
	} else {
		log.Errorln("Unrecognized log-level for Cache_Xrd, setting to default (error) setting.")
		xrdConfig.Logging.CacheXrd = "-all"
	}
}
