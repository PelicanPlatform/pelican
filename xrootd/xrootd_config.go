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
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/p11proxy"
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

	clientHttpPluginDefault = `
url = http://*;https://*
lib = libXrdClCurl.so
enable = true
`

	clientPluginMac = `
url = pelican://*
lib = libXrdClPelican.dylib
enable = true
`

	clientHttpPluginMac = `
url = http://*;https://*
lib = libXrdClCurl.dylib
enable = true
`
)

type (
	OriginConfig struct {
		Multiuser           bool
		DirectorTest        bool
		EnableCmsd          bool
		EnableMacaroons     bool
		EnableVoms          bool
		EnablePublicReads   bool
		EnableListings      bool
		EnableAtomicUploads bool
		SelfTest            bool
		Concurrency         int
		Port                int
		FederationPrefix    string
		HttpServiceUrl      string
		HttpAuthTokenFile   string
		XRootServiceUrl     string
		RunLocation         string
		StorageType         string
		UploadTempLocation  string

		// S3 specific options that are kept top-level because
		// they aren't specific to each export
		S3Region     string
		S3ServiceUrl string
		S3UrlStyle   string

		// Globus specific options
		GlobusTransferTokenFile string

		Exports []server_utils.OriginExport
	}

	LotmanCfg struct {
		Enabled    bool
		LotHome    string
		PurgeOrder []string
	}

	CacheConfig struct {
		UseCmsd                    bool
		EnablePrefetch             bool
		EnableVoms                 bool
		Port                       int
		HighWaterMark              string
		LowWatermark               string
		FilesBaseSize              string
		FilesNominalSize           string
		FilesMaxSize               string
		ExportLocation             string
		RunLocation                string
		DataLocations              []string
		MetaLocations              []string
		NamespaceLocation          string
		PSSOrigin                  string
		BlocksToPrefetch           int
		Concurrency                int
		LotmanCfg                  LotmanCfg
		EnableTLSClientAuth        bool
		EvictionMonitoringInterval int
		EvictionMonitoringMaxDepth int
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
		HttpMaxDelay           int
		MaxThreads             int
	}

	ServerConfig struct {
		TLSCertificateChain       string
		TLSKey                    string
		TLSCACertificateDirectory string
		TLSCACertificateFile      string
		DropPrivileges            bool
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
		CacheLotman     string
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

type xrootdMaintenanceState struct {
	lastAuthfileSuccess  time.Time
	lastScitokensSuccess time.Time
	authfileFailures     int
	scitokensFailures    int
	// Mutex is not needed because the XRootD maintenance callback is executed in a single goroutine,
	// so there’s no concurrent access to this state
}

// CheckOriginXrootdEnv is almost a misnomer -- it does both checking and configuring. In partcicular,
// it is responsible for setting up the exports and handling all the symlinking we use
// to export our directories.
func CheckOriginXrootdEnv(exportPath string, server server_structs.XRootDServer, uid int, gid int, username, groupname string) error {
	// First we check if our config yaml contains the Exports block. If it does, we use that instead of the older legacy
	// options for all this configuration
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}

	backendType, err := server_structs.ParseOriginStorageType(param.Origin_StorageType.GetString())
	if err != nil {
		return err
	}
	if backendType == server_structs.OriginStoragePosix {
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
		if err := param.Set("Xrootd.Mount", exportPath); err != nil {
			return err
		}

		// Create the upload temp directory with appropriate permissions.
		// When the multiuser plugin is enabled, XRootD performs filesystem operations as the
		// authenticated user rather than root. This means each uploading user needs the ability
		// to create their own subdirectory (e.g., <uploadTempDir>/<username>/) for temporary
		// files. Mode 1777 (world-writable + sticky bit) allows any user to create entries
		// while the sticky bit prevents them from deleting each other's directories.
		// An alternative to 1777 is to pre-create per-user subdirectories with appropriate
		// ownership. See the "Configure the POSC" section of pelicanplatform/xrootd-s3-http/README.md for
		// the full discussion of these two models.
		uploadTempDir := param.Origin_UploadTempLocation.GetString()

		// Check if the directory exists
		if stat, err := os.Stat(uploadTempDir); os.IsNotExist(err) {
			// Directory doesn't exist - create it with mode 1777 (world-writable + sticky bit)
			log.Infof("Creating in-progress directory %v with mode 1777 (world-writable + sticky bit)", uploadTempDir)
			if err = config.MkdirAll(uploadTempDir, 0777|os.ModeSticky, uid, gid); err != nil {
				return errors.Wrapf(err, "unable to create in-progress directory %v", uploadTempDir)
			}
			if err = os.Chown(uploadTempDir, uid, -1); err != nil {
				return errors.Wrapf(err, "unable to change ownership of in-progress directory %v"+
					" to desired daemon user %v", uploadTempDir, username)
			}
		} else if err != nil {
			// Error checking directory
			return errors.Wrapf(err, "unable to stat in-progress directory %v", uploadTempDir)
		} else if !stat.IsDir() {
			// Path exists but is not a directory
			return errors.Errorf("in-progress location %v exists but is not a directory", uploadTempDir)
		} else {
			// Directory exists - check its permissions
			mode := stat.Mode()
			perm := mode.Perm()

			// Check if world-writable (others have write permission)
			isWorldWritable := (perm & 0002) != 0

			if isWorldWritable {
				// Check sticky bit
				hasStickyBit := (mode & os.ModeSticky) != 0

				if hasStickyBit {
					log.Infof("In-progress directory %v exists with mode %04o - using shared sticky-bit model",
						uploadTempDir, perm)
				} else {
					return errors.Errorf("in-progress directory %v has mode %04o (world-writable without sticky bit); "+
						"this is unsafe because any user can delete others' files. "+
						"Set permissions to 1777 (chmod 1777 %v) to enable the sticky bit",
						uploadTempDir, perm, uploadTempDir)
				}
			} else {
				// Not world-writable - per-user model
				log.Infof("In-progress directory %v has mode %04o (per-user model). "+
					"Users must have pre-created subdirectories (%v/$USER) with proper ownership and permissions.",
					uploadTempDir, perm, uploadTempDir)
			}

			// Ensure ownership is correct
			if err = os.Chown(uploadTempDir, uid, -1); err != nil {
				return errors.Wrapf(err, "unable to change ownership of in-progress directory %v"+
					" to desired daemon user %v", uploadTempDir, username)
			}
		}
		// At this point, the in-progress directory is created and owned by the user specified in the config
		// We need to symlink the user-specified in-progress directory to the actual in-progress directory

		err = os.Symlink(uploadTempDir, filepath.Join(exportPath, "in-progress"))
		if err != nil {
			return errors.Wrapf(err, "Failed to create in-progress symlink from %v to %v", uploadTempDir, filepath.Join(exportPath, "in-progress"))
		}
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
	if _, ok := server.(*origin.OriginServer); ok {
		// This is the first time we write the scitokens.cfg file, so isFirstRun = true
		err = WriteOriginScitokensConfig(true)
		if err != nil {
			return err
		}
	}
	if err := origin.ConfigureXrootdMonitoringDir(); err != nil {
		return err
	}

	return nil
}

func CheckCacheXrootdEnv(server server_structs.XRootDServer, uid int, gid int) error {
	storageLocation := param.Cache_StorageLocation.GetString()
	if err := config.MkdirAll(storageLocation, 0775, uid, gid); err != nil {
		return errors.Wrapf(err, "Unable to create the cache's storage directory '%s'", storageLocation)
	}
	// Setting Cache.StorageLocation to /run/pelican/cache is a default we use for testing, but it shouldn't ever be used
	// in a production setting. If the user hasn't overridden the default, log a warning.
	if storageLocation == filepath.Join("/run", "pelican", "cache") {
		log.Warnf("%s is set to the default /run/pelican/cache. This default is to allow quick testing but should not be used in production.", param.Cache_StorageLocation.GetName())
	}

	namespaceLocation := param.Cache_NamespaceLocation.GetString()
	if err := config.MkdirAll(namespaceLocation, 0775, uid, gid); err != nil {
		return errors.Wrapf(err, "Unable to create the cache's storage directory '%s'", storageLocation)
	}

	// Validate configured data and meta locations. In particular, make sure we don't export
	// data under our namespace directory, and that data locations are not nested (they're meant to be
	// separate disks)
	dataPaths := param.Cache_DataLocations.GetStringSlice()
	cleanedDataPaths := make([]string, len(dataPaths))
	for i, dPath := range dataPaths {
		cleanedDataPaths[i] = filepath.Clean(dPath)
	}

	// Make sure there's no nesting between data locations
	for i, dPath1 := range cleanedDataPaths {
		for j, dPath2 := range cleanedDataPaths {
			if i != j {
				relPath, err := filepath.Rel(dPath1, dPath2)
				if err != nil {
					return errors.Wrapf(err, "Unable to determine relative path between %s and %s", dPath1, dPath2)
				}
				if relPath == "." || !strings.HasPrefix(relPath, "..") {
					return errors.Errorf("Data location '%s' is a subdirectory or parent directory of '%s'. Please ensure these directories are not nested.", dPath1, dPath2)
				}
			}
		}
	}

	// Check for subdirectory relationships with namespaceLocation
	for _, dPath := range cleanedDataPaths {
		if strings.HasPrefix(dPath, namespaceLocation) {
			return errors.Errorf("A configured data location '%s' is a subdirectory of the namespace location '%s'. Please ensure these directories are not nested.", dPath, namespaceLocation)
		}

		if err := config.MkdirAll(dPath, 0775, uid, gid); err != nil {
			return errors.Wrapf(err, "Unable to create data directory %v", filepath.Dir(dPath))
		}
	}

	metaPaths := param.Cache_MetaLocations.GetStringSlice()
	for _, mPath := range metaPaths {
		metaPath := filepath.Clean(mPath)
		// Similar to data locations, meta locations should never be below the namespace location
		if strings.HasPrefix(mPath, namespaceLocation) {
			return errors.Errorf("The configured meta location '%s' is a subdirectory of the namespace location '%s'. Please ensure these directories are not nested.", mPath, namespaceLocation)
		}

		if err := config.MkdirAll(metaPath, 0775, uid, gid); err != nil {
			return errors.Wrapf(err, "Unable to create meta directory %v",
				filepath.Dir(metaPath))
		}
	}

	if _, err := ensureCachePSSOrigin(context.Background()); err != nil {
		return err
	}

	if cacheServer, ok := server.(*cache.CacheServer); ok {
		err := WriteCacheScitokensConfig(cacheServer.GetNamespaceAds(), true)
		if err != nil {
			return errors.Wrap(err, "Failed to create scitokens configuration for the cache")
		}
	}

	return nil
}

func ensureCachePSSOrigin(ctx context.Context) (string, error) {
	if existing := param.Cache_PSSOrigin.GetString(); existing != "" {
		return existing, nil
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", errors.Wrap(err, "Failed to pull information from the federation")
	}

	pssOrigin := ""

	if discoveryUrlStr := fedInfo.DiscoveryEndpoint; discoveryUrlStr != "" {
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
			pssOrigin = discoveryUrl.String()
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
			pssOrigin = directorUrl.String()
		} else {
			return "", errors.Wrapf(err, "Failed to parse director URL %s", directorUrlStr)
		}
	}

	if pssOrigin == "" {
		return "", errors.New("One of Federation.DiscoveryUrl or Federation.DirectorUrl must be set to configure a cache")
	}

	if err := param.Set("Cache.PSSOrigin", pssOrigin); err != nil {
		return "", err
	}

	return pssOrigin, nil
}

func CheckXrootdEnv(server server_structs.XRootDServer) error {
	// Check XRootD version before proceeding with environment setup
	if err := CheckXrootdVersion(); err != nil {
		return err
	}

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
	if server.GetServerType().IsEnabled(server_structs.CacheType) {
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

	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		clientPluginsDir := filepath.Join(runtimeDir, "cache-client.plugins.d")
		if err = os.MkdirAll(clientPluginsDir, os.FileMode(0755)); err != nil {
			return errors.Wrap(err, "Unable to create cache client plugins directory")
		}
		if runtime.GOOS == "darwin" {
			err = os.WriteFile(filepath.Join(clientPluginsDir, "pelican-plugin.conf"), []byte(clientPluginMac), os.FileMode(0644))
			if err == nil {
				err = os.WriteFile(filepath.Join(clientPluginsDir, "http-plugin.conf"), []byte(clientHttpPluginMac), os.FileMode(0644))
			}
		} else {
			err = os.WriteFile(filepath.Join(clientPluginsDir, "pelican-plugin.conf"), []byte(clientPluginDefault), os.FileMode(0644))
			if err == nil {
				err = os.WriteFile(filepath.Join(clientPluginsDir, "http-plugin.conf"), []byte(clientHttpPluginDefault), os.FileMode(0644))
			}
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

	if err = copyXrootdCertificates(server); err != nil {
		return err
	}

	if server.GetServerType().IsEnabled(server_structs.OriginType) {
		err = CheckOriginXrootdEnv(exportPath, server, uid, gid, username, groupname)
	} else {
		err = CheckCacheXrootdEnv(server, uid, gid)
	}
	if err != nil {
		return err
	}

	xServerUrl := param.Origin_Url.GetString()
	if server.GetServerType().IsEnabled(server_structs.CacheType) {
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
			if err := param.Set("Xrootd.RobotsTxtFile", newPath); err != nil {
				return err
			}
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
	if err := EmitAuthfile(server, true); err != nil {
		return err
	}

	return nil
}

// Returns the path to the Pelican-generated TLS certificate file
// for the given server type at runtime.
// In normal mode, this file can be directly used by XRootD.
// In drop-privileges mode, XRootD-HTTP plugin will send this file
// to another directory that the xrootd user can access.
func runtimeTLSCertPath(isCache bool) string {
	base := param.Origin_RunLocation.GetString()
	if isCache {
		base = param.Cache_RunLocation.GetString()
	}
	if param.Server_DropPrivileges.GetBool() {
		base = filepath.Join(base, "pelican")
	}
	return filepath.Join(base, "copied-tls-creds.crt")
}

func writeX509Credentials(fp *os.File, includeKey bool) error {
	srcFile, err := os.Open(param.Server_TLSCertificateChain.GetString())
	if err != nil {
		return errors.Wrap(err, "Failure when opening source certificate for xrootd")
	}
	defer srcFile.Close()

	if _, err = io.Copy(fp, srcFile); err != nil {
		return errors.Wrapf(err, "Failure when copying source certificate for xrootd")
	}

	if !includeKey {
		return nil
	}

	if _, err = fp.Write([]byte{'\n', '\n'}); err != nil {
		return errors.Wrap(err, "Failure when writing into copied key pair for xrootd")
	}

	srcKeyFile, err := os.Open(param.Server_TLSKey.GetString())
	if err != nil {
		return errors.Wrap(err, "Failure when opening source key for xrootd")
	}
	defer srcKeyFile.Close()

	if _, err = io.Copy(fp, srcKeyFile); err != nil {
		return errors.Wrapf(err, "Failure when copying source key for xrootd")
	}

	return nil
}

// Copies the server certificate/key files into the XRootD runtime
// directory.  Combines the two files into a single one so the new
// certificate shows up atomically from XRootD's perspective.
// Adjusts the ownership and mode to match that expected
// by the XRootD framework.
func copyXrootdCertificates(server server_structs.XRootDServer) error {
	user, err := config.GetDaemonUserInfo()
	if err != nil {
		return errors.Wrap(err, "Unable to copy certificates to xrootd runtime directory; failed xrootd user lookup")
	}

	certFile := param.Server_TLSCertificateChain.GetString()
	certKey := param.Server_TLSKey.GetString()
	if _, err = tls.LoadX509KeyPair(certFile, certKey); err != nil {
		return builtin_errors.Join(err, errBadKeyPair)
	}

	destination := filepath.Join(param.Origin_RunLocation.GetString(), "copied-tls-creds.crt")
	if server.GetServerType().IsEnabled(server_structs.CacheType) {
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

	pkcs11Info := p11proxy.CurrentInfo()
	pkcs11Active := param.Server_EnablePKCS11.GetBool() && pkcs11Info.Enabled
	if err = writeX509Credentials(destFile, !pkcs11Active); err != nil {
		return err
	}

	if err = os.Rename(tmpName, destination); err != nil {
		return errors.Wrapf(err, "Failure when moving key pair for xrootd")
	}

	return nil
}

func FileCopyToXrootdDir(isOrigin bool, cmd int, file *os.File) error {
	log.Debugf("Transplanting file %s to a directory owned by the xrootd process", file.Name())
	if err := sendChildFD(isOrigin, cmd, file); err != nil {
		return errors.Wrapf(err, "Failed to copy the file %s via FD", file.Name())
	}
	return nil
}

// After privileges have been dropped, copy the server certificates
// to the xrootd process.
func dropPrivilegeCopy(server server_structs.XRootDServer) error {
	certFile := param.Server_TLSCertificateChain.GetString()
	certKey := param.Server_TLSKey.GetString()
	if _, err := tls.LoadX509KeyPair(certFile, certKey); err != nil {
		return builtin_errors.Join(err, errBadKeyPair)
	}

	// This intermediate file is written by the parent (pelican process) and sent to XRootD-HTTP plugin.
	// XRootD-HTTP plugin will then copy this file to the runtime directory that the xrootd user can access.
	intermediatePath := runtimeTLSCertPath(server.GetServerType().IsEnabled(server_structs.CacheType))

	// If the file already exists, delete it so that OpenFile will create a new one.
	// Because this intermediate file is read-only (0400), user cannot update it (os.O_TRUNC will hit an permission denied error).
	err := os.Remove(intermediatePath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "Failure when removing existing certificate key pair file for xrootd")
	}

	destFile, err := os.OpenFile(intermediatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(0400))
	if err != nil {
		return errors.Wrap(err, "Failure when opening certificate key pair file to pass to xrootd")
	}
	defer destFile.Close()

	pkcs11Info := p11proxy.CurrentInfo()
	pkcs11Active := param.Server_EnablePKCS11.GetBool() && pkcs11Info.Enabled
	if err = writeX509Credentials(destFile, !pkcs11Active); err != nil {
		return err
	}

	for idx := 0; idx < 2; idx++ {
		rdDestFile, err := os.OpenFile(intermediatePath, os.O_RDONLY, fs.FileMode(0400))
		if err != nil {
			return errors.Wrap(err, "Failed to re-open the copied certificate key pair file as read-only")
		}
		isOrigin := true
		if idx == 1 {
			isOrigin = false
		}
		if err = sendChildFD(isOrigin, 2, rdDestFile); err != nil {
			return errors.Wrap(err, "Failed to send the copied certificate key pair file to xrootd")
		}
	}

	return nil
}

// Launch a separate goroutine that performs the XRootD maintenance tasks.
// For maintenance that is periodic, `sleepTime` is the maintenance period.
func LaunchXrootdMaintenance(ctx context.Context, server server_structs.XRootDServer, sleepTime time.Duration) {
	state := &xrootdMaintenanceState{
		// This initial set-to-now is a grace baseline to avoid tripping the timeout before the first successful cycle
		lastAuthfileSuccess:  time.Now(),
		lastScitokensSuccess: time.Now(),
	}
	// Capture timeout and auto-shutdown config at launch time to avoid race conditions with Viper resets in tests
	configTimeout := param.Xrootd_ConfigUpdateFailureTimeout.GetDuration()
	autoShutdownEnabled := param.Xrootd_AutoShutdownEnabled.GetBool()

	server_utils.LaunchWatcherMaintenance(
		ctx,
		[]string{
			filepath.Dir(param.Server_TLSCertificateChain.GetString()),
			filepath.Dir(param.Xrootd_Authfile.GetString()),
			filepath.Dir(param.Xrootd_ScitokensConfig.GetString()),
		},
		"xrootd maintenance",
		sleepTime,
		func(notifyEvent bool) error {
			var err error
			if param.Server_DropPrivileges.GetBool() {
				err = dropPrivilegeCopy(server)
				if err != nil {
					log.Errorln("Failure when copying the TLS certificates to the xrootd process:", err)
				}
			} else {
				err = copyXrootdCertificates(server)
			}
			if notifyEvent && errors.Is(err, errBadKeyPair) {
				log.Debugln("Bad keypair encountered when doing xrootd certificate maintenance:", err)
				return nil
			} else {
				log.Debugln("Successfully updated the Xrootd TLS certificates")
			}
			lastErr := err

			// Emit authfile and track success/failure
			if err := EmitAuthfile(server, false); err != nil {
				state.authfileFailures += 1
				elapsed := time.Since(state.lastAuthfileSuccess)
				if lastErr != nil {
					log.Errorln("Failure when generating authfile:", err)
				}
				log.Debugf("Authfile update has failed %d times in a row; last success was %s ago", state.authfileFailures, elapsed.Round(time.Second).String())
				lastErr = err
			} else {
				state.lastAuthfileSuccess = time.Now()
				state.authfileFailures = 0
				log.Debugln("Successfully updated the Xrootd authfile")
			}

			// Emit scitokens config and track success/failure
			if err := EmitScitokensConfig(server); err != nil {
				state.scitokensFailures += 1
				elapsed := time.Since(state.lastScitokensSuccess)
				if lastErr != nil {
					log.Errorln("Failure when emitting the scitokens.cfg:", err)
				}
				log.Debugf("Scitokens config update has failed %d times in a row; last success was %s ago", state.scitokensFailures, elapsed.Round(time.Second).String())
				lastErr = err
			} else {
				state.lastScitokensSuccess = time.Now()
				state.scitokensFailures = 0
				log.Debugln("Successfully updated the Xrootd scitokens configuration")
			}

			// Health reporting and auto-shutdown check
			oldest := state.lastAuthfileSuccess
			if state.lastScitokensSuccess.Before(oldest) {
				oldest = state.lastScitokensSuccess
			}
			authFails := state.authfileFailures
			sciFails := state.scitokensFailures

			age := time.Since(oldest)

			if authFails == 0 && sciFails == 0 {
				metrics.SetComponentHealthStatus(metrics.OriginCache_ConfigUpdates, metrics.StatusOK, "Authfile and scitoken.cfg file updated successfully")
			} else if age < configTimeout {
				metrics.SetComponentHealthStatus(metrics.OriginCache_ConfigUpdates, metrics.StatusWarning, "Authfile and/or scitoken.cfg file update failures observed; within timeout")
			} else {
				metrics.SetComponentHealthStatus(metrics.OriginCache_ConfigUpdates, metrics.StatusCritical, "Authfile and/or scitoken.cfg file stale beyond timeout; initiating shutdown if enabled")
				if autoShutdownEnabled {
					staleXrootdCfgFiles := "XRootD "
					if authFails > 0 && sciFails > 0 {
						staleXrootdCfgFiles += "authfile and scitokens.cfg file"
					} else if authFails > 0 {
						staleXrootdCfgFiles += "authfile"
					} else if sciFails > 0 {
						staleXrootdCfgFiles += "scitokens.cfg file"
					}
					log.Errorf("%s not updated for %s (timeout: %s); initiating auto-shutdown", staleXrootdCfgFiles, age.Round(time.Second).String(), configTimeout.Round(time.Second).String())
					// Use non-blocking send to avoid deadlock when multiple rapid maintenance cycles trigger shutdown before the signal is consumed
					select {
					case config.ShutdownFlag <- true:
					default:
						// Shutdown already initiated, no need to send again
					}
				}
			}

			return lastErr
		},
	)
}

// The default config has `Xrootd.AuthRefreshInterval: 5m`, which we need to convert
// to an integer representation of seconds for our XRootD configuration. This hook
// handles that conversion during unmarshalling, as well as some sanitization of user inputs.
func durationStrToSecondsHookFuncGenerator(structName, fieldName, configName string, validation func(duration time.Duration, durStr string) time.Duration) mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		// Filter out underlying data we don't want to risk manipulating
		if t.Kind() != reflect.Struct || f.Kind() != reflect.Map || t.Name() != structName {
			return data, nil
		}

		// Get the value, load as a time.Duration, and then update the value with seconds as an int
		dataMap, ok := data.(map[string]any)
		if !ok {
			return nil, errors.New("data is not a map[string]any")
		}

		uncastDur, ok := dataMap[fieldName]
		if !ok {
			// If the key is not present, we don't need to do anything.
			return data, nil
		}

		var (
			duration time.Duration
			durStr   string
		)

		switch v := uncastDur.(type) {
		case time.Duration:
			duration = v
			durStr = v.String()
		case int8:
			val := int64(v)
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatInt(val, 10)
		case int16:
			val := int64(v)
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatInt(val, 10)
		case int32:
			val := int64(v)
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatInt(val, 10)
		case int64:
			val := int64(v)
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatInt(val, 10)
		case int:
			val := int64(v)
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatInt(val, 10)
		case uint, uint8, uint16, uint32, uint64:
			val := reflect.ValueOf(v).Uint()
			duration = time.Duration(val) * time.Second
			durStr = strconv.FormatUint(val, 10)
		case float64:
			duration = time.Duration(v * float64(time.Second))
			durStr = strconv.FormatFloat(v, 'f', -1, 64)
		case float32:
			duration = time.Duration(v * float32(time.Second))
			durStr = strconv.FormatFloat(float64(v), 'f', -1, 32)
		default:
			durStr, ok = uncastDur.(string)
			if !ok {
				return nil, errors.Errorf("%s is not a string, duration, or numeric type", fieldName)
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
				log.Warningf("'%s' does not have a time unit (s, m, h). Interpreting as seconds", configName)
				durStr = durStr + "s"
			}

			var err error
			duration, err = time.ParseDuration(durStr)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse '%s' of %s as a duration", configName, durStr)
			}
		}

		if validation != nil {
			duration = validation(duration, durStr)
		}

		dataMap[fieldName] = int(duration.Seconds())
		return data, nil
	}
}

func authRefreshIntervalValidation(duration time.Duration, durStr string) time.Duration {
	if duration < 60*time.Second {
		log.Warningf("'%s' of %s appears as less than 60s. Using fallback of 5m", param.Xrootd_AuthRefreshInterval.GetName(), durStr)
		return time.Minute * 5
	}
	return duration
}

func evictionMonitoringIntervalValidation(duration time.Duration, durStr string) time.Duration {
	if duration < 0*time.Second {
		log.Warningf("'%s' of %s is a negative value. Using the absolute value.", param.Cache_EvictionMonitoringInterval.GetName(), durStr)
		duration = -duration
	} else if duration > 0*time.Second && duration < 5*time.Second {
		log.Warningf("'%s' of %s appears as less than 5s. This is a very frequent interval and may cause performance issues", param.Cache_EvictionMonitoringInterval.GetName(), durStr)
	}
	return duration
}

func httpMaxDelayValidation(duration time.Duration, durStr string) time.Duration {
	// Normalize to whole seconds; XRootD expects seconds granularity
	if duration%time.Second != 0 {
		duration = duration.Round(time.Second)
		if duration == 0 && durStr != "0" {
			// Round could bring small positive values to 0s; avoid that
			duration = 1 * time.Second
		}
	}

	// Disallow non-positive and too-small values; fallback to 9s (our default)
	if duration <= 0 {
		log.Warningf("'%s' of %s is not positive. Using fallback of 9s", param.Xrootd_HttpMaxDelay.GetName(), durStr)
		return 9 * time.Second
	}
	if duration < 3*time.Second {
		log.Warningf("'%s' of %s appears as less than 3s. Using fallback of 9s", param.Xrootd_HttpMaxDelay.GetName(), durStr)
		return 9 * time.Second
	}

	// Warn for unusually large values that can cause server-side backlogs
	if duration > 1*time.Minute {
		log.Warningf("'%s' of %s is very large and may cause server-side backlogs; consider a small value such as 9s-12s", param.Xrootd_HttpMaxDelay.GetName(), durStr)
	}
	return duration
}

// A wrapper to combine multiple decoder hook functions for XRootD cfg unmarshalling
func xrootdDecodeHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		durationStrToSecondsHookFuncGenerator("XrootdOptions", "authrefreshinterval", param.Xrootd_AuthRefreshInterval.GetName(), authRefreshIntervalValidation),
		durationStrToSecondsHookFuncGenerator("XrootdOptions", "httpmaxdelay", param.Xrootd_HttpMaxDelay.GetName(), httpMaxDelayValidation),
		durationStrToSecondsHookFuncGenerator("CacheConfig", "evictionmonitoringinterval", param.Cache_EvictionMonitoringInterval.GetName(), evictionMonitoringIntervalValidation),
		server_utils.OriginExportsDecoderHook(),
	)
}

func ConfigXrootd(ctx context.Context, isOrigin bool) (string, error) {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	configSnapshot, err := param.GetUnmarshaledConfig()
	if err != nil {
		configSnapshot, err = param.Refresh()
		if err != nil {
			return "", errors.Wrap(err, "failed to load configuration for xrootd")
		}
	}

	var xrdConfig XrootdConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		DecodeHook:       xrootdDecodeHook(),
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(mapKey, fieldName)
		},
		Result: &xrdConfig,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to build xrootd config decoder")
	}

	if err := decoder.Decode(configSnapshot); err != nil {
		return "", errors.Wrap(err, "failed to decode xrootd config from parameters")
	}

	// Ensure monitoring endpoints use the actual listener port configured by SetUpMonitoring.
	monitorPort := param.Xrootd_LocalMonitoringPort.GetInt()
	if monitorPort <= 0 {
		return "", errors.Errorf("%s must be set by SetUpMonitoring before generating xrootd config", param.Xrootd_LocalMonitoringPort.GetName())
	}
	xrdConfig.Xrootd.LocalMonitoringPort = monitorPort

	if !isOrigin {
		pssOrigin, err := ensureCachePSSOrigin(ctx)
		if err != nil {
			return "", err
		}
		xrdConfig.Cache.PSSOrigin = pssOrigin

		// For cache watermarks, convert integer percentage value [0,100] to decimal fraction [0.00, 1.00]
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

		// Set up Lotman config
		lotmanCfg := LotmanCfg{Enabled: false}
		if param.Cache_EnableLotman.GetBool() {
			lotmanCfg.Enabled = true
			lotmanCfg.LotHome = param.Lotman_LotHome.GetString()
			policyMap, err := lotman.GetPolicyMap()
			if err != nil {
				return "", errors.Wrap(err, "unable to parse lotman configuration")
			}

			enabledPolicy := param.Lotman_EnabledPolicy.GetString()
			if _, exists := policyMap[enabledPolicy]; !exists {
				return "", errors.Errorf("policy %s is not defined in the lotman configuration", enabledPolicy)
			}

			purgeOrder := policyMap[enabledPolicy].PurgeOrder
			if len(purgeOrder) == 0 {
				return "", errors.Errorf("lotman policy %s has an undefined purge order", enabledPolicy)
			}
			lotmanCfg.PurgeOrder = purgeOrder
		}
		xrdConfig.Cache.LotmanCfg = lotmanCfg
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

		switch xrdConfig.Origin.StorageType {
		case "https":
			if xrdConfig.Origin.HttpServiceUrl == "" {
				xrdConfig.Origin.HttpServiceUrl = param.Origin_HttpServiceUrl.GetString()
			}
			if xrdConfig.Origin.FederationPrefix == "" {
				xrdConfig.Origin.FederationPrefix = param.Origin_FederationPrefix.GetString()
			}
		case "globus":
			xrdConfig.Origin.StorageType = "globus"
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
					xrdConfig.Origin.HttpAuthTokenFile = globusExports[0].TokenFile
					xrdConfig.Origin.GlobusTransferTokenFile = globusExports[0].TransferTokenFile
				}
			}
		}
	}

	// Map out xrootd logs
	err = mapXrootdLogLevels(&xrdConfig)
	if err != nil {
		return "", err
	}

	runtimeXRootdDir := filepath.Join(param.Origin_RunLocation.GetString())
	if !isOrigin {
		runtimeXRootdDir = filepath.Join(param.Cache_RunLocation.GetString())
	}
	// Set up the runtime CA bundle
	runtimeCAs := runtimeXRootdDir
	// If we plan to drop privileges, we'll write the CA bundle to a location that is owned
	// by the pelican daemon.  Since it's going to be marked as world-readable, we don't need
	// to periodically update it as the xrootd user like we do for the host key.
	if param.Server_DropPrivileges.GetBool() {
		runtimeCAs = filepath.Join(runtimeCAs, "pelican")
		puser, err := config.GetPelicanUser()
		if err != nil {
			return "", err
		}
		if err = config.MkdirAll(runtimeCAs, 0755, puser.Uid, puser.Gid); err != nil {
			return "", errors.Wrapf(err, "Unable to create runtime directory %v", runtimeCAs)
		}
	}
	runtimeCAs = filepath.Join(runtimeCAs, "ca-bundle.crt")
	egrpKey := string(config.EgrpKey)
	caCount, err := utils.LaunchPeriodicWriteCABundle(ctx, egrpKey, runtimeCAs, 2*time.Minute)
	if err != nil {
		return "", errors.Wrap(err, "Failed to setup the runtime CA bundle")
	}
	log.Debugf("A total of %d CA certificates were written", caCount)
	if caCount > 0 {
		xrdConfig.Server.TLSCACertificateFile = runtimeCAs
	}

	runtimeCertPath := filepath.Join(runtimeXRootdDir, "copied-tls-creds.crt")
	xrdConfig.Server.TLSCertificateChain = runtimeCertPath

	pkcs11Info := p11proxy.CurrentInfo()
	pkcs11Active := param.Server_EnablePKCS11.GetBool() && pkcs11Info.Enabled
	if pkcs11Active {
		xrdConfig.Server.TLSKey = pkcs11Info.PKCS11URL
	} else {
		if param.Server_EnablePKCS11.GetBool() && !pkcs11Info.Enabled {
			log.Warn("Server.EnablePKCS11 is true but the PKCS#11 helper is not active; falling back to the local TLS key file for XRootD")
		}
		xrdConfig.Server.TLSKey = runtimeCertPath
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
				log.Warningf("The Director URL (%s) does not contain an explicit port number; XRootD 5.6.3 and earlier are known to segfault in this case", xrdConfig.Cache.PSSOrigin)
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
		monitorPort, err = metrics.LaunchShoveler(ctx, egrp)
		if err != nil {
			return err
		}
	}

	if err := param.Set(param.Xrootd_LocalMonitoringPort.GetName(), monitorPort); err != nil {
		return err
	}

	return nil
}

// genLoggingConfig is a helper function that handles mapping input log levels to
// log levels for XRootD components. In the event that the input log level doesn't have
// a concretely-defined mapping for the XRootD component, it will get the next best level
// of verbocity for which there is a defined mapping. If the input log level is empty, it
// will inherit the log level from Pelican's log level.
//
// For example, an input loggingMap of:
//
//	loggingMap{
//	  Info:  "bar",
//	  Error: "foo",
//	}
//
// Should result in the following mappings:
//
//	"trace" --> "bar"
//	"debug" --> "bar"
//	"info"  --> "bar"
//	"warn"  --> "bar"
//	"error" --> "foo"
//	"fatal" --> "foo"
//	"panic" --> "foo"
func genLoggingConfig(input string, logMap loggingMap) (string, error) {
	// If no input is configured, inherit from Pelican's log level
	if input == "" {
		// Grab the log level directly from param, not from the logrus object
		// itself, which has a lot of fancy schmancy stuff that in effect makes it look
		// like it's debug when Pelican uses its default "Error" level.
		input = param.Logging_Level.GetString()
	}

	// Note that while Pelican itself doesn't take a "warning" level, when
	// logrus parses a level of "warn" it converts it to "warning". By
	// adding "Warning" here, we'll automatically fall down to the "Warn" level
	// if we happen to grab a log level that passed through logrus without being
	// mapped back "warn".
	orderedLevels := []string{
		"Panic",
		"Fatal",
		"Error",
		"Warning",
		"Warn",
		"Info",
		"Debug",
		"Trace",
	}

	levelMap := make(map[string]string, len(orderedLevels))
	v := reflect.ValueOf(logMap)

	var lastValidValue string
	comeBackTo := make([]string, 0, len(orderedLevels))
	goneBack := false
	for _, level := range orderedLevels {
		field := v.FieldByName(level)
		if field.IsValid() && field.Kind() == reflect.String && field.String() != "" {
			lastValidValue = field.String()
		}
		// If we haven't yet encountered a valid log level for the component,
		// we need to back-assign the first valid map we find.
		if lastValidValue == "" && !goneBack {
			comeBackTo = append(comeBackTo, level)
			continue
		}
		if !goneBack {
			goneBack = true
			for _, unmappedLevel := range comeBackTo {
				levelMap[strings.ToLower(unmappedLevel)] = lastValidValue
			}
		}

		levelMap[strings.ToLower(level)] = lastValidValue
	}

	// Just in case the programmer provided an empty map
	if len(levelMap) == 0 {
		return "", errors.New("the logging map is empty -- this is a Pelican bug, not a user error!")
	}

	level := levelMap[strings.ToLower(input)]
	if level == "" {
		return "", errors.Errorf("unrecognized input log level '%s'", input)
	}

	return level, nil
}

// mapXrootdLogLevels is utilized to map Pelican config values to Xrootd ones
// this is used to keep our log levels for Xrootd simple, so one does not need
// to be an Xrootd expert to understand the inconsistent logs within Xrootd
func mapXrootdLogLevels(xrdConfig *XrootdConfig) error {
	/////////////////////////ORIGIN/////////////////////////////
	// Origin Cms
	// https://xrootd.slac.stanford.edu/doc/dev54/cms_config.htm
	var err error
	if xrdConfig.Logging.OriginCms, err = genLoggingConfig(param.Logging_Origin_Cms.GetString(), loggingMap{
		Trace: "debug",
		Debug: "debug",
		Info:  "all",
		Error: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Cms")
	}

	// Origin Scitokens
	// https://github.com/xrootd/xrootd/blob/8f8498d66aa583c54c0875bb1cfe432f4be040f4/src/XrdSciTokens/XrdSciTokensAccess.cc#L951-L963
	if xrdConfig.Logging.OriginScitokens, err = genLoggingConfig(param.Logging_Origin_Scitokens.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug info warning error",
		Info:  "info warning error",
		Warn:  "warning error",
		Error: "error",
		Fatal: "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Scitokens")
	}

	// Origin Xrd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	if xrdConfig.Logging.OriginXrd, err = genLoggingConfig(param.Logging_Origin_Xrd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Xrd")
	}

	// Origin Xrootd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	if xrdConfig.Logging.OriginXrootd, err = genLoggingConfig(param.Logging_Origin_Xrootd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug emsg login stall redirect request stall",
		Info:  "emsg login stall redirect", // what we had set originally
		Warn:  "emsg",                      // errors sent back to the client
		Error: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Xrootd")
	}

	// Origin Ofs
	// https://xrootd.slac.stanford.edu/doc/dev56/ofs_config.htm
	if xrdConfig.Logging.OriginOfs, err = genLoggingConfig(param.Logging_Origin_Ofs.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "info",
		Warn:  "most",
		Error: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Ofs")
	}

	// Origin Oss
	if xrdConfig.Logging.OriginOss, err = genLoggingConfig(param.Logging_Origin_Oss.GetString(), loggingMap{
		Trace: "dump debug info warning error",
		Debug: "debug info warning error",
		Info:  "info warning error",
		Warn:  "warning error",
		Error: "error",
		Fatal: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Oss")
	}

	// Origin HTTP
	if xrdConfig.Logging.OriginHttp, err = genLoggingConfig(param.Logging_Origin_Http.GetString(), loggingMap{
		Debug: "all",
		Info:  "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Origin.Http")
	}

	//////////////////////////CACHE/////////////////////////////
	// Cache Ofs
	// https://xrootd.slac.stanford.edu/doc/dev56/ofs_config.htm
	if xrdConfig.Logging.CacheOfs, err = genLoggingConfig(param.Logging_Cache_Ofs.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "info",
		Warn:  "most",
		Error: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Ofs")
	}

	// Cache Pfc
	// https://xrootd.slac.stanford.edu/doc/dev56/pss_config.htm
	if xrdConfig.Logging.CachePfc, err = genLoggingConfig(param.Logging_Cache_Pfc.GetString(), loggingMap{
		Trace: "dump",
		Debug: "debug",
		Info:  "info",
		Warn:  "warning",
		Error: "error",
		Fatal: "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Pfc")
	}

	// Cache PssSetOptCache and Cache Pss
	// https://xrootd.slac.stanford.edu/doc/dev56/pss_config.htm
	// Note: pss has interesting config options:
	// all     informational events.
	// on      warning events.
	// debug   error events.
	// Therefore the following pss.trace I came up with is what follows:
	if xrdConfig.Logging.CachePss, err = genLoggingConfig(param.Logging_Cache_Pss.GetString(), loggingMap{
		Trace: "all",
		Info:  "on",
		Warn:  "debug",
		Error: "off",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Pss")
	}

	// Cache Setopt:
	if xrdConfig.Logging.PssSetOptCache, err = genLoggingConfig(param.Logging_Cache_PssSetOpt.GetString(), loggingMap{
		Debug: "DebugLevel 4",
		Info:  "DebugLevel 3",
		Warn:  "DebugLevel 2",
		Error: "DebugLevel 1",
		Fatal: "DebugLevel 0",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.PssSetOpt")
	}

	// Cache HTTP
	if xrdConfig.Logging.CacheHttp, err = genLoggingConfig(param.Logging_Cache_Http.GetString(), loggingMap{
		Debug: "all",
		Info:  "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Http")
	}

	// Cache Lotman
	// lotman.trace levels are additive: trace includes all levels, info includes warning and error, etc.
	// Supported values: none, error, warning, info, debug, trace
	if xrdConfig.Logging.CacheLotman, err = genLoggingConfig(param.Logging_Cache_Lotman.GetString(), loggingMap{
		Trace: "trace",
		Debug: "debug",
		Info:  "info",
		Warn:  "warning",
		Error: "error",
		Fatal: "none",
		Panic: "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for %s", param.Logging_Cache_Lotman.GetName())
	}

	// Cache Scitokens
	// https://github.com/xrootd/xrootd/blob/8f8498d66aa583c54c0875bb1cfe432f4be040f4/src/XrdSciTokens/XrdSciTokensAccess.cc#L951-L963
	if xrdConfig.Logging.CacheScitokens, err = genLoggingConfig(param.Logging_Cache_Scitokens.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug info warning error",
		Info:  "info warning error",
		Warn:  "warning error",
		Error: "error",
		Fatal: "none",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Scitokens")
	}

	// Cache Xrd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	if xrdConfig.Logging.CacheXrd, err = genLoggingConfig(param.Logging_Cache_Xrd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug",
		Info:  "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Xrd")
	}

	// Cache Xrootd
	// https://xrootd.slac.stanford.edu/doc/dev56/xrd_config.htm
	if xrdConfig.Logging.CacheXrootd, err = genLoggingConfig(param.Logging_Cache_Xrootd.GetString(), loggingMap{
		Trace: "all",
		Debug: "debug emsg login stall redirect request stall",
		Info:  "emsg login stall redirect", // what we had set originally
		Warn:  "emsg",                      // errors sent back to the client
		Error: "-all",
	}); err != nil {
		return errors.Wrapf(err, "failed to map logging level for Logging.Cache.Xrootd")
	}

	return nil
}
