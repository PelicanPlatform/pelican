package xrootd

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	//go:embed resources/xrootd-origin.cfg
	xrootdOriginCfg string
	//go:embed resources/xrootd-cache.cfg
	xrootdCacheCfg string
	//go:embed resources/robots.txt
	robotsTxt string
)

type (
	OriginConfig struct {
		Multiuser        bool
		EnableCmsd       bool
		EnableMacaroons  bool
		EnableVoms       bool
		EnableDirListing bool
		SelfTest         bool
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
		ExportLocation string
		DataLocation   string
		DirectorUrl    string
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

	XrootdConfig struct {
		Server ServerConfig
		Origin OriginConfig
		Xrootd XrootdOptions
		Cache  CacheConfig
	}
)

func CheckOriginXrootdEnv(exportPath string, uid int, gid int, groupname string) (string, error) {
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
				return exportPath, fmt.Errorf("Export volume %v has empty destination path", volumeMount)
			}
			if volumeMountDst[0:1] != "/" {
				return "", fmt.Errorf("Export volume %v has a relative destination path",
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
				return exportPath, errors.New(`Export information was not provided.
		Add command line flag:

			-v /mnt/foo:/bar

		to export the directory /mnt/foo to the path /bar in the data federation`)
			}
			mountPath, err := filepath.Abs(mountPath)
			if err != nil {
				return exportPath, err
			}
			mountPath = filepath.Clean(mountPath)
			namespacePrefix = filepath.Clean(namespacePrefix)
			if namespacePrefix[0:1] != "/" {
				return exportPath, fmt.Errorf("Namespace prefix %v must have an absolute path",
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
	// Set up exportedPaths, which we later use to grant access to the origin's issuer.
	exportedPaths := viper.GetStringSlice("Origin.NamespacePrefix")
	if err := WriteOriginScitokensConfig(exportedPaths); err != nil {
		return exportPath, errors.Wrap(err, "Failed to create scitokens configuration for the origin")
	}

	if err := origin_ui.ConfigureXrootdMonitoringDir(); err != nil {
		return exportPath, err
	}

	return exportPath, nil
}

func CheckCacheXrootdEnv(exportPath string, uid int, gid int, nsAds []director.NamespaceAd) (string, error) {
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
	viper.Set("Cache.DirectorUrl", param.Federation_DirectorUrl.GetString())

	if err := WriteCacheScitokensConfig(nsAds); err != nil {
		return "", errors.Wrap(err, "Failed to create scitokens configuration for the cache")
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

	exportPath := filepath.Join(runtimeDir, "export")
	if _, err := os.Stat(exportPath); err == nil {
		if err = os.RemoveAll(exportPath); err != nil {
			return errors.Wrap(err, "Failure when cleaning up temporary export tree")
		}
	}

	if server.GetServerType().IsEnabled(config.OriginType) {
		exportPath, err = CheckOriginXrootdEnv(exportPath, uid, gid, groupname)
	} else {
		exportPath, err = CheckCacheXrootdEnv(exportPath, uid, gid, server.GetNamespaceAds())
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

	// If the authfile does not exist, create one
	authfile := param.Xrootd_Authfile.GetString()
	err = config.MkdirAll(path.Dir(authfile), 0755, -1, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create directory %v",
			path.Dir(authfile))
	}
	if file, err := os.OpenFile(authfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err = os.Chown(authfile, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of authfile %v"+
			" to desired daemon group %v", authfile, groupname)
	}

	if err := EmitAuthfile(server); err != nil {
		return err
	}

	return nil
}

func ConfigXrootd(origin bool) (string, error) {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	var xrdConfig XrootdConfig
	xrdConfig.Xrootd.LocalMonitoringPort = -1
	if err := viper.Unmarshal(&xrdConfig); err != nil {
		return "", err
	}

	runtimeCAs := filepath.Join(param.Xrootd_RunLocation.GetString(), "ca-bundle.crt")
	caCount, err := utils.PeriodicWriteCABundle(runtimeCAs, 2*time.Minute)
	if err != nil {
		return "", errors.Wrap(err, "Failed to setup the runtime CA bundle")
	}
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
	} else if xrdConfig.Cache.DirectorUrl != "" {
		// Workaround for a bug in XRootD 5.6.3: if the director URL is missing a port number, then
		// XRootD crashes.
		urlParsed, err := url.Parse(xrdConfig.Cache.DirectorUrl)
		if err != nil {
			return "", errors.Errorf("Director URL (%s) does not parse as a URL", xrdConfig.Cache.DirectorUrl)
		}
		if !strings.Contains(urlParsed.Host, ":") {
			switch urlParsed.Scheme {
			case "http":
				urlParsed.Host += ":80"
			case "https":
				urlParsed.Host += ":443"
			default:
				log.Warningf("The Director URL (%s) does not contain an explicit port number; XRootD 5.6.3 and earlier are known to segfault in thie case", xrdConfig.Cache.DirectorUrl)
			}
			xrdConfig.Cache.DirectorUrl = urlParsed.String()
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
func SetUpMonitoring(ctx context.Context, wg *sync.WaitGroup) error {
	monitorPort, err := metrics.ConfigureMonitoring(ctx, wg)
	if err != nil {
		return err
	}

	viper.Set("Xrootd.LocalMonitoringPort", monitorPort)

	return nil
}
