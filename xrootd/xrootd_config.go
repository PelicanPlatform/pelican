package xrootd

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	//go:embed resources/xrootd.cfg
	xrootdCfg string
	//go:embed resources/robots.txt
	robotsTxt string
)

type (
	OriginConfig struct {
		Multiuser       bool
		UseCmsd         bool
		UseMacaroons    bool
		UseVoms         bool
		SelfTest        bool
		NamespacePrefix string
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
	}
)

func CheckXrootdEnv(origin bool) error {
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

	exportPath := filepath.Join(runtimeDir, "export")
	if _, err := os.Stat(exportPath); err == nil {
		if err = os.RemoveAll(exportPath); err != nil {
			return errors.Wrap(err, "Failure when cleaning up temporary export tree")
		}
	}

	// If we use "volume mount" style options, configure the export directories.
	if origin {
		volumeMount := param.Origin_ExportVolume.GetString()
		if volumeMount != "" {
			volumeMount, err = filepath.Abs(volumeMount)
			if err != nil {
				return err
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
				return fmt.Errorf("Export volume %v has empty destination path", volumeMount)
			}
			if volumeMountDst[0:1] != "/" {
				return fmt.Errorf("Export volume %v has a relative destination path",
					volumeMountDst)
			}
			destPath := path.Clean(filepath.Join(exportPath, volumeMountDst[1:]))
			err = config.MkdirAll(filepath.Dir(destPath), 0755, uid, gid)
			if err != nil {
				return errors.Wrapf(err, "Unable to create export directory %v",
					filepath.Dir(destPath))
			}
			err = os.Symlink(volumeMountSrc, destPath)
			if err != nil {
				return errors.Wrapf(err, "Failed to create export symlink")
			}
			viper.Set("Origin.NamespacePrefix", volumeMountDst)
		} else {
			mountPath := param.Xrootd_Mount.GetString()
			namespacePrefix := param.Origin_NamespacePrefix.GetString()
			if mountPath == "" || namespacePrefix == "" {
				return errors.New(`Export information was not provided.
Add command line flag:

    -v /mnt/foo:/bar

to export the directory /mnt/foo to the path /bar in the data federation`)
			}
			mountPath, err := filepath.Abs(mountPath)
			if err != nil {
				return err
			}
			mountPath = filepath.Clean(mountPath)
			namespacePrefix = filepath.Clean(namespacePrefix)
			if namespacePrefix[0:1] != "/" {
				return fmt.Errorf("Namespace prefix %v must have an absolute path",
					namespacePrefix)
			}
			destPath := path.Clean(filepath.Join(exportPath, namespacePrefix[1:]))
			err = config.MkdirAll(filepath.Dir(destPath), 0755, uid, gid)
			if err != nil {
				return errors.Wrapf(err, "Unable to create export directory %v",
					filepath.Dir(destPath))
			}
			srcPath := filepath.Join(mountPath, namespacePrefix[1:])
			err = os.Symlink(srcPath, destPath)
			if err != nil {
				return errors.Wrapf(err, "Failed to create export symlink")
			}
		}
	}
	viper.Set("Xrootd.Mount", exportPath)

	if param.Origin_SelfTest.GetBool() {
		if err := origin_ui.ConfigureXrootdMonitoringDir(); err != nil {
			return err
		}
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
	if err = os.Chown(macaroonsSecret, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of macaroons secret %v"+
			" to desired daemon group %v", macaroonsSecret, groupname)
	}

	// If the authfile or scitokens.cfg does not exist, create one
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
			" to desired daemon group %v", macaroonsSecret, groupname)
	}

	if err := EmitAuthfile(); err != nil {
		return err
	}

	if err := WriteOriginScitokensConfig(); err != nil {
		return errors.Wrap(err, "Failed to create scitokens configuration for the origin")
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

func SetUpMonitoring() error {
	monitorPort, err := metrics.ConfigureMonitoring()
	if err != nil {
		return err
	}

	viper.Set("Xrootd.LocalMonitoringPort", monitorPort)

	return nil
}
