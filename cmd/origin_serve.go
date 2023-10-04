//go:build !windows

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

package main

import (
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
		Multiuser bool
	}

	XrootdConfig struct {
		Port                   int
		ManagerHost            string
		ManagerPort            string
		TLSCertificate         string
		TLSKey                 string
		TLSCertDir             string
		TLSCertFile            string
		MacaroonsKeyFile       string
		RobotsTxtFile          string
		Sitename               string
		SummaryMonitoringHost  string
		SummaryMonitoringPort  int
		DetailedMonitoringHost string
		DetailedMonitoringPort int
		XrootdRun              string
		Authfile               string
		ScitokensConfig        string
		Mount                  string
		NamespacePrefix        string
		LocalMonitoringPort    int
		Origin                 OriginConfig
	}
)

func init() {
	err := config.InitServer()
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("xrootd", "critical", "xrootd has not been started")
	cobra.CheckErr(err)
	err = metrics.SetComponentHealthStatus("cmsd", "critical", "cmsd has not been started")
	cobra.CheckErr(err)
}

func checkXrootdEnv() error {
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
	runtimeDir := config.XrootdRun.GetString()
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
	volumeMount := viper.GetString("ExportVolume")
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
		viper.Set("NamespacePrefix", volumeMountDst)
	} else {
		mountPath := viper.GetString("Mount")
		namespacePrefix := viper.GetString("NamespacePrefix")
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
	viper.Set("Mount", exportPath)

	keys, err := config.GenerateIssuerJWKS()
	if err != nil {
		return err
	}
	wellKnownPath := filepath.Join(exportPath, ".well-known")
	err = config.MkdirAll(wellKnownPath, 0755, -1, gid)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(wellKnownPath, "issuer.jwks"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	buf, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return errors.Wrap(err, "Failed to marshal public keys")
	}
	_, err = file.Write(buf)
	if err != nil {
		return errors.Wrap(err, "Failed to write public key set to export directory")
	}

	// If no robots.txt, create a ephemeral one for xrootd to use
	robotsTxtFile := config.RobotsTxtFile.GetString()
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
			viper.Set("RobotsTxtFile", newPath)
		} else {
			return err
		}
	}

	// If macaroons secret does not exist, create one
	macaroonsSecret := viper.GetString("MacaroonsKeyFile")
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
	authfile := viper.GetString("Authfile")
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

	scitokensCfg := config.ScitokensConfig.GetString()
	err = config.MkdirAll(path.Dir(scitokensCfg), 0755, -1, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create directory %v",
			path.Dir(scitokensCfg))
	}
	if file, err := os.OpenFile(scitokensCfg, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err = os.Chown(scitokensCfg, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of scitokens config %v"+
			" to desired daemon group %v", scitokensCfg, groupname)
	}

	return nil
}

func checkConfigFileReadable(fileName string, errMsg string) error {
	if _, err := os.Open(fileName); errors.Is(err, os.ErrNotExist) {
		return errors.New(fmt.Sprintf("%v: the specified path in the configuration (%v) "+
			"does not exist", errMsg, fileName))
	} else if err != nil {
		return errors.New(fmt.Sprintf("%v; an error occurred when reading %v: %v", errMsg,
			fileName, err.Error()))
	}
	return nil
}

func checkDefaults() error {
	requiredConfigs := []string{"ManagerHost", "SummaryMonitoringHost", "DetailedMonitoringHost",
		"TLSCertificate", "TLSKey", "XrootdRun", "RobotsTxtFile"}
	for _, configName := range requiredConfigs {
		mgr := viper.GetString(configName) // TODO: Remove direct access once all parameters are generated
		if mgr == "" {
			return errors.New(fmt.Sprintf("Required value of '%v' is not set in config",
				configName))
		}
	}

	// As necessary, generate a private key and corresponding cert
	if err := config.GeneratePrivateKey(config.TLSKey.GetString(), elliptic.P256()); err != nil {
		return err
	}
	if err := config.GenerateCert(); err != nil {
		return err
	}

	// TODO: Could upgrade this to a check for a cert in the file...
	if err := checkConfigFileReadable(config.TLSCertificate.GetString(),
		"A TLS certificate is required to serve HTTPS"); err != nil {
		return err
	}
	if err := checkConfigFileReadable(config.TLSKey.GetString(),
		"A TLS key is required to serve HTTPS"); err != nil {
		return err
	}

	if err := checkXrootdEnv(); err != nil {
		return err
	}

	// Check that OriginUrl is defined in the config file. Make sure it parses.
	// Fail if either condition isn't met, although note that url.Parse doesn't
	// generate errors for many things that are not recognizable urls.
	originUrlStr := viper.GetString("OriginUrl")
	if originUrlStr == "" {
		return errors.New("OriginUrl must be configured to serve an origin")
	}
	originUrlParsed, err := url.Parse(originUrlStr)
	if err != nil {
		return errors.Wrap(err, "Could not parse the provided OriginUrl")
	}

	if originUrlParsed.Port() == "" {
		// No port was specified, let's tack on whatever was passed in the
		// command line argument
		viper.Set("OriginUrl", originUrlParsed.String()+":"+fmt.Sprint(config.WebPort.GetInt()))
	} else if originUrlParsed.Port() != fmt.Sprint(config.WebPort.GetInt()) {
		// The web port configured via the config file and the webport configured
		// via commandline don't match. Perhaps the user is confused?
		return errors.New("Mismatched webports: from command line: " + fmt.Sprint(config.WebPort.GetInt()) +
			", from config file: " + originUrlParsed.Port() + ". Please ensure these match")
	}

	return nil
}

func configXrootd() (string, error) {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	var xrdConfig XrootdConfig
	xrdConfig.LocalMonitoringPort = -1
	if err := viper.Unmarshal(&xrdConfig); err != nil {
		return "", err
	}

	if xrdConfig.Origin.Multiuser {
		ok, err := config.HasMultiuserCaps()
		if err != nil {
			return "", errors.Wrap(err, "Failed to determine if the origin can run in multiuser mode")
		}
		if !ok {
			return "", errors.New("Origin.Multiuser is set to `true` but the command was run without sufficient privilege; was it launched as root?")
		}
	}

	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))

	xrootdRun := config.XrootdRun.GetString()
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

	return configPath, nil
}

func serveOrigin( /*cmd*/ *cobra.Command /*args*/, []string) error {
	defer config.CleanupTempResources()

	err := config.DiscoverFederation()
	if err != nil {
		log.Warningln("Failed to do service auto-discovery:", err)
	}

	monitorPort, err := metrics.ConfigureMonitoring()
	if err != nil {
		return err
	}
	viper.Set("LocalMonitoringPort", monitorPort)

	err = checkDefaults()
	if err != nil {
		return err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}
	if err = origin_ui.ConfigureOriginUI(engine); err != nil {
		return err
	}
	if err = origin_ui.PeriodicAdvertiseOrigin(); err != nil {
		return err
	}

	go web_ui.RunEngine(engine)
	if err = metrics.SetComponentHealthStatus("web-ui", "warning", "Authentication not initialized"); err != nil {
		return err
	}

	// Ensure we wait until the origin has been initialized
	// before launching XRootD.
	if err = origin_ui.WaitUntilLogin(); err != nil {
		return err
	}
	if err = metrics.SetComponentHealthStatus("web-ui", "ok", ""); err != nil {
		return err
	}

	configPath, err := configXrootd()
	if err != nil {
		return err
	}
	privileged := viper.GetBool("Origin.Multiuser")
	err = xrootd.LaunchXrootd(privileged, configPath)
	if err != nil {
		return err
	}
	log.Info("Clean shutdown of the origin")
	return nil
}
