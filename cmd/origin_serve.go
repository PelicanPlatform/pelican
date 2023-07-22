//go:build !windows

package main

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (

	//go:embed resources/defaults.yaml
	defaultsYaml string
	//go:embed resources/osdf.yaml
	osdfDefaultsYaml string
	//go:embed resources/xrootd.cfg
	xrootdCfg string
	//go:embed resources/robots.txt
	robotsTxt string

	// Potentially holds a directory to cleanup
	tempRunDir string
)

type XrootdConfig struct {
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
	XrootdMultiuser        bool
	LocalMonitoringPort    int
}

func cleanupDirOnShutdown(dir string) {
	sigs := make(chan os.Signal, 1)
	tempRunDir = dir
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigs
		os.RemoveAll(dir)
	}()
}

func init() {
	viper.SetConfigType("yaml")
	if config.IsRootExecution() {
		viper.SetDefault("TLSCertificate", "/etc/pelican/certificates/tls.crt")
		viper.SetDefault("TLSKey", "/etc/pelican/certificates/tls.key")
		viper.SetDefault("XrootdRun", "/run/pelican/xrootd")
		viper.SetDefault("GeoIPLocation", "/run/pelican/geoip/GeoIP2.mmdb")
		viper.SetDefault("MaxMindKeyFile", "/run/pelican/maxmind/maxmind.key")
		viper.SetDefault("RobotsTxtFile", "/etc/pelican/robots.txt")
		viper.SetDefault("ScitokensConfig", "/etc/pelican/xrootd/scitokens.cfg")
		viper.SetDefault("Authfile", "/etc/pelican/xrootd/authfile")
		viper.SetDefault("MacaroonsKeyFile", "/etc/pelican/macaroons-secret")
		viper.SetDefault("IssuerKey", "/etc/pelican/issuer.jwk")
		viper.SetDefault("XrootdMultiuser", true)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		configBase := filepath.Join(home, ".config", "pelican")
		viper.SetDefault("TLSCertificate", filepath.Join(configBase, "certificates", "tls.crt"))
		viper.SetDefault("TLSKey", filepath.Join(configBase, "certificates", "tls.key"))
		viper.SetDefault("RobotsTxtFile", filepath.Join(configBase, "robots.txt"))
		viper.SetDefault("ScitokensConfig", filepath.Join(configBase, "xrootd", "scitokens.cfg"))
		viper.SetDefault("Authfile", filepath.Join(configBase, "xrootd", "authfile"))
		viper.SetDefault("MacaroonsKeyFile", filepath.Join(configBase, "macaroons-secret"))
		viper.SetDefault("IssuerKey", filepath.Join(configBase, "issuer.jwk"))
		viper.SetDefault("MaxMindKeyFile", filepath.Join(configBase, "maxmind.key"))

		var runtimeDir string
		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir = filepath.Join(userRuntimeDir, "pelican")
		} else {
			runtimeDir, err = os.MkdirTemp("", "pelican-xrootd-*")
			cobra.CheckErr(err)
			cleanupDirOnShutdown(runtimeDir)
		}
		xrootdRuntimeDir := filepath.Join(runtimeDir, "xrootd")
		if err = os.MkdirAll(xrootdRuntimeDir, 0750); err != nil {
			cobra.CheckErr(err)
		}
		viper.SetDefault("XrootdRun", xrootdRuntimeDir)

		geoipRuntimeDir := filepath.Join(runtimeDir, "geoip")
		if err = os.MkdirAll(geoipRuntimeDir, 0750); err != nil {
			cobra.CheckErr(err)
		}
		viper.SetDefault("GeoIPLocation", filepath.Join(geoipRuntimeDir, "GeoIP2.mmdb"))

		viper.SetDefault("XrootdMultiuser", false)
	}
	viper.SetDefault("TLSCertFile", "/etc/pki/tls/cert.pem")

	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	viper.SetDefault("Sitename", hostname)

	err = viper.MergeConfig(strings.NewReader(defaultsYaml))
	if err != nil {
		panic(err)
	}

	prefix := config.GetPreferredPrefix()
	if prefix == "OSDF" {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			panic(err)
		}
	}
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
	runtimeDir := viper.GetString("XrootdRun")
	err = os.MkdirAll(runtimeDir, 0755)
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
		err = os.MkdirAll(filepath.Dir(destPath), 0755)
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
		err = os.MkdirAll(filepath.Dir(destPath), 0755)
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
	err = os.MkdirAll(wellKnownPath, 0755)
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
	robotsTxtFile := viper.GetString("RobotsTxtFile")
	if _, err := os.Open(robotsTxtFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			newPath := filepath.Join(runtimeDir, "robots.txt")
			err = os.MkdirAll(path.Dir(newPath), 0755)
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
			err = os.MkdirAll(path.Dir(macaroonsSecret), 0755)
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
	err = os.MkdirAll(path.Dir(authfile), 0755)
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

	scitokensCfg := viper.GetString("ScitokensConfig")
	err = os.MkdirAll(path.Dir(scitokensCfg), 0755)
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
		mgr := viper.GetString(configName)
		if mgr == "" {
			return errors.New(fmt.Sprintf("Required value of '%v' is not set in config",
				configName))
		}
	}

	// As necessary, generate a private key and corresponding cert
	if err := config.GeneratePrivateKey(viper.GetString("TLSKey")); err != nil {
		return err
	}
	if err := config.GenerateCert(); err != nil {
		return err
	}

	// TODO: Could upgrade this to a check for a cert in the file...
	if err := checkConfigFileReadable(viper.GetString("TLSCertificate"),
		"A TLS certificate is required to serve HTTPS"); err != nil {
		return err
	}
	if err := checkConfigFileReadable(viper.GetString("TLSKey"),
		"A TLS key is required to serve HTTPS"); err != nil {
		return err
	}

	if err := checkXrootdEnv(); err != nil {
		return err
	}

	return nil
}

func configXrootd() (string, error) {
	var config XrootdConfig
	config.LocalMonitoringPort = -1
	if err := viper.Unmarshal(&config); err != nil {
		return "", err
	}
	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))

	xrootdRun := viper.GetString("XrootdRun")
	configPath := filepath.Join(xrootdRun, "xrootd.cfg")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()

	err = templ.Execute(file, config)
	if err != nil {
		return "", err
	}

	return configPath, nil
}

func forwardCommandToLogger(daemonName string, cmd *exec.Cmd, isDoneChannel chan error) error {
	cmdStdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmdStderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	go func() {
		cmd_logger := log.WithFields(log.Fields{"daemon": daemonName})
		stdout_scanner := bufio.NewScanner(cmdStdout)
		stdout_lines := make(chan string, 10)

		stderr_scanner := bufio.NewScanner(cmdStderr)
		stderr_lines := make(chan string, 10)
		go func() {
			defer close(stdout_lines)
			for stdout_scanner.Scan() {
				stdout_lines <- stdout_scanner.Text()
			}
		}()
		go func() {
			defer close(stderr_lines)
			for stderr_scanner.Scan() {
				stderr_lines <- stderr_scanner.Text()
			}
		}()
		for {
			select {
			case stdout_line, ok := <-stdout_lines:
				if ok {
					cmd_logger.Info(stdout_line)
				} else {
					stdout_lines = nil
				}
			case stderr_line, ok := <-stderr_lines:
				if ok {
					cmd_logger.Info(stderr_line)
				} else {
					stderr_lines = nil
				}
			}
			if stdout_lines == nil && stderr_lines == nil {
				break
			}
		}
		result := cmd.Wait()
		isDoneChannel <- result
		close(isDoneChannel)
	}()
	return nil
}

func launchXrootd() error {
	configPath, err := configXrootd()
	if err != nil {
		return err
	}
	xrootdCmd := exec.Command("xrootd", "-f", "-c", configPath)
	if xrootdCmd.Err != nil {
		return xrootdCmd.Err
	}
	xrootdDoneChannel := make(chan error, 1)
	if err := forwardCommandToLogger("xrootd", xrootdCmd, xrootdDoneChannel); err != nil {
		return err
	}
	if err := xrootdCmd.Start(); err != nil {
		return err
	}
	log.Info("Successfully launched xrootd")

	cmsdCmd := exec.Command("cmsd", "-f", "-c", configPath)
	if cmsdCmd.Err != nil {
		return cmsdCmd.Err
	}
	cmsdDoneChannel := make(chan error, 1)
	if err := forwardCommandToLogger("cmsd", cmsdCmd, cmsdDoneChannel); err != nil {
		return err
	}
	if err := cmsdCmd.Start(); err != nil {
		return err
	}
	log.Info("Successfully launched cmsd")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	var xrootdExpiry time.Time
	var cmsdExpiry time.Time
	for {
		timer := time.NewTimer(time.Second)
		select {
		case sig := <-sigs:
			if sys_sig, ok := sig.(syscall.Signal); ok {
				log.Warnf("Forwarding signal %v to xrootd processes\n", sys_sig)
				if err = syscall.Kill(xrootdCmd.Process.Pid, sys_sig); err != nil {
					return errors.Wrap(err, "Failed to forward signal to xrootd process")
				}
				if err = syscall.Kill(cmsdCmd.Process.Pid, sys_sig); err != nil {
					return errors.Wrap(err, "Failed to forward signal to cmsd process")
				}
			} else {
				panic(errors.New("Unable to convert signal to syscall.Signal"))
			}
			xrootdExpiry = time.Now().Add(10 * time.Second)
			cmsdExpiry = time.Now().Add(10 * time.Second)
		case waitResult := <-xrootdDoneChannel:
			if waitResult != nil {
				if !cmsdExpiry.IsZero() {
					return nil
				}
				return errors.Wrap(waitResult, "xrootd process failed unexpectedly")
			}
			return nil
		case waitResult := <-cmsdDoneChannel:
			if waitResult != nil {
				if !xrootdExpiry.IsZero() {
					return nil
				}
				return errors.Wrap(waitResult, "cmsd process failed unexpectedly")
			}
			return nil
		case <-timer.C:
			if !xrootdExpiry.IsZero() && time.Now().After(xrootdExpiry) {
				if err = syscall.Kill(xrootdCmd.Process.Pid, syscall.SIGKILL); err != nil {
					return errors.Wrap(err, "Failed to SIGKILL the xrootd process")
				}
			}
			if !cmsdExpiry.IsZero() && time.Now().After(cmsdExpiry) {
				if err = syscall.Kill(cmsdCmd.Process.Pid, syscall.SIGKILL); err != nil {
					return errors.Wrap(err, "Failed to SIGKILL the cmsd process")
				}
			}
		}
	}
}

func serveOrigin( /*cmd*/ *cobra.Command /*args*/, []string) error {
	defer func() {
		if tempRunDir != "" {
			os.RemoveAll(tempRunDir)
		}
	}()

	monitorPort, err := pelican.ConfigureMonitoring()
	if err != nil {
		return err
	}
	viper.Set("LocalMonitoringPort", monitorPort)

	err = checkDefaults()
	if err != nil {
		return err
	}

	engine := gin.New()
	engine.Use(gin.Recovery())
	webLogger := log.WithFields(log.Fields{"daemon": "gin"})
	engine.Use(func(ctx *gin.Context) {
		startTime := time.Now()

		ctx.Next()

		latency := time.Since(startTime)
		webLogger.WithFields(log.Fields{"method": ctx.Request.Method,
			"status": ctx.Writer.Status(),
			"time": latency.String(),
			"client": ctx.RemoteIP(),
			"resource": ctx.Request.URL.Path},
		).Info("Served Request")
	})
	if err = pelican.ConfigureMetrics(engine); err != nil {
		return err
	}
	if err = origin_ui.ConfigureOriginUI(engine); err != nil {
		return err
	}

	engine.GET("/api/v1.0/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	go func() {
		err = engine.Run()
		if err != nil {
			panic(err)
		}
	}()
	err = launchXrootd()
	if err != nil {
		return err
	}
	log.Info("Clean shutdown of the origin")
	return nil
}
