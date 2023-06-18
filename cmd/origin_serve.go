
package main

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"os"
	"os/user"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/pelicanplatform/pelican"
	"github.com/pkg/errors"
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
	Port int
	ManagerHost string
	ManagerPort string
	TLSCertificate string
	TLSKey string
	TLSCertDir string
	MacaroonsKeyFile string
	RobotsTxtFile string
	Sitename string
	SummaryMonitoringHost string
	SummaryMonitoringPort int
	DetailedMonitoringHost string
	DetailedMonitoringPort int
	XrootdRun string
	Mount string
	Authfile string
	ScitokensConfig string
	NamespacePrefix string
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
	if pelican.IsRootExecution() {
		viper.SetDefault("TLSCertificate", "/etc/pelican/certificates/tls.crt")
		viper.SetDefault("TLSKey", "/etc/pelican/certificates/tls.key")
		viper.SetDefault("XrootdRun", "/run/pelican/xrootd")
		viper.SetDefault("RobotsTxtFile", "/etc/pelican/robots.txt")
		viper.SetDefault("ScitokensConfig", "/etc/pelican/xrootd/scitokens.cfg")
		viper.SetDefault("Authfile", "/etc/pelican/xrootd/authfile")
		viper.SetDefault("MacaroonsKeyFile", "/etc/pelican/macaroons-secret")
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

		if userRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); userRuntimeDir != "" {
			runtimeDir := filepath.Join(userRuntimeDir, "pelican")
			err := os.MkdirAll(runtimeDir, 0750)
			if err != nil {
				cobra.CheckErr(err)
			}
			viper.SetDefault("XrootdRun", runtimeDir)
		} else {
			dir, err := os.MkdirTemp("", "pelican-xrootd-*")
			cobra.CheckErr(err)
			viper.SetDefault("XrootdRun", dir)
			cleanupDirOnShutdown(dir)
		}
	}

	err := viper.MergeConfig(strings.NewReader(defaultsYaml))
	if err != nil {
		panic(err)
	}

	prefix := pelican.GetPreferredPrefix()
	if prefix == "OSDF" {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			panic(err)
		}
	}
}

func checkXrootdEnv() error {
	// Ensure the runtime directory exists
	runtimeDir := viper.GetString("XrootdRun")
	err := os.MkdirAll(runtimeDir, 0750)
	if err != nil {
		return errors.Wrapf(err, "Unable to create runtime directory %v", runtimeDir)
	}
	userObj, err := user.Current()
	if err != nil {
		return err
	}
	desiredUsername := userObj.Username
	if pelican.IsRootExecution() {
		desiredUsername = "xrootd"
		userObj, err = user.Lookup(desiredUsername)
		if err != nil {
			return errors.Wrap(err, "Unable to lookup the xrootd runtime user" +
				" information; does the xrootd user exist?")
		}
	}
	uid, err := strconv.Atoi(userObj.Uid)
	if err != nil {
		return err
	}
	if err = os.Chown(runtimeDir, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of runtime directory %v" +
			" to desired daemon user %v", runtimeDir, userObj.Username)
	}

	// If no robots.txt, create a ephemeral one for xrootd to use
	robotsTxtFile := viper.GetString("RobotsTxtFile")
	if _, err := os.Open(robotsTxtFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			newPath := filepath.Join(runtimeDir, "robots.txt")
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
			file, err := os.OpenFile(macaroonsSecret, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return errors.Wrap(err, "Failed to create a new macaroons key")
			}
			defer file.Close()
			buf := make([]byte, 64)
			_, err = rand.Read(buf)
			if err != nil {
				return err
			}
			if _, err = file.Write(buf); err != nil {
				return errors.Wrap(err, "Failed to write out a macaroons key")
			}
		} else {
			return err
		}
	}

	return nil
}

func checkConfigFileReadable(fileName string, errMsg string) error {
	if _, err := os.Open(fileName); errors.Is(err, os.ErrNotExist) {
		return errors.New(fmt.Sprintf("%v: the specified path in the configuration (%v) " +
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

func launchXrootd() error {
	var config XrootdConfig
	viper.Unmarshal(&config)
	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))
	err := templ.Execute(os.Stdout, config)
	if err != nil {
		return err
	}

	return nil
}

func serve(/*cmd*/ *cobra.Command, /*args*/ []string) error {
	defer func() {
		if tempRunDir != "" {
			os.RemoveAll(tempRunDir)
		}
	} ()

	err := checkDefaults()
	if err != nil {
		fmt.Println("Fatal error:")
		fmt.Println(err.Error())
		return err
	}

	err = launchXrootd()
	if err != nil {
		fmt.Println("Fatal error:", err.Error())
		return err
	}
	return nil
}
