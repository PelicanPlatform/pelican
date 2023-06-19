//go:build !windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"math/big"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

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
	TLSCertFile string
	MacaroonsKeyFile string
	RobotsTxtFile string
	Sitename string
	SummaryMonitoringHost string
	SummaryMonitoringPort int
	DetailedMonitoringHost string
	DetailedMonitoringPort int
	XrootdRun string
	Authfile string
	ScitokensConfig string
	Mount string
	NamespacePrefix string
	XrootdMultiuser bool
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

	prefix := pelican.GetPreferredPrefix()
	if prefix == "OSDF" {
		err := viper.MergeConfig(strings.NewReader(osdfDefaultsYaml))
		if err != nil {
			panic(err)
		}
	}
}

func generateCert() error {
	gid, err := pelican.GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := pelican.GetDaemonGroup()
	if err != nil {
		return err
	}

	tlsCert := viper.GetString("TLSCertificate")
	if file, err := os.Open(tlsCert); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	certDir := path.Dir(tlsCert)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	tlsKey := viper.GetString("TLSKey")
	rest, err := os.ReadFile(tlsKey)
	if err != nil {
		return nil
	}

	var privateKey *ecdsa.PrivateKey
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		} else if block.Type == "EC PRIVATE KEY" {
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			break
		}
	}
	if privateKey == nil {
		return fmt.Errorf("Private key file, %v, contains no private key", tlsKey)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican"},
			CommonName: hostname,
		},
		NotBefore: notBefore,
		NotAfter: notBefore.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = []string{hostname}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &(privateKey.PublicKey),
		privateKey)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(tlsCert, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = os.Chown(tlsCert, -1, gid); err != nil {
		return errors.Wrapf(err, "Failed to chown generated certificate %v to daemon group %v",
			tlsCert, groupname)
	}

	pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return nil
}

func generatePrivateKey() error {
	gid, err := pelican.GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := pelican.GetDaemonGroup()
	if err != nil {
		return err
	}

	tlsKey := viper.GetString("TLSKey")
	if file, err := os.Open(tlsKey); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keyDir := path.Dir(tlsKey)
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return err
	}
	// In this case, the private key file doesn't exist.
	file, err := os.OpenFile(tlsKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	defer file.Close()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}
	if err = os.Chown(tlsKey, -1, gid); err != nil {
		return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
			tlsKey, groupname)
	}


	bytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	priv_block := pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}
	pem.Encode(file, &priv_block)
	return nil
}

func checkXrootdEnv() error {
	uid, err := pelican.GetDaemonUID()
	if err != nil {
		return err
	}
	gid, err := pelican.GetDaemonGID()
	if err != nil {
		return err
	}
	username, err := pelican.GetDaemonUser()
	if err != nil {
		return err
	}
	groupname, err := pelican.GetDaemonGroup()
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
		return errors.Wrapf(err, "Unable to change ownership of runtime directory %v" +
			" to desired daemon user %v", runtimeDir, username)
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
		return errors.Wrapf(err, "Unable to change ownership of macaroons secret %v" +
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
		return errors.Wrapf(err, "Unable to change ownership of authfile %v" +
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
		return errors.Wrapf(err, "Unable to change ownership of scitokens config %v" +
			" to desired daemon group %v", scitokensCfg, groupname)
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

	// As necessary, generate a private key and corresponding cert
	if err := generatePrivateKey(); err != nil {
		return err
	}
	if err := generateCert(); err != nil {
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
	viper.Unmarshal(&config)
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

func launchXrootd() error {
	configPath, err := configXrootd()
	if err != nil {
		return err
	}
	cmd := exec.Command("xrootd", "-f", "-c", configPath)
	if cmd.Err != nil {
		return cmd.Err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	isDoneChannel := make(chan error, 1)
	go func() {
		result := cmd.Wait()
		isDoneChannel <- result
	}()
	fmt.Println("Started xrootd")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	var expiry time.Time
	for {
		timer := time.NewTimer(time.Second)
		select {
		case sig := <-sigs:
			if sys_sig, ok := sig.(syscall.Signal); ok {
				fmt.Printf("Forwarding signal %v to xrootd process\n", sys_sig)
				syscall.Kill(cmd.Process.Pid, sys_sig)
			} else {
				panic(errors.New("Unable to convert signal to syscall.Signal"))
			}
			expiry = time.Now().Add(10*time.Second)
		case waitResult := <-isDoneChannel:
			if waitResult != nil {
				if !expiry.IsZero() {
					return nil
				}
				return errors.Wrap(waitResult, "Xrootd process failed unexpectedly")
			}
			return nil
		case <-timer.C:
			if !expiry.IsZero() && time.Now().After(expiry) {
				syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}
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
