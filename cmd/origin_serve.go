
package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/pelicanplatform/pelican"
)

var (

	//go:embed resources/defaults.yaml
	defaultsYaml string
	//go:embed resources/osdf.yaml
	osdfDefaultsYaml string
	//go:embed resources/xrootd.cfg
	xrootdCfg string

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

func init() {
	viper.SetConfigType("yaml")
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


func checkDefaults() error {
	requiredConfigs := []string{"ManagerHost", "SummaryMonitoringHost", "DetailedMonitoringHost"}
	for _, configName := range requiredConfigs {
		mgr := viper.GetString(configName)
		if mgr == "" {
			return errors.New(fmt.Sprintf("Required value of '%v' is not set in config", configName))
		}
	}
	
	return nil
}

func serve(/*cmd*/ *cobra.Command, /*args*/ []string) {
	templ := template.Must(template.New("xrootd.cfg").Parse(xrootdCfg))

	err := checkDefaults()
	if err != nil {
		panic(err)
	}

	var config XrootdConfig
	viper.Unmarshal(&config)
	err = templ.Execute(os.Stdout, config)
	if err != nil {
		fmt.Println("Fatal error:", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
