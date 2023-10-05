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

package xrootd

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed resources/test-scitokens-empty.cfg
	emptyOutput string

	//go:embed resources/test-scitokens-issuer.cfg
	simpleOutput string

	//go:embed resources/test-scitokens-2issuers.cfg
	dualOutput string

	// For now, this unit test uses the same input as the prior one;
	// duplicating the variable name to make it clear these are different
	// tests.
	//go:embed resources/test-scitokens-2issuers.cfg
	toMergeOutput string

	//go:embed resources/test-scitokens-monitoring.cfg
	monitoringOutput string
)

func TestEmitCfg(t *testing.T) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(cfg *ScitokensCfg, configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			err = EmitScitokensConfiguration(cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	globalCfg := GlobalCfg{Audience: []string{"test_audience"}}
	t.Run("EmptyConfig", configTester(&ScitokensCfg{Global: globalCfg}, emptyOutput))

	issuer := Issuer{Name: "Demo", Issuer: "https://demo.scitokens.org", BasePaths: []string{"/foo", "/bar"}, DefaultUser: "osg"}
	t.Run("SimpleIssuer", configTester(&ScitokensCfg{Global: globalCfg, Issuers: []Issuer{issuer}}, simpleOutput))
	issuer2 := Issuer{Name: "WLCG", Issuer: "https://wlcg.cnaf.infn.it", BasePaths: []string{"/baz"}}
	t.Run("DualIssuers", configTester(&ScitokensCfg{Global: globalCfg, Issuers: []Issuer{issuer, issuer2}}, dualOutput))
}

func TestLoadScitokensConfig(t *testing.T) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			cfgFname := filepath.Join(dirname, "scitokens-test.cfg")
			err := os.WriteFile(cfgFname, []byte(configResult), 0600)
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(cfgFname)
			require.NoError(t, err)

			err = EmitScitokensConfiguration(&cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	t.Run("EmptyConfig", configTester(emptyOutput))
	t.Run("SimpleIssuer", configTester(simpleOutput))
	t.Run("DualIssuers", configTester(dualOutput))
}

func TestGenerateConfig(t *testing.T) {
	viper.Set("Origin.SelfTest", false)
	issuer, err := GenerateMonitoringIssuer()
	require.NoError(t, err)
	assert.Equal(t, issuer.Name, "")

	viper.Set("Origin.SelfTest", true)
	err = config.InitServer()
	require.NoError(t, err)
	issuer, err = GenerateMonitoringIssuer()
	require.NoError(t, err)
	assert.Equal(t, issuer.Name, "Built-in Monitoring")
	assert.Equal(t, issuer.Issuer, "https://"+param.Server_Hostname.GetString()+":"+fmt.Sprint(param.Xrootd_Port.GetInt()))
	require.Equal(t, len(issuer.BasePaths), 1)
	assert.Equal(t, issuer.BasePaths[0], "/pelican/monitoring")
	assert.Equal(t, issuer.DefaultUser, "xrootd")
}

func TestWriteOriginScitokensConfig(t *testing.T) {
	dirname := t.TempDir()
	os.Setenv("PELICAN_XROOTD_RUNLOCATION", dirname)
	defer os.Unsetenv("PELICAN_XROOTD_RUNLOCATION")
	config_dirname := t.TempDir()
	viper.Reset()
	viper.Set("Origin.SelfTest", true)
	viper.Set("ConfigDir", config_dirname)
	viper.Set("Xrootd.RunLocation", dirname)
	viper.Set("Server.Hostname", "origin.example.com")
	err := config.InitServer()
	require.Nil(t, err)

	scitokensCfg := param.Xrootd_ScitokensConfig.GetString()
	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, -1)
	require.NoError(t, err)
	err = os.WriteFile(scitokensCfg, []byte(toMergeOutput), 0640)
	require.NoError(t, err)

	err = WriteOriginScitokensConfig()
	require.NoError(t, err)

	genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-generated.cfg"))
	require.NoError(t, err)

	assert.Equal(t, string(monitoringOutput), string(genCfg))
}
