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
	"os"
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var (
	//go:embed resources/test-scitokens-empty.cfg
	emptyOutput string

	//go:embed resources/test-scitokens-issuer.cfg
	simpleOutput string

	//go:embed resources/test-scitokens-2issuers.cfg
	dualOutput string
)

func TestEmitCfg(t *testing.T) {
	dirname := t.TempDir()
	os.Setenv("PELICAN_XROOTDRUN", dirname)
	defer os.Unsetenv("PELICAN_XROOTDRUN")
	viper.Reset()
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
