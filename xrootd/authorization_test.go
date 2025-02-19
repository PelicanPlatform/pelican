//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"bufio"
	"context"
	_ "embed"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
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

	//go:embed resources/test-scitokens-cache-issuer.cfg
	cacheSciOutput string

	//go:embed resources/test-scitokens-cache-empty.cfg
	cacheEmptyOutput string

	//go:embed resources/osdf-authfile
	authfileOutput string

	//go:embed resources/multi-export-multi-issuers.yml
	multiExportIssuers string

	//go:embed resources/single-export-no-issuers.yml
	singleExportNoIssuers string

	//go:embed resources/single-export-one-issuer.yml
	singleExportOneIssuer string

	sampleMultilineOutput = `foo \
	bar
	baz
	abc \`

	sampleMultilineOutputParsed = []string{"foo \tbar", "\tbaz", "\tabc "}

	cacheAuthfileMultilineInput = `
u * /user/ligo -rl \
/Gluex rl \
/NSG/PUBLIC rl \
/VDC/PUBLIC rl`

	cacheAuthfileOutput = "u * /.well-known lr /user/ligo -rl /Gluex rl /NSG/PUBLIC rl /VDC/PUBLIC rl\n"

	// Configuration snippet from bug report #601
	scitokensCfgAud = `
[Global]
audience = GLOW, HCC, IceCube, NRP, OSG, PATh, UCSD

[Issuer https://ap20.uc.osg-htc.org:1094/ospool/ap20]
issuer = https://ap20.uc.osg-htc.org:1094/ospool/ap20
base_path = /ospool/ap20
`

	// Actual authfile entries here are from the bug report #568
	otherAuthfileEntries = `# DN: /CN=sc-origin.chtc.wisc.edu
u 5a42185a.0 /chtc/PROTECTED/sc-origin lr
# DN: /DC=org/DC=incommon/C=US/ST=California/O=University of California, San Diego/CN=osg-stash-sfu-computecanada-ca.nationalresearchplatform.org
u 4ff08838.0 /chtc/PROTECTED/sc-origin lr
# DN: /DC=org/DC=incommon/C=US/ST=Georgia/O=Georgia Institute of Technology/OU=Office of Information Technology/CN=osg-gftp2.pace.gatech.edu
u 3af6a420.0 /chtc/PROTECTED/sc-origin lr
`

	mergedAuthfileEntries = otherAuthfileEntries + "u * /.well-known lr\n"

	otherMergedAuthfileEntries = otherAuthfileEntries + "u * /.well-known lr /user/ligo -rl /Gluex rl /NSG/PUBLIC rl /VDC/PUBLIC rl\n"

	//Actual cache authfile entriese here for testing
	cacheAuthfileEntries = `# FQAN: /GLOW
g /GLOW /chtc/PROTECTED/sc-origin rl /chtc/PROTECTED/sc-origin2000 rl /chtc/itb/helm-origin/PROTECTED rl
# DN: /DC=org/DC=cilogon/C=US/O=University of Wisconsin-Madison/CN=Matyas Selmeci A148276
u 5922b3b6.0 /chtc/PROTECTED/sc-origin rl /chtc/PROTECTED/sc-origin2000 rl /chtc/itb/helm-origin/PROTECTED rl
# FQAN: /hcc
g /hcc /hcc/focusday rl
# DN: /DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=bbockelm/CN=659869/CN=Brian Paul Bockelman
u 6fb7593d.0 /hcc/focusday rl
# FQAN: /xenon.biggrid.nl/*
g /xenon.biggrid.nl/* /nrp/protected/xenon-biggrid-nl/ rl
# DN: /DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=jstephen/CN=781624/CN=Judith Lorraine Stephen
u eeccb14b.0 /nrp/protected/xenon-biggrid-nl/ rl
`

	cacheMergedAuthfileEntries = cacheAuthfileEntries + "u * /user/ligo -rl /Gluex rl /NSG/PUBLIC rl /VDC/PUBLIC rl "
)

func TestOSDFAuthRetrieval(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/origin/Authfile" && r.URL.RawQuery == "fqdn=sc-origin.chtc.wisc.edu" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(authfileOutput))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	// Hijack the common transport used by Pelican, forcing all connections to go to our test server
	transport := config.GetTransport()
	oldDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, svr.Listener.Addr().Network(), svr.Listener.Addr().String())
	}
	oldConfig := transport.TLSClientConfig
	transport.TLSClientConfig = svr.TLS.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	t.Cleanup(func() {
		transport.DialContext = oldDial
		transport.TLSClientConfig = oldConfig
	})

	server_utils.ResetTestState()
	viper.Set("Federation.TopologyUrl", "https://topology.opensciencegrid.org/")
	viper.Set("Server.Hostname", "sc-origin.chtc.wisc.edu")

	originServer := &origin.OriginServer{}
	_, err := getOSDFAuthFiles(originServer)

	require.NoError(t, err, "error")
	server_utils.ResetTestState()
}

func TestOSDFAuthCreation(t *testing.T) {
	tests := []struct {
		desc        string
		authIn      string
		authOut     string
		server      server_structs.XRootDServer
		hostname    string
		disableX509 bool
	}{
		{
			desc:        "osdf-origin-auth-no-merge",
			authIn:      "",
			authOut:     mergedAuthfileEntries,
			server:      &origin.OriginServer{},
			hostname:    "origin-test",
			disableX509: false,
		},
		{
			desc:        "osdf-origin-auth-merge",
			authIn:      cacheAuthfileMultilineInput,
			authOut:     otherMergedAuthfileEntries,
			server:      &origin.OriginServer{},
			hostname:    "origin-test",
			disableX509: false,
		},
		{
			desc:        "osdf-cache-auth-no-merge",
			authIn:      "",
			authOut:     cacheAuthfileEntries,
			server:      &cache.CacheServer{},
			hostname:    "cache-test",
			disableX509: false,
		},
		{
			desc:        "osdf-cache-auth-merge",
			authIn:      cacheAuthfileMultilineInput,
			authOut:     cacheMergedAuthfileEntries,
			server:      &cache.CacheServer{},
			hostname:    "cache-test",
			disableX509: false,
		},
		{
			desc:        "osdf-origin-no-authfile",
			authIn:      "",
			authOut:     "u * /.well-known lr\n",
			server:      &origin.OriginServer{},
			hostname:    "origin-test-empty",
			disableX509: false,
		},
		{
			desc:        "osdf-cache-no-authfile",
			authIn:      "",
			authOut:     "",
			server:      &cache.CacheServer{},
			hostname:    "cache-test-empty",
			disableX509: false,
		},
		{
			desc:        "osdf-cache-disable-auth",
			authIn:      cacheAuthfileMultilineInput,
			authOut:     "u * /user/ligo -rl /Gluex rl /NSG/PUBLIC rl /VDC/PUBLIC rl ",
			server:      &cache.CacheServer{},
			hostname:    "cache-test",
			disableX509: true,
		},
		{
			desc:        "osdf-origin-disable-auth",
			authIn:      "",
			authOut:     "u * /.well-known lr\n",
			server:      &origin.OriginServer{},
			hostname:    "origin-test",
			disableX509: true,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && req.URL.Path == "/origin/Authfile" {
			if req.URL.RawQuery == "fqdn=origin-test" {
				res := []byte(otherAuthfileEntries)
				_, err := w.Write(res)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else if req.Method == "GET" && req.URL.Path == "/cache/Authfile" {
			if req.URL.RawQuery == "fqdn=cache-test" {
				res := []byte(cacheAuthfileEntries)
				_, err := w.Write(res)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	for _, testInput := range tests {
		t.Run(testInput.desc, func(t *testing.T) {
			dirName := t.TempDir()
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			viper.Set("Xrootd.Authfile", filepath.Join(dirName, "authfile"))
			viper.Set("Federation.TopologyUrl", ts.URL)
			viper.Set("Server.Hostname", testInput.hostname)
			if testInput.disableX509 {
				viper.Set("Topology.DisableCacheX509", true)
				viper.Set("Topology.DisableOriginX509", true)
			}
			var xrootdRun string
			if strings.Contains(testInput.hostname, "cache") {
				viper.Set("Cache.RunLocation", dirName)
				xrootdRun = param.Cache_RunLocation.GetString()
			} else {
				viper.Set("Origin.RunLocation", dirName)
				xrootdRun = param.Origin_RunLocation.GetString()
			}
			viper.Set("Origin.FederationPrefix", "/")
			viper.Set("Origin.StoragePrefix", "/")
			oldPrefix, err := config.SetPreferredPrefix(config.OsdfPrefix)
			assert.NoError(t, err)
			defer func() {
				_, err := config.SetPreferredPrefix(oldPrefix)
				require.NoError(t, err)
			}()

			err = os.WriteFile(filepath.Join(dirName, "authfile"), []byte(testInput.authIn), fs.FileMode(0600))
			require.NoError(t, err, "Failure writing test input authfile")

			err = EmitAuthfile(testInput.server)
			require.NoError(t, err, "Failure generating authfile")

			finalAuthPath := filepath.Join(xrootdRun, "authfile-origin-generated")
			if testInput.server.GetServerType().IsEnabled(server_structs.CacheType) {
				finalAuthPath = filepath.Join(xrootdRun, "authfile-cache-generated")
			}

			genAuth, err := os.ReadFile(finalAuthPath)
			require.NoError(t, err, "Error reading generated authfile")

			require.Equal(t, testInput.authOut, string(genAuth))
		})
	}
}

func TestAuthfileMultiline(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader(sampleMultilineOutput))
	sc.Split(ScanLinesWithCont)
	idx := 0
	for sc.Scan() {
		require.Less(t, idx, len(sampleMultilineOutputParsed))
		assert.Equal(t, string(sampleMultilineOutputParsed[idx]), sc.Text())
		idx += 1
	}
	assert.Equal(t, idx, len(sampleMultilineOutputParsed))
}

func TestEmitAuthfile(t *testing.T) {
	tests := []struct {
		desc    string
		authIn  string
		authOut string
	}{
		{
			desc:    "merge-multi-lines",
			authIn:  cacheAuthfileMultilineInput,
			authOut: cacheAuthfileOutput,
		},
		{
			desc:    "merge-other-entries",
			authIn:  otherAuthfileEntries,
			authOut: mergedAuthfileEntries,
		},
	}
	for _, testInput := range tests {
		t.Run(testInput.desc, func(t *testing.T) {
			dirName := t.TempDir()
			server_utils.ResetTestState()

			defer server_utils.ResetTestState()

			viper.Set("Xrootd.Authfile", filepath.Join(dirName, "authfile"))
			viper.Set("Origin.RunLocation", dirName)
			viper.Set("Origin.FederationPrefix", "/")
			viper.Set("Origin.StoragePrefix", "/")
			server := &origin.OriginServer{}

			err := os.WriteFile(filepath.Join(dirName, "authfile"), []byte(testInput.authIn), fs.FileMode(0600))
			require.NoError(t, err)

			err = EmitAuthfile(server)
			require.NoError(t, err)

			contents, err := os.ReadFile(filepath.Join(dirName, "authfile-origin-generated"))
			require.NoError(t, err)

			assert.Equal(t, testInput.authOut, string(contents))
		})
	}
}

func TestEmitOriginAuthfileWithCacheAuth(t *testing.T) {
	dirName := t.TempDir()
	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	viper.Set(param.Origin_DisableDirectClients.GetName(), true)
	viper.Set(param.Xrootd_Authfile.GetName(), filepath.Join(dirName, "authfile"))
	viper.Set(param.Origin_RunLocation.GetName(), dirName)
	viper.Set(param.Origin_FederationPrefix.GetName(), "cache-authz-test")
	viper.Set(param.Origin_StoragePrefix.GetName(), "/")
	viper.Set(param.Origin_EnablePublicReads.GetName(), true)

	originServer := &origin.OriginServer{}

	err := os.WriteFile(filepath.Join(dirName, "authfile"), []byte(""), fs.FileMode(0600))
	require.NoError(t, err)

	err = EmitAuthfile(originServer)
	require.NoError(t, err)

	contents, err := os.ReadFile(filepath.Join(dirName, "authfile-origin-generated"))
	require.NoError(t, err)

	assert.Equal(t, "u * /.well-known lr\n", string(contents))
}

func TestEmitOriginAuthfileWithCapabilities(t *testing.T) {
	tests := []struct {
		desc         string
		name         string
		authOut      string
		capabilities []string
	}{
		{
			desc:         "public-reads",
			name:         "/public",
			authOut:      "u * /.well-known lr /public lr\n",
			capabilities: []string{param.Origin_EnablePublicReads.GetName()},
		},
		{
			desc:         "no-public-access",
			name:         "/private",
			authOut:      "u * /.well-known lr\n",
			capabilities: []string{param.Origin_EnableReads.GetName()},
		},
	}
	for _, testInput := range tests {
		t.Run(testInput.desc, func(t *testing.T) {
			dirName := t.TempDir()
			server_utils.ResetTestState()

			defer server_utils.ResetTestState()

			viper.Set(param.Xrootd_Authfile.GetName(), filepath.Join(dirName, "authfile"))
			viper.Set(param.Origin_RunLocation.GetName(), dirName)
			viper.Set(param.Origin_FederationPrefix.GetName(), testInput.name)
			viper.Set(param.Origin_StoragePrefix.GetName(), "/")
			viper.Set(param.Server_IssuerUrl.GetName(), "https://test-issuer.com")
			for _, cap := range testInput.capabilities {
				viper.Set(cap, true)
			}
			originServer := &origin.OriginServer{}

			err := os.WriteFile(filepath.Join(dirName, "authfile"), []byte(""), fs.FileMode(0600))
			require.NoError(t, err)

			err = EmitAuthfile(originServer)
			require.NoError(t, err)

			contents, err := os.ReadFile(filepath.Join(dirName, "authfile-origin-generated"))
			require.NoError(t, err)

			assert.Equal(t, testInput.authOut, string(contents))
		})
	}
}

func TestEmitCfg(t *testing.T) {
	dirname := t.TempDir()
	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	viper.Set("Origin.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(cfg *ScitokensCfg, configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			err = writeScitokensConfiguration(server_structs.OriginType, cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	globalCfg := GlobalCfg{Audience: []string{"test_audience"}}
	t.Run("EmptyConfig", configTester(&ScitokensCfg{Global: globalCfg}, emptyOutput))

	issuer := Issuer{Name: "Demo", Issuer: "https://demo.scitokens.org", BasePaths: []string{"/foo", "/bar"}, DefaultUser: "osg"}
	t.Run("SimpleIssuer", configTester(&ScitokensCfg{Global: globalCfg, IssuerMap: map[string]Issuer{issuer.Issuer: issuer}}, simpleOutput))
	issuer2 := Issuer{Name: "WLCG", Issuer: "https://wlcg.cnaf.infn.it", BasePaths: []string{"/baz"}}
	t.Run("DualIssuers", configTester(&ScitokensCfg{Global: globalCfg, IssuerMap: map[string]Issuer{issuer.Issuer: issuer, issuer2.Issuer: issuer2}}, dualOutput))
}

func TestDeduplicateBasePaths(t *testing.T) {
	tests := []struct {
		name        string
		initialCfg  ScitokensCfg
		expectedCfg ScitokensCfg
	}{
		{
			name: "duplicate base paths",
			initialCfg: ScitokensCfg{
				Global: GlobalCfg{Audience: []string{"test_audience"}},
				IssuerMap: map[string]Issuer{"iss": {
					Name:      "Demo",
					BasePaths: []string{"foo", "foo"},
				}},
			},
			expectedCfg: ScitokensCfg{
				Global: GlobalCfg{Audience: []string{"test_audience"}},
				IssuerMap: map[string]Issuer{"iss": {
					Name:      "Demo",
					BasePaths: []string{"foo"},
				}},
			},
		},
		{
			name: "non-sequential duplicate base paths",
			initialCfg: ScitokensCfg{
				Global: GlobalCfg{Audience: []string{"test_audience"}},
				IssuerMap: map[string]Issuer{"iss": {
					Name:      "Demo",
					BasePaths: []string{"foo", "bar", "foo"},
				}},
			},
			expectedCfg: ScitokensCfg{
				Global: GlobalCfg{Audience: []string{"test_audience"}},
				IssuerMap: map[string]Issuer{"iss": {
					Name:      "Demo",
					BasePaths: []string{"bar", "foo"},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deduplicateBasePaths(&tt.initialCfg)
			require.Equal(t, tt.initialCfg, tt.expectedCfg)
		})
	}
}

func TestLoadScitokensConfig(t *testing.T) {
	dirname := t.TempDir()
	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	viper.Set("Origin.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			cfgFname := filepath.Join(dirname, "scitokens-test.cfg")
			err := os.WriteFile(cfgFname, []byte(configResult), 0600)
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(cfgFname)
			require.NoError(t, err)

			err = writeScitokensConfiguration(server_structs.OriginType, &cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	t.Run("EmptyConfig", configTester(emptyOutput))
	t.Run("SimpleIssuer", configTester(simpleOutput))
	t.Run("DualIssuers", configTester(dualOutput))
}

// Test that merging the configuration works without throwing any errors
func TestMergeConfig(t *testing.T) {
	dirname := t.TempDir()
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	viper.Set(param.Logging_Level.GetName(), "debug")
	viper.Set("Origin.RunLocation", dirname)
	viper.Set("Origin.Port", 8443)
	viper.Set("Origin.StoragePrefix", "/")
	viper.Set("Origin.FederationPrefix", "/")
	// We don't inherit any defaults at this level of code -- in order to recognize
	// that this is an authorized prefix, we must set either EnableReads && !EnablePublicReads
	// or EnableWrites
	viper.Set("Origin.EnableReads", true)
	scitokensConfigFile := filepath.Join(dirname, "scitokens-input.cfg")
	viper.Set("Xrootd.ScitokensConfig", scitokensConfigFile)

	configTester := func(configInput string, postProcess func(*testing.T, ScitokensCfg)) func(t *testing.T) {
		return func(t *testing.T) {
			ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
			defer func() { require.NoError(t, egrp.Wait()) }()
			defer cancel()

			err := os.WriteFile(scitokensConfigFile, []byte(configInput), fs.FileMode(0600))
			require.NoError(t, err)

			err = config.InitServer(ctx, server_structs.OriginType)
			require.NoError(t, err)

			err = EmitScitokensConfig(&origin.OriginServer{})
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			require.NoError(t, err)

			postProcess(t, cfg)
		}
	}

	t.Run("AudienceNoJson", configTester(scitokensCfgAud, func(t *testing.T, cfg ScitokensCfg) {
		assert.True(t, reflect.DeepEqual([]string{"GLOW", "HCC", "IceCube", "NRP", "OSG", "PATh", "UCSD", param.Origin_TokenAudience.GetString()}, cfg.Global.Audience))
	}))
}

func TestGenerateMonitoringIssuer(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name            string
		selfTestEnabled bool
		externalWebUrl  string
		expectedIssuer  Issuer
		expectError     bool
	}{
		{
			name:            "self-test enabled",
			selfTestEnabled: true,
			externalWebUrl:  "https://my-origin.com:8443",
			expectedIssuer: Issuer{
				Name:        "Built-in Monitoring",
				Issuer:      "https://my-origin.com:8443",
				BasePaths:   []string{server_utils.MonitoringBaseNs},
				DefaultUser: "xrootd",
			},
			expectError: false,
		},
		{
			name:            "self-test disabled",
			selfTestEnabled: false,
			externalWebUrl:  "https://my-origin.com:8443",
			expectedIssuer:  Issuer{},
			expectError:     false,
		},
		{
			name:            "self-test enabled, no external web URL",
			selfTestEnabled: true,
			externalWebUrl:  "",
			expectedIssuer:  Issuer{},
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set(param.Origin_SelfTest.GetName(), tc.selfTestEnabled)
			viper.Set(param.Server_ExternalWebUrl.GetName(), tc.externalWebUrl)
			issuer, err := GenerateMonitoringIssuer()
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedIssuer, issuer)
		})
	}
}

func TestGenerateOriginIssuer(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name               string
		yamlConfig         string
		extraViperSettings map[string]string
		expectError        bool
		expectedIssuers    []Issuer
	}{
		{
			name:       "single export default issuer",
			yamlConfig: singleExportNoIssuers,
			extraViperSettings: map[string]string{
				param.Server_IssuerUrl.GetName(): "https://foo.com",
			},
			expectError: false,
			expectedIssuers: []Issuer{
				{
					Name:            "Origin https://foo.com",
					Issuer:          "https://foo.com",
					BasePaths:       []string{"/first/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
			},
		},
		{
			name:        "single export one issuer",
			yamlConfig:  singleExportOneIssuer,
			expectError: false,
			expectedIssuers: []Issuer{
				{
					Name:            "Origin https://foo.com",
					Issuer:          "https://foo.com",
					BasePaths:       []string{"/first/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
			},
		},
		{
			name:       "multiple exports multiple issuers",
			yamlConfig: multiExportIssuers,
			extraViperSettings: map[string]string{
				param.Server_IssuerUrl.GetName(): "https://foo99.com",
			},
			expectError: false,
			expectedIssuers: []Issuer{
				{
					Name:            "Origin https://foo99.com",
					Issuer:          "https://foo99.com",
					BasePaths:       []string{"/first/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
				{
					Name:            "Origin https://foo1.com",
					Issuer:          "https://foo1.com",
					BasePaths:       []string{"/second/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
				{
					Name:            "Origin https://foo2.com",
					Issuer:          "https://foo2.com",
					BasePaths:       []string{"/second/namespace", "/third/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
				{
					Name:            "Origin https://foo3.com",
					Issuer:          "https://foo3.com",
					BasePaths:       []string{"/third/namespace"},
					RestrictedPaths: nil,
					MapSubject:      false,
					DefaultUser:     "",
					UsernameClaim:   "",
				},
			},
		},
		{
			name:       "single export one issuer with all parameters",
			yamlConfig: singleExportOneIssuer,
			extraViperSettings: map[string]string{
				param.Origin_ScitokensRestrictedPaths.GetName(): "/restricted/path",
				param.Origin_ScitokensMapSubject.GetName():      "true",
				param.Origin_ScitokensDefaultUser.GetName():     "defaultUser",
				param.Origin_ScitokensUsernameClaim.GetName():   "usernameClaim",
			},
			expectError: false,
			expectedIssuers: []Issuer{
				{
					Name:            "Origin https://foo.com",
					Issuer:          "https://foo.com",
					BasePaths:       []string{"/first/namespace"},
					RestrictedPaths: []string{"/restricted/path"},
					MapSubject:      true,
					DefaultUser:     "defaultUser",
					UsernameClaim:   "usernameClaim",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer server_utils.ResetTestState()
			ctx, _, _ := test_utils.TestContext(context.Background(), t)
			viper.Set("ConfigDir", t.TempDir())
			viper.Set(param.Logging_Level.GetName(), "debug")

			// Load in test config
			viper.SetConfigType("yaml")
			err := viper.MergeConfig(strings.NewReader(tc.yamlConfig))
			require.NoError(t, err, "error reading config")
			err = config.InitServer(ctx, server_structs.OriginType)
			require.NoError(t, err)

			// Set extra Viper settings if provided
			for key, value := range tc.extraViperSettings {
				viper.Set(key, value)
			}

			issuers, err := GenerateOriginIssuers()
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			// There are no guarantees about ordering of the issuers because
			// of the map operation in the function, so we use ElementsMatch
			assert.ElementsMatch(t, tc.expectedIssuers, issuers)
		})
	}
}

// Test that, given a slice of namespace ads, the cache generates the correct
// set of issuers for the scitokens configuration. The test cases cover
// various combinations of public/private capabilities, multiple issuers,
// and overlapping base paths.
func TestGenerateCacheIssuers(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name            string
		nsAds           []server_structs.NamespaceAdV2
		expectedIssuers []Issuer
	}{
		{
			name:            "empty namespace ads",
			nsAds:           []server_structs.NamespaceAdV2{},
			expectedIssuers: []Issuer{},
		},
		{
			name: "single namespace ad with public capabilities",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/foo1",
					Caps: server_structs.Capabilities{
						PublicReads: true,
						Reads:       true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo1"},
						},
					},
				},
			},
			expectedIssuers: []Issuer{}, // No issuers are generated because public reads are enabled. Caches don't care about writes (yet)
		},
		{
			name: "single namespace ad with private capabilities",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/foo1",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo1"},
						},
					},
				},
			},
			expectedIssuers: []Issuer{
				{
					Name:      "https://issuer1.com",
					Issuer:    "https://issuer1.com",
					BasePaths: []string{"/foo1"},
				},
			},
		},
		{
			name: "multiple namespace ads with the same issuer",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/foo1",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo1"},
						},
					},
				},
				{
					Path: "/foo2",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo2"},
						},
					},
				},
			},
			expectedIssuers: []Issuer{
				{
					Name:      "https://issuer1.com",
					Issuer:    "https://issuer1.com",
					BasePaths: []string{"/foo1", "/foo2"},
				},
			},
		},
		{
			name: "multiple namespace ads with different issuers",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/foo1",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo1"},
						},
					},
				},
				{
					Path: "/foo2",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer2.com"},
							BasePaths: []string{"/foo2"},
						},
					},
				},
			},
			expectedIssuers: []Issuer{
				{
					Name:      "https://issuer1.com",
					Issuer:    "https://issuer1.com",
					BasePaths: []string{"/foo1"},
				},
				{
					Name:      "https://issuer2.com",
					Issuer:    "https://issuer2.com",
					BasePaths: []string{"/foo2"},
				},
			},
		},
		{
			name: "multiple namespace ads with multiple issuers",
			nsAds: []server_structs.NamespaceAdV2{
				{
					Path: "/foo1",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer1.com"},
							BasePaths: []string{"/foo1"},
						},
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer2.com"},
							BasePaths: []string{"/foo1"},
						},
					},
				},
				{
					Path: "/foo2",
					Caps: server_structs.Capabilities{
						Reads: true,
					},
					Issuer: []server_structs.TokenIssuer{
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer2.com"},
							BasePaths: []string{"/foo2"},
						},
						{
							IssuerUrl: url.URL{Scheme: "https", Host: "issuer3.com"},
							BasePaths: []string{"/foo2"},
						},
					},
				},
			},
			expectedIssuers: []Issuer{
				{
					Name:      "https://issuer1.com",
					Issuer:    "https://issuer1.com",
					BasePaths: []string{"/foo1"},
				},
				{
					Name:      "https://issuer2.com",
					Issuer:    "https://issuer2.com",
					BasePaths: []string{"/foo1", "/foo2"},
				},
				{
					Name:      "https://issuer3.com",
					Issuer:    "https://issuer3.com",
					BasePaths: []string{"/foo2"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cacheServer := &cache.CacheServer{}
			cacheServer.SetNamespaceAds(tc.nsAds)
			issuers := GenerateCacheIssuers(tc.nsAds)
			require.ElementsMatch(t, tc.expectedIssuers, issuers)
		})
	}
}

func TestWriteOriginAuthFiles(t *testing.T) {
	server_utils.ResetTestState()

	originAuthTester := func(server server_structs.XRootDServer, authStart string, authResult string) func(t *testing.T) {
		return func(t *testing.T) {
			defer server_utils.ResetTestState()

			viper.Set("Origin.StorageType", "posix")
			dirname := t.TempDir()
			viper.Set("Origin.RunLocation", dirname)
			viper.Set("Origin.StoragePrefix", "/")
			viper.SetDefault("Origin.FederationPrefix", "/")
			viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-generated.cfg"))
			viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile"))
			xAuthFile := filepath.Join(param.Origin_RunLocation.GetString(), "authfile-origin-generated")

			authfileProvided := param.Xrootd_Authfile.GetString()

			err := os.WriteFile(authfileProvided, []byte(authStart), 0600)
			assert.NoError(t, err)

			err = EmitAuthfile(server)
			assert.NoError(t, err)

			authGen, err := os.ReadFile(xAuthFile)
			assert.NoError(t, err)
			assert.Equal(t, authResult, string(authGen))
		}
	}
	nsAds := []server_structs.NamespaceAdV2{}

	originServer := &origin.OriginServer{}
	originServer.SetNamespaceAds(nsAds)

	t.Run("MultiIssuer", originAuthTester(originServer, "u * t1 lr t2 lr t3 lr", "u * /.well-known lr t1 lr t2 lr t3 lr\n"))

	nsAds = []server_structs.NamespaceAdV2{}
	originServer.SetNamespaceAds(nsAds)

	t.Run("EmptyAuth", originAuthTester(originServer, "", "u * /.well-known lr\n"))

	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("Origin.FederationPrefix", "/foo/bar")
	t.Run("PublicAuth", originAuthTester(originServer, "", "u * /.well-known lr /foo/bar lr\n"))
}

func TestWriteCacheAuthFiles(t *testing.T) {

	cacheAuthTester := func(server server_structs.XRootDServer, sciTokenResult string, authResult string) func(t *testing.T) {
		return func(t *testing.T) {

			dirname := t.TempDir()
			server_utils.ResetTestState()
			viper.Set("Cache.RunLocation", dirname)
			if server.GetServerType().IsEnabled(server_structs.OriginType) {
				viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-origin-generated.cfg"))
				viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile-origin-generated"))
			} else {
				viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-cache-generated.cfg"))
				viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile-cache-generated"))
			}
			authFile := param.Xrootd_Authfile.GetString()
			err := os.WriteFile(authFile, []byte(""), 0600)
			assert.NoError(t, err)

			err = WriteCacheScitokensConfig(server.GetNamespaceAds())
			assert.NoError(t, err)

			sciFile := param.Xrootd_ScitokensConfig.GetString()
			genSciToken, err := os.ReadFile(sciFile)
			assert.NoError(t, err)

			assert.Equal(t, sciTokenResult, string(genSciToken))

			err = EmitAuthfile(server)
			assert.NoError(t, err)

			authGen, err := os.ReadFile(authFile)
			assert.NoError(t, err)
			assert.Equal(t, authResult, string(authGen))
		}
	}

	issuer1URL := url.URL{}
	issuer1URL.Scheme = "https"
	issuer1URL.Host = "issuer1.com"

	issuer2URL := url.URL{}
	issuer2URL.Scheme = "https"
	issuer2URL.Host = "issuer2.com"

	issuer3URL := url.URL{}
	issuer3URL.Scheme = "https"
	issuer3URL.Host = "issuer3.com"

	PublicCaps := server_structs.Capabilities{
		PublicReads: true,
		Reads:       true,
		Writes:      true,
	}
	PrivateCaps := server_structs.Capabilities{
		PublicReads: false,
		Reads:       true,
		Writes:      true,
	}

	nsAds := []server_structs.NamespaceAdV2{
		{
			Caps: PrivateCaps,
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl:       issuer1URL,
				BasePaths:       []string{"/p1"},
				RestrictedPaths: []string{"/p1/nope", "p1/still_nope"}}},
		},
		{
			Caps: PrivateCaps,
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: issuer2URL,
				BasePaths: []string{"/p2/path", "/p2/foo", "/p2/baz"},
			}},
		},
		{
			Path: "/p3",
			Caps: PublicCaps,
		},
		{
			Caps: PrivateCaps,
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: issuer1URL,
				BasePaths: []string{"/p1_again"},
			}, {
				IssuerUrl: issuer3URL,
				BasePaths: []string{"/i3/multi", "/ithree/multi"},
			}},
		},
		{
			Path: "/p4/depth",
			Caps: PublicCaps,
		},
		{
			Path: "/p2_noauth",
			Caps: PublicCaps,
		},
	}

	cacheServer := &cache.CacheServer{}
	cacheServer.SetNamespaceAds(nsAds)

	t.Run("MultiIssuer", cacheAuthTester(cacheServer, cacheSciOutput, "u * /p3 lr /p4/depth lr /p2_noauth lr \n"))

	nsAds = []server_structs.NamespaceAdV2{}
	cacheServer.SetNamespaceAds(nsAds)

	t.Run("EmptyNS", cacheAuthTester(cacheServer, cacheEmptyOutput, ""))
}

func TestGenerateFederationIssuer(t *testing.T) {
	testCases := []struct {
		name           string
		PublicReads    bool
		AcceptableAuth string
	}{
		{
			name:           "PublicReads",
			PublicReads:    true,
			AcceptableAuth: "",
		},
		{
			name:           "PrivateReads",
			PublicReads:    false,
			AcceptableAuth: "none",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()
			ctx, _, _ := test_utils.TestContext(context.Background(), t)

			tmpDir := t.TempDir()
			viper.Set("ConfigDir", tmpDir)
			viper.Set(param.Logging_Level.GetName(), "debug")
			viper.Set(param.Origin_RunLocation.GetName(), tmpDir)
			viper.Set(param.Origin_SelfTest.GetName(), true)
			viper.Set(param.Server_Hostname.GetName(), "origin.example.com")
			viper.Set(param.Origin_StorageType.GetName(), string(server_structs.OriginStoragePosix))
			viper.Set(param.Origin_DisableDirectClients.GetName(), true)
			viper.Set(param.Origin_EnableDirectReads.GetName(), false)
			viper.Set(param.Origin_EnablePublicReads.GetName(), tc.PublicReads)
			viper.Set(param.Origin_EnableListings.GetName(), false)
			viper.Set(param.Origin_EnableWrites.GetName(), false)
			viper.Set(param.Origin_StoragePrefix.GetName(), "/does/not/matter")
			viper.Set(param.Origin_FederationPrefix.GetName(), "/foo/bar")
			viper.Set(param.TLSSkipVerify.GetName(), true)

			test_utils.MockFederationRoot(t, nil, nil)

			config.InitConfig()
			err := config.InitServer(ctx, server_structs.OriginType)
			require.NoError(t, err)

			issuer, err := GenerateFederationIssuer()
			require.NoError(t, err)

			assert.Equal(t, issuer.Issuer, param.Federation_DiscoveryUrl.GetString())
			assert.Equal(t, issuer.Name, "Federation")
			assert.Equal(t, issuer.BasePaths, []string{"/foo/bar"})
			assert.Empty(t, issuer.RestrictedPaths)
			assert.Equal(t, issuer.DefaultUser, "")
			assert.Equal(t, issuer.AcceptableAuth, tc.AcceptableAuth)
			assert.Equal(t, issuer.RequiredAuth, "all")
		})
	}
}

func TestWriteOriginScitokensConfig(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	tmpDir := t.TempDir()
	viper.Set("ConfigDir", tmpDir)
	viper.Set(param.Logging_Level.GetName(), "debug")
	viper.Set(param.Origin_RunLocation.GetName(), tmpDir)
	viper.Set(param.Origin_SelfTest.GetName(), true)
	viper.Set(param.Origin_FederationPrefix.GetName(), "/foo/bar")
	viper.Set(param.Origin_StoragePrefix.GetName(), "/does/not/matter")
	viper.Set(param.Server_Hostname.GetName(), "origin.example.com")
	viper.Set(param.Origin_StorageType.GetName(), string(server_structs.OriginStoragePosix))

	config.InitConfig()
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	scitokensCfg := param.Xrootd_ScitokensConfig.GetString()
	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, -1)
	require.NoError(t, err)
	err = os.WriteFile(scitokensCfg, []byte(toMergeOutput), 0640)
	require.NoError(t, err)

	err = WriteOriginScitokensConfig()
	require.NoError(t, err)

	genCfg, err := os.ReadFile(filepath.Join(tmpDir, "scitokens-origin-generated.cfg"))
	require.NoError(t, err)

	assert.Equal(t, string(monitoringOutput), string(genCfg))
}
