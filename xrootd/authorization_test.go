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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
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

	//go:embed resources/osdf-authfile
	osdfAuthfile string

	//go:embed resources/multi-export-origin.yml
	multiExportOrigin string

	//go:embed resources/multi-export-origin-write-only.yml
	multiExportOriginWriteOnly string

	//go:embed resources/multi-export-multi-issuers.yml
	multiExportIssuers string

	//go:embed resources/single-export-no-issuers.yml
	singleExportNoIssuers string

	//go:embed resources/single-export-one-issuer.yml
	singleExportOneIssuer string

	// Configuration snippet from bug report #601
	scitokensCfgAud = `
[Global]
audience = GLOW, HCC, IceCube, NRP, OSG, PATh, UCSD

[Issuer https://ap20.uc.osg-htc.org:1094/ospool/ap20]
issuer = https://ap20.uc.osg-htc.org:1094/ospool/ap20
base_path = /ospool/ap20
`
)

func TestOSDFAuthRetrieval(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/origin/Authfile" && r.URL.RawQuery == "fqdn=sc-origin.chtc.wisc.edu" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(osdfAuthfile))
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
	require.NoError(t, param.Set(param.Federation_TopologyUrl.GetName(), "https://topology.opensciencegrid.org/"))
	require.NoError(t, param.Set(param.Server_Hostname.GetName(), "sc-origin.chtc.wisc.edu"))

	originServer := &origin.OriginServer{}
	_, err := getOSDFAuthFiles(originServer)

	require.NoError(t, err, "error")
	server_utils.ResetTestState()
}

func TestAuthPathCompToWord(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		component authPathComponent
		word      string
	}{
		// Verbose testing around `lr` combinations because these are used by Pelican
		{authPathComponent{prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}}, "/path1 lr"},
		{authPathComponent{prefix: "/path2", privs: authPrivileges{reads: true, listings: false, subtractive: false}}, "/path2 r"},
		{authPathComponent{prefix: "/path3", privs: authPrivileges{reads: false, listings: true, subtractive: false}}, "/path3 l"},
		{authPathComponent{prefix: "/path4", privs: authPrivileges{reads: true, listings: true, subtractive: true}}, "/path4 -lr"},
		{authPathComponent{prefix: "/path5", privs: authPrivileges{reads: true, listings: false, subtractive: true}}, "/path5 -r"},
		{authPathComponent{prefix: "/path6", privs: authPrivileges{reads: false, listings: true, subtractive: true}}, "/path6 -l"},

		// Other combinations may come from admin-defined authfiles
		{authPathComponent{prefix: "/path7", privs: authPrivileges{all: true, subtractive: true}}, "/path7 -a"},
		{authPathComponent{prefix: "/path8", privs: authPrivileges{delete: true, insert: true, rename: true, write: true}}, "/path8 dinw"},
	}
	for _, testInput := range testCases {
		t.Run(testInput.word, func(t *testing.T) {
			word := testInput.component.String()
			require.Equal(t, testInput.word, word, "Mismatch in word for component: %+v", testInput.component)
		})
	}
}

func TestConstructAuthEntry(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name        string
		prefix      string
		caps        server_structs.Capabilities
		expected    authPathComponent
		expectError bool
	}{
		// constructAuthEntry only cares about `lr` authfile privs because it takes as input a Capabilities struct,
		// meaning it is inherently tied to internal generation of authfile entries from exports and NOT user-supplied
		// authfiles.
		{
			"public reads only generates lr", // See comment in constructAuthEntry about why we still need `lr`
			"/foo",
			server_structs.Capabilities{PublicReads: true, Listings: false, Reads: false},
			authPathComponent{prefix: "/foo", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
			false,
		},
		{
			"public reads with writes and listings generates lr",
			"/foo",
			server_structs.Capabilities{PublicReads: true, Listings: true, Reads: true, Writes: true},
			authPathComponent{prefix: "/foo", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
			false,
		},
		{
			"protected reads, writes and listings generates -lr", // Listings subtracted because they are not public
			"/foo",
			server_structs.Capabilities{PublicReads: false, Listings: true, Reads: true, Writes: true},
			authPathComponent{prefix: "/foo", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
			false,
		},
		{
			"protected reads, writes and no listings still generates -lr", // Listings subtracted because they are not public
			"/foo",
			server_structs.Capabilities{PublicReads: false, Listings: false, Reads: true, Writes: true},
			authPathComponent{prefix: "/foo", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
			false,
		},
		{
			"protected writes generates -lr",
			"/foo",
			server_structs.Capabilities{PublicReads: false, Listings: false, Reads: false, Writes: true},
			authPathComponent{prefix: "/foo", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
			false,
		},
		{
			"no prefix generates error",
			"",
			server_structs.Capabilities{PublicReads: true, Listings: false, Reads: false},
			authPathComponent{},
			true,
		},
	}

	for _, testInput := range testCases {
		t.Run(testInput.name, func(t *testing.T) {
			authComp, err := constructAuthEntry(testInput.prefix, testInput.caps)
			if testInput.expectError {
				require.Error(t, err, "Expected error for test case: %s", testInput.name)
				return
			}
			require.NoError(t, err, "Unexpected error for test case: %s", testInput.name)
			require.Equal(t, testInput.expected, authComp, "Mismatch in auth component for test case: %s", testInput.name)
		})
	}
}

func TestAuthPrivilegesFromWord(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		privsWord   string
		privs       authPrivileges
		expectError bool
	}{
		{"lr", authPrivileges{subtractive: false, reads: true, listings: true}, false},
		{"l", authPrivileges{subtractive: false, reads: false, listings: true}, false},
		{"r", authPrivileges{subtractive: false, reads: true, listings: false}, false},
		{"-lr", authPrivileges{subtractive: true, reads: true, listings: true}, false},
		{"-l", authPrivileges{subtractive: true, reads: false, listings: true}, false},
		{"-r", authPrivileges{subtractive: true, reads: true, listings: false}, false},
		{"a", authPrivileges{subtractive: false, all: true}, false},
		{"-a", authPrivileges{subtractive: true, all: true}, false},
		{"dinw", authPrivileges{subtractive: false, delete: true, insert: true, rename: true, write: true}, false},
		{"x", authPrivileges{}, true},
		{"-x", authPrivileges{}, true},
		{"l-r", authPrivileges{}, true},
		{"", authPrivileges{}, true},
	}

	for _, testInput := range testCases {
		t.Run(testInput.privsWord, func(t *testing.T) {
			privs, err := authPrivilegesFromWord(testInput.privsWord)
			if testInput.expectError {
				require.Error(t, err, "Expected error for privs word: %s", testInput.privsWord)
				return
			}

			require.NoError(t, err, "Unexpected error for privs word: %s", testInput.privsWord)
			require.Equal(t, testInput.privs, privs, "Mismatch in privs for privs word: %s", testInput.privsWord)
		})
	}
}

func TestAuthPoliciesFromLine(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name            string
		line            string
		entries         map[string]*authLine
		expectedEntries map[string]*authLine
		expectError     bool
	}{
		{
			"simple case, first entry",
			"u * /path1 lr /path2 -r",
			map[string]*authLine{},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/path1": {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/path2": {prefix: "/path2", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
				},
				},
			},
			false,
		},
		{
			"simple case, second entry",
			"u blah /path3 -lr /path4 r",
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/path1": {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/path2": {prefix: "/path2", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
				},
				},
			},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/path1": {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/path2": {prefix: "/path2", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
				},
				},
				"u blah": {idType: "u", id: "blah", authComponents: map[string]*authPathComponent{
					"/path3": {prefix: "/path3", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/path4": {prefix: "/path4", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
				},
				},
			},
			false,
		},
		{
			"duplicate identifier",
			"u * /path3 -lr /path4 r",
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/path1": {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/path2": {prefix: "/path2", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
				},
				},
			},
			map[string]*authLine{},
			true,
		},
		{
			"duplicate paths",
			"u * /path1 lr /path1 -r",
			map[string]*authLine{},
			map[string]*authLine{},
			true,
		},
		{
			"malformed missing privileges",
			"u * /path1 lr /path2 -r /path-missing-privileges",
			map[string]*authLine{}, // no entries yet
			map[string]*authLine{},
			true,
		},
		{
			"malformed no paths",
			"u *",
			map[string]*authLine{}, // no entries yet
			map[string]*authLine{},
			true,
		},
		{
			"malformed bad privileges",
			"u * /foo x",
			map[string]*authLine{}, // no entries yet
			map[string]*authLine{},
			true,
		},
		{
			"comments skipped",
			"# u * /foo x",
			map[string]*authLine{}, // no entries yet
			map[string]*authLine{},
			false,
		},
	}

	for _, testInput := range testCases {
		t.Run(testInput.line, func(t *testing.T) {
			err := authPoliciesFromLine(testInput.line, testInput.entries)
			if testInput.expectError {
				require.Error(t, err, "Expected error for line: %s", testInput.line)
				return
			}
			require.NoError(t, err, "Unexpected error for line: %s", testInput.line)
			require.True(t, reflect.DeepEqual(testInput.expectedEntries, testInput.entries), "Mismatch in entries for line: %s: %+v", testInput.line, testInput.entries)
		})
	}
}

// Helper function for other tests here who call server_utils.GetOriginExports() internally.
// This function gets a temp dir for export StoragePrefixes, whose existence is validated
// by server_utils.GetOriginExports().
func getTmpFile(t *testing.T) string {
	tmpFile := t.TempDir() + "/tmpfile"

	// Create the file
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	file.Close()

	// Set file permissions to 777
	err = os.Chmod(tmpFile, 0777)
	if err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	return tmpFile
}

// Helper function for other tests here who call server_utils.GetOriginExports() internally.
// This function populates the values so that call doesn't fail.
func setupExports(t *testing.T, config string) {
	viper.SetConfigType("yaml")
	// Use viper to read in the embedded config
	err := viper.ReadConfig(strings.NewReader(config))
	require.NoError(t, err, "error reading config")
	// Some keys need to be overridden because GetOriginExports validates things like filepaths by making
	// sure the file exists and is readable by the process.
	// Iterate through Origin.XXX keys and check for "<WILL BE REPLACED IN TEST>" in the value
	for _, key := range viper.AllKeys() {
		if strings.Contains(viper.GetString(key), "<WILL BE REPLACED IN TEST>") {
			tmpFile := getTmpFile(t)
			require.NoError(t, param.Set(key, tmpFile))
		} else if key == "origin.exports" { // keys will be lowercased
			// We also need to override paths for any exports that define "SHOULD-OVERRIDE-TEMPFILE"
			exports := viper.Get(key).([]interface{})
			for _, export := range exports {
				exportMap := export.(map[string]interface{})
				for k, v := range exportMap {
					if v == "<WILL BE REPLACED IN TEST>" {
						tmpFile := getTmpFile(t)
						exportMap[k] = tmpFile
					}
				}
			}
			// Set the modified exports back to viper after all overrides
			require.NoError(t, param.Set(key, exports))
		}
	}

	// Provide an issuer URL so setup doesn't fail
	require.NoError(t, param.Set(param.Server_IssuerUrl.GetName(), "https://foo.bar.com"))

	// Now call GetOriginExports and check the struct
	_, err = server_utils.GetOriginExports()
	require.NoError(t, err, "error getting origin exports")
}

func TestPopulateAuthLinesMapForOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name              string
		inputAuthLinesMap map[string]*authLine
		expectedEntries   map[string]*authLine
		inputOriginCfg    string
	}{
		// Each of the tests uses the same multi-export Origin config, which has both
		// public and protected namespaces.
		{
			"multi-export, multi-auth origin with no input authfile",
			map[string]*authLine{},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
			multiExportOrigin,
		},
		{
			"multi-export, multi-auth origin with non-conflicting input authfile",
			map[string]*authLine{
				"u another": {idType: "u", id: "another", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{all: true}},
					"/fourth/namespace": {prefix: "/fourth/namespace", privs: authPrivileges{delete: true, insert: true, rename: true, write: true}},
				},
				},
			},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
				"u another": {idType: "u", id: "another", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{all: true}},
					"/fourth/namespace": {prefix: "/fourth/namespace", privs: authPrivileges{delete: true, insert: true, rename: true, write: true}},
				},
				},
			},
			multiExportOrigin,
		},
		{
			"multi-export, multi-auth origin with conflicting input authfile",
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace": {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/third/namespace": {prefix: "/third/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
			map[string]*authLine{
				// The pre-populated auth map coming from admin input should override the export-derived one
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
			multiExportOrigin,
		},
		{
			"multi-export, multi-auth origin with no input authfile where one namespace has no reads",
			map[string]*authLine{},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/mynamespace":        {prefix: "/mynamespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/mynamespace-writes": {prefix: "/mynamespace-writes", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/.well-known":        {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
			multiExportOriginWriteOnly,
		},
	}

	for _, testInput := range testCases {
		t.Run(testInput.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			setupExports(t, testInput.inputOriginCfg)

			err := populateAuthLinesMapForOrigin(testInput.inputAuthLinesMap)
			// Note we don't test for the err != nil case because that implies GetOriginExports returned
			// a prefixless-export. This error cannot be triggered by these inputs.
			require.NoError(t, err, "Unexpected error for test case: %s", testInput.name)
			// Since the outer map contains an inner map to references, spew lets us see the full structure on error
			require.True(t, reflect.DeepEqual(testInput.expectedEntries, testInput.inputAuthLinesMap),
				"Mismatch in entries for test case: %s\nExpected:\n%s\nActual:\n%s",
				testInput.name,
				spew.Sdump(testInput.expectedEntries),
				spew.Sdump(testInput.inputAuthLinesMap),
			)
		})
	}
}

func TestPopulateAuthLinesMapForCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	nsAds := []server_structs.NamespaceAdV2{
		{
			Caps: server_structs.Capabilities{PublicReads: true, Listings: true, Reads: true},
			Path: "/first/namespace",
		},
		{
			Caps: server_structs.Capabilities{PublicReads: false, Listings: false, Reads: true},
			Path: "/second/namespace",
		},
	}
	server := server_structs.XRootDServer(&cache.CacheServer{})
	server.SetNamespaceAds(nsAds)

	testCases := []struct {
		name              string
		inputAuthLinesMap map[string]*authLine
		expectedEntries   map[string]*authLine
	}{
		{
			"multi-export, multi-auth cache with no input authfile",
			map[string]*authLine{},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
		},
		{
			"multi-export, multi-auth cache with non-conflicting input authfile",
			map[string]*authLine{
				"u another": {idType: "u", id: "another", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{all: true}},
					"/fourth/namespace": {prefix: "/fourth/namespace", privs: authPrivileges{delete: true, insert: true, rename: true, write: true}},
				},
				},
			},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
				"u another": {idType: "u", id: "another", authComponents: map[string]*authPathComponent{
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{all: true}},
					"/fourth/namespace": {prefix: "/fourth/namespace", privs: authPrivileges{delete: true, insert: true, rename: true, write: true}},
				},
				},
			},
		},
		{
			"multi-export, multi-auth cache with conflicting input authfile",
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					"/first/namespace": {prefix: "/first/namespace", privs: authPrivileges{reads: false, listings: true, subtractive: false}},
					"/third/namespace": {prefix: "/third/namespace", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
				},
				},
			},
			map[string]*authLine{
				"u *": {idType: "u", id: "*", authComponents: map[string]*authPathComponent{
					// This one is overridden by discovered namespace ad
					"/first/namespace":  {prefix: "/first/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					"/second/namespace": {prefix: "/second/namespace", privs: authPrivileges{reads: true, listings: true, subtractive: true}},
					"/third/namespace":  {prefix: "/third/namespace", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
					"/.well-known":      {prefix: "/.well-known", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				},
				},
			},
		},
	}

	for _, testInput := range testCases {
		t.Run(testInput.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			err := populateAuthLinesMapForCache(testInput.inputAuthLinesMap, server)
			// Similar to the Origin case, we don't test for the err != nil case because that implies
			// a prefixless-export. This error cannot be triggered by these inputs.
			require.NoError(t, err, "Unexpected error for test case: %s", testInput.name)
			// Since the outer map contains an inner map to references, spew lets us see the full structure on error
			require.True(t, reflect.DeepEqual(testInput.expectedEntries, testInput.inputAuthLinesMap),
				"Mismatch in entries for test case: %s\nExpected:\n%s\nActual:\n%s",
				testInput.name,
				spew.Sdump(testInput.expectedEntries),
				spew.Sdump(testInput.inputAuthLinesMap),
			)
		})
	}
}

func TestSerializeAuthline(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name     string
		authLine authLine
		outStr   string
	}{
		{
			"single path",
			authLine{idType: "u", id: "*", authComponents: map[string]*authPathComponent{
				"/path1": {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
			},
			},
			"u * /path1 lr",
		},
		{
			"multiple paths with different lengths",
			authLine{idType: "u", id: "*", authComponents: map[string]*authPathComponent{
				"/path1":   {prefix: "/path1", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				"/path123": {prefix: "/path123", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
			},
			},
			"u * /path123 -r /path1 lr",
		},
		{
			"multiple paths with same lengths",
			// Until we switch to an ordered map, we'll always sort
			// lexicographically when lengths are the same -- regular
			// go maps have no order to preserve.
			authLine{idType: "u", id: "*", authComponents: map[string]*authPathComponent{
				"/path432": {prefix: "/path432", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
				"/path123": {prefix: "/path123", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
			},
			},

			"u * /path123 -r /path432 lr",
		},
	}

	for _, testInput := range testCases {
		t.Run(testInput.name, func(t *testing.T) {
			outStr := serializeAuthLine(testInput.authLine)
			require.Equal(t, testInput.outStr, outStr, "Mismatch in serialized authline for test case: %s", testInput.name)
		})
	}
}

func TestGetSortedSerializedAuthLines(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tests := []struct {
		name     string
		input    map[string]*authLine
		expected []string
	}{
		{
			name: "Only u * entry",
			input: map[string]*authLine{
				"u *": {
					idType: "u",
					id:     "*",
					authComponents: map[string]*authPathComponent{
						"/foo":    {prefix: "/foo", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
						"/foobar": {prefix: "/foobar", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
					},
				},
			},
			expected: []string{"u * /foobar -r /foo r"},
		},
		{
			name: "Multiple entries, u * last",
			input: map[string]*authLine{
				"u alice": {
					idType: "u",
					id:     "alice",
					authComponents: map[string]*authPathComponent{
						"/bar": {prefix: "/bar", privs: authPrivileges{reads: true, listings: true, subtractive: false}},
					},
				},
				"u *": {
					idType: "u",
					id:     "*",
					authComponents: map[string]*authPathComponent{
						"/foo":    {prefix: "/foo", privs: authPrivileges{reads: true, listings: false, subtractive: false}},
						"/foobar": {prefix: "/foobar", privs: authPrivileges{reads: true, listings: false, subtractive: true}},
					},
				},
			},
			expected: []string{
				"u alice /bar lr",
				"u * /foobar -r /foo r",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := getSortedSerializedAuthLines(tc.input)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestEmitAuthfile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name                 string
		serverType           server_structs.ServerType
		originCfg            string                         // only used if serverType is Origin
		nsAds                []server_structs.NamespaceAdV2 // only used if serverType is Cache
		dropPrivileges       bool
		discoverOSDFAuthfile bool
		inputAuthfile        string
		expectedAuthfile     string
	}{
		{
			name:                 "Origin with discoverOSDFAuthfile true and valid input authfile",
			serverType:           server_structs.OriginType,
			originCfg:            multiExportOrigin,
			discoverOSDFAuthfile: true,
			inputAuthfile:        "u * /valid/path r\n",
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: `u 3af6a420.0 /chtc/PROTECTED/sc-origin lr
u 4ff08838.0 /chtc/PROTECTED/sc-origin lr
u 5a42185a.0 /chtc/PROTECTED/sc-origin lr
u * /second/namespace -lr /first/namespace lr /.well-known lr /valid/path r
`,
		},
		{
			name:          "Origin with valid input authfile and without OSDF authfile",
			serverType:    server_structs.OriginType,
			originCfg:     multiExportOrigin,
			inputAuthfile: "u * /valid/path r\nu another /another/path lr",
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: `u another /another/path lr
u * /second/namespace -lr /first/namespace lr /.well-known lr /valid/path r
`,
		},
		{
			name:       "Origin with multiline input authfile and without OSDF authfile",
			serverType: server_structs.OriginType,
			originCfg:  multiExportOrigin,
			inputAuthfile: `u * /valid/path r \
/second/valid/path lr
u another /another/path lr`,
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: `u another /another/path lr
u * /second/valid/path lr /second/namespace -lr /first/namespace lr /.well-known lr /valid/path r
`,
		},
		{
			name:       "Origin with without extra authfiles",
			serverType: server_structs.OriginType,
			originCfg:  multiExportOrigin,
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: "u * /second/namespace -lr /first/namespace lr /.well-known lr\n",
		},
		{
			name:       "Origin with without extra authfiles, drop privs",
			serverType: server_structs.OriginType,
			originCfg:  multiExportOrigin,
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: "u * /second/namespace -lr /first/namespace lr /.well-known lr\n",
		},
		{
			name:       "Cache with discoverOSDFAuthfile true and valid input authfile",
			serverType: server_structs.CacheType,
			nsAds: []server_structs.NamespaceAdV2{
				{
					Caps: server_structs.Capabilities{PublicReads: true, Listings: true, Reads: true},
					Path: "/first/namespace",
				},
				{
					Caps: server_structs.Capabilities{PublicReads: false, Listings: false, Reads: true},
					Path: "/second/namespace",
				},
			},
			discoverOSDFAuthfile: true,
			inputAuthfile:        "u * /valid/path r\n",
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: `u 3af6a420.0 /chtc/PROTECTED/sc-origin lr
u 4ff08838.0 /chtc/PROTECTED/sc-origin lr
u 5a42185a.0 /chtc/PROTECTED/sc-origin lr
u * /second/namespace -lr /first/namespace lr /.well-known lr /valid/path r
`,
		},
		{
			name:       "Cache with valid input authfile and without OSDF authfile",
			serverType: server_structs.CacheType,
			nsAds: []server_structs.NamespaceAdV2{
				{
					Caps: server_structs.Capabilities{PublicReads: true, Listings: true, Reads: true},
					Path: "/first/namespace",
				},
				{
					Caps: server_structs.Capabilities{PublicReads: false, Listings: false, Reads: true},
					Path: "/second/namespace",
				},
			},
			inputAuthfile: "u another /another/path lr\nu * /valid/path r\n",
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: `u another /another/path lr
u * /second/namespace -lr /first/namespace lr /.well-known lr /valid/path r
`,
		},
		{
			name:       "Cache with without input authfile or OSDF authfile",
			serverType: server_structs.CacheType,
			nsAds: []server_structs.NamespaceAdV2{
				{
					Caps: server_structs.Capabilities{PublicReads: true, Listings: true, Reads: true},
					Path: "/first/namespace",
				},
				{
					Caps: server_structs.Capabilities{PublicReads: false, Listings: false, Reads: true},
					Path: "/second/namespace",
				},
			},
			// The IDType:ID orderings from the OSDF Authfile are first sorted by length and then alphabetically,
			// meaning the original order from the OSDF Authfile is not preserved. This guarantees the most
			// specific entries are always matched first.
			expectedAuthfile: "u * /second/namespace -lr /first/namespace lr /.well-known lr\n",
		},
	}

	// Start a test server that will return the OSDF authfile for tests that need it
	// We don't do any fancy path parsing here -- just give the file for all GET requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" {
			res := []byte(osdfAuthfile)
			_, err := w.Write(res)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dirname := t.TempDir()
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), filepath.Join(dirname, "origin")))
			require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), filepath.Join(dirname, "cache")))
			if tc.inputAuthfile != "" {
				require.NoError(t, param.Set(param.Xrootd_Authfile.GetName(), filepath.Join(dirname, "input-authfile")))
			}
			require.NoError(t, param.Set(param.Federation_TopologyUrl.GetName(), ts.URL))

			require.NoError(t, param.Set(param.Server_DropPrivileges.GetName(), tc.dropPrivileges))

			// Toggle whether the OSDF Authfile discovery should be triggered
			if tc.discoverOSDFAuthfile {
				oldPrefix, err := config.SetPreferredPrefix(config.OsdfPrefix)
				require.NoError(t, err, "error setting preferred prefix")
				t.Cleanup(func() {
					_, _ = config.SetPreferredPrefix(oldPrefix)
				})

				require.NoError(t, param.Set(param.Topology_DisableCacheX509.GetName(), false))
				require.NoError(t, param.Set(param.Topology_DisableOriginX509.GetName(), false))
			} else {
				require.NoError(t, param.Set(param.Topology_DisableCacheX509.GetName(), true))
				require.NoError(t, param.Set(param.Topology_DisableOriginX509.GetName(), true))
			}

			// Write the input authfile if provided
			if tc.inputAuthfile != "" {
				err := os.WriteFile(viper.GetString(param.Xrootd_Authfile.GetName()), []byte(tc.inputAuthfile), 0600)
				require.NoError(t, err)
			}

			// Set up the servers with their exports/namespace ads
			var server server_structs.XRootDServer
			var generatedAuthfileName string
			var serverDir string
			if tc.serverType == server_structs.OriginType {
				server = &origin.OriginServer{}
				setupExports(t, tc.originCfg)
				generatedAuthfileName = "authfile-origin-generated"
				serverDir = viper.GetString(param.Origin_RunLocation.GetName())
			} else if tc.serverType == server_structs.CacheType {
				server = &cache.CacheServer{}
				server.SetNamespaceAds(tc.nsAds)
				generatedAuthfileName = "authfile-cache-generated"
				serverDir = viper.GetString(param.Cache_RunLocation.GetName())
			}
			err := os.MkdirAll(serverDir, 0755)
			require.NoError(t, err, "error creating server run dir")
			generatedAuthfilePath := filepath.Join(serverDir, generatedAuthfileName)

			err = EmitAuthfile(server, true)
			require.NoError(t, err, "Unexpected error for test case: %s", tc.name)

			// Read back the emitted authfile and compare with expected
			emittedAuthfileBytes, err := os.ReadFile(generatedAuthfilePath)
			require.NoError(t, err, "error reading emitted authfile for test case: %s", tc.name)

			require.Equal(t, tc.expectedAuthfile, string(emittedAuthfileBytes), "Mismatch in emitted authfile for test case: %s", tc.name)
		})
	}
}

func TestEmitCfg(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	dirname := t.TempDir()
	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	test_utils.InitClient(t, nil)
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), dirname))

	configTester := func(cfg *ScitokensCfg, configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			err := writeScitokensConfiguration(server_structs.OriginType, cfg, false)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	dirname := t.TempDir()
	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	test_utils.InitClient(t, nil)

	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), dirname))

	configTester := func(configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			cfgFname := filepath.Join(dirname, "scitokens-test.cfg")
			err := os.WriteFile(cfgFname, []byte(configResult), 0600)
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(cfgFname)
			require.NoError(t, err)

			err = writeScitokensConfiguration(server_structs.OriginType, &cfg, false)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	dirname := t.TempDir()
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	test_utils.MockFederationRoot(t, nil, nil)

	storageDir := filepath.Join(dirname, "storage")
	require.NoError(t, os.MkdirAll(storageDir, 0755))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), dirname))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 8443))
	require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), storageDir))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/"))
	require.NoError(t, param.Set("ConfigDir", dirname))
	// We don't inherit any defaults at this level of code -- in order to recognize
	// that this is an authorized prefix, we must set either EnableReads && !EnablePublicReads
	// or EnableWrites
	require.NoError(t, param.Set(param.Origin_EnableReads.GetName(), true))
	scitokensConfigFile := filepath.Join(dirname, "scitokens-input.cfg")
	require.NoError(t, param.Set(param.Xrootd_ScitokensConfig.GetName(), scitokensConfigFile))

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
	t.Cleanup(test_utils.SetupTestLogging(t))
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
			require.NoError(t, param.Set(param.Origin_SelfTest.GetName(), tc.selfTestEnabled))
			require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), tc.externalWebUrl))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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
			require.NoError(t, param.Set("ConfigDir", t.TempDir()))
			require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))

			test_utils.MockFederationRoot(t, nil, nil)

			// Load in test config
			viper.SetConfigType("yaml")
			err := viper.MergeConfig(strings.NewReader(tc.yamlConfig))
			require.NoError(t, err, "error reading config")
			err = config.InitServer(ctx, server_structs.OriginType)
			require.NoError(t, err)

			// Set extra Viper settings if provided
			for key, value := range tc.extraViperSettings {
				require.NoError(t, param.Set(key, value))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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

func TestGenerateFederationIssuer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
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
			require.NoError(t, param.Set("ConfigDir", tmpDir))
			require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
			require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), tmpDir))
			require.NoError(t, param.Set(param.Origin_SelfTest.GetName(), true))
			require.NoError(t, param.Set(param.Server_Hostname.GetName(), "origin.example.com"))
			require.NoError(t, param.Set(param.Origin_StorageType.GetName(), string(server_structs.OriginStoragePosix)))
			require.NoError(t, param.Set(param.Origin_DisableDirectClients.GetName(), true))
			require.NoError(t, param.Set(param.Origin_EnableDirectReads.GetName(), false))
			require.NoError(t, param.Set(param.Origin_EnablePublicReads.GetName(), tc.PublicReads))
			require.NoError(t, param.Set(param.Origin_EnableListings.GetName(), false))
			require.NoError(t, param.Set(param.Origin_EnableWrites.GetName(), false))
			require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), "/does/not/matter"))
			require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/foo/bar"))
			require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))

			test_utils.MockFederationRoot(t, nil, nil)

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
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	tmpDir := t.TempDir()
	require.NoError(t, param.Set("ConfigDir", tmpDir))
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), tmpDir))
	require.NoError(t, param.Set(param.Origin_SelfTest.GetName(), true))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/foo/bar"))
	require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), "/does/not/matter"))
	require.NoError(t, param.Set(param.Server_Hostname.GetName(), "origin.example.com"))
	require.NoError(t, param.Set(param.Origin_StorageType.GetName(), string(server_structs.OriginStoragePosix)))

	test_utils.MockFederationRoot(t, nil, nil)

	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	// Since this test asserts the static config from resources/test-scitokens-monitoring.cfg
	// matches the generated/written config, we need to force WriteOriginScitokensConfig to find a
	// static federation issuer URL as well. The mocked fed root has already assisted with discovery,
	// so we can now overwrite the discovered fed info with something static.
	config.SetFederation(pelican_url.FederationDiscovery{DiscoveryEndpoint: "https://federation.example.com/discovery"})

	scitokensCfg := param.Xrootd_ScitokensConfig.GetString()
	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, -1)
	require.NoError(t, err)
	err = os.WriteFile(scitokensCfg, []byte(toMergeOutput), 0640)
	require.NoError(t, err)

	err = WriteOriginScitokensConfig(false)
	require.NoError(t, err)

	genCfg, err := os.ReadFile(filepath.Join(tmpDir, "scitokens-origin-generated.cfg"))
	require.NoError(t, err)

	assert.Equal(t, string(monitoringOutput), string(genCfg))
}

// TestConfigFilesUpdateDuringRuntime tests that scitokens.cfg and authfile are actually updated
// when namespace ads change during runtime. It simulates runtime by invoking the same write
// functions the maintenance loop uses.
func TestConfigFilesUpdateDuringRuntime(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	dirName := t.TempDir()

	// Set up basic configuration for cache
	require.NoError(t, param.Set("Xrootd.Authfile", filepath.Join(dirName, "authfile")))
	require.NoError(t, param.Set("Xrootd.ScitokensConfig", filepath.Join(dirName, "scitokens.cfg")))
	require.NoError(t, param.Set("Cache.RunLocation", dirName))
	require.NoError(t, param.Set("Server.DropPrivileges", false)) // Not testing drop privileges mode

	// Create minimal input files
	err := os.WriteFile(filepath.Join(dirName, "authfile"), []byte(""), fs.FileMode(0600))
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dirName, "scitokens.cfg"), []byte(""), fs.FileMode(0600))
	require.NoError(t, err)

	// Create cache server with initial namespace ads - one public, one private
	cacheServer := &cache.CacheServer{}
	initialNamespaceAds := []server_structs.NamespaceAdV2{
		{
			Path: "/public/data",
			Caps: server_structs.Capabilities{
				PublicReads: true,
				Reads:       true,
			},
		},
		{
			Path: "/private/data",
			Caps: server_structs.Capabilities{
				PublicReads: false,
				Reads:       true,
			},
			Issuer: []server_structs.TokenIssuer{
				{
					IssuerUrl: url.URL{Scheme: "https", Host: "issuer.example.com"},
					BasePaths: []string{"/private/data"},
				},
			},
		},
	}
	cacheServer.SetNamespaceAds(initialNamespaceAds)

	// Generate initial configuration files
	err = EmitAuthfile(cacheServer, false)
	require.NoError(t, err)
	err = EmitScitokensConfig(cacheServer)
	require.NoError(t, err)

	// Get paths to generated files
	authfilePath := filepath.Join(dirName, "authfile-cache-generated")
	scitokensPath := filepath.Join(dirName, "scitokens-cache-generated.cfg")

	// Verify initial files exist
	require.FileExists(t, authfilePath)
	require.FileExists(t, scitokensPath)

	// Read initial content and get modification times
	initialAuthContent, err := os.ReadFile(authfilePath)
	require.NoError(t, err)
	initialScitokensContent, err := os.ReadFile(scitokensPath)
	require.NoError(t, err)

	initialAuthStat, err := os.Stat(authfilePath)
	require.NoError(t, err)
	initialSciTokensStat, err := os.Stat(scitokensPath)
	require.NoError(t, err)

	// Verify initial authfile contains public namespace
	assert.Contains(t, string(initialAuthContent), "/public/data lr")

	// Verify initial scitokens.cfg contains the private issuer
	assert.Contains(t, string(initialScitokensContent), "issuer.example.com")

	// Wait a small amount of time to ensure file modification times will differ
	time.Sleep(10 * time.Millisecond)

	// Simulate namespace ads changing - make the previously public namespace private
	// and add a new public namespace
	updatedNamespaceAds := []server_structs.NamespaceAdV2{
		{
			Path: "/public/data", // This was public, now becomes private
			Caps: server_structs.Capabilities{
				PublicReads: false,
				Reads:       true,
			},
			Issuer: []server_structs.TokenIssuer{
				{
					IssuerUrl: url.URL{Scheme: "https", Host: "issuer.example.com"},
					BasePaths: []string{"/public/data"},
				},
			},
		},
		{
			Path: "/private/data", // Unchanged
			Caps: server_structs.Capabilities{
				PublicReads: false,
				Reads:       true,
			},
			Issuer: []server_structs.TokenIssuer{
				{
					IssuerUrl: url.URL{Scheme: "https", Host: "issuer.example.com"},
					BasePaths: []string{"/private/data"},
				},
			},
		},
		{
			Path: "/new/public", // New public namespace
			Caps: server_structs.Capabilities{
				PublicReads: true,
				Reads:       true,
			},
		},
	}
	cacheServer.SetNamespaceAds(updatedNamespaceAds)

	// Trigger config file updates (simulating what maintenance loop would do)
	err = EmitAuthfile(cacheServer, false)
	require.NoError(t, err)
	err = EmitScitokensConfig(cacheServer)
	require.NoError(t, err)

	// Read updated content and get new modification times
	updatedAuthContent, err := os.ReadFile(authfilePath)
	require.NoError(t, err)
	updatedScitokensContent, err := os.ReadFile(scitokensPath)
	require.NoError(t, err)

	updatedAuthStat, err := os.Stat(authfilePath)
	require.NoError(t, err)
	updatedSciTokensStat, err := os.Stat(scitokensPath)
	require.NoError(t, err)

	// Verify files were actually updated (modification times advanced)
	assert.True(t, updatedAuthStat.ModTime().After(initialAuthStat.ModTime()),
		"Authfile modification time should advance after update")
	assert.True(t, updatedSciTokensStat.ModTime().After(initialSciTokensStat.ModTime()),
		"Scitokens config modification time should advance after update")

	// Verify content actually changed
	assert.NotEqual(t, string(initialAuthContent), string(updatedAuthContent),
		"Authfile content should change when namespace ads change")
	assert.NotEqual(t, string(initialScitokensContent), string(updatedScitokensContent),
		"Scitokens config content should change when namespace ads change")

	// Verify specific security-critical changes in authfile:
	// - Should no longer contain public access to /public/data
	// - Should contain public access to /new/public
	assert.NotContains(t, string(updatedAuthContent), "/public/data lr",
		"Previously public namespace should not have public access in updated authfile")
	assert.Contains(t, string(updatedAuthContent), "/new/public lr",
		"New public namespace should have public access in updated authfile")

	// Verify specific changes in scitokens.cfg:
	// - Should now have /public/data as a base path for the issuer (since it's now private)
	assert.Contains(t, string(updatedScitokensContent), "/public/data",
		"Previously public namespace should now appear in scitokens config as private")
}
