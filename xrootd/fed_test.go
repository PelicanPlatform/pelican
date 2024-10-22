//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package xrootd_test

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/test-https-origin.yml
	httpsOriginConfig string
)

func TestHttpOriginConfig(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	// temp place holder so we can start the test server before this value has been parsed
	// from the http origin config
	var storageName string

	body := "Hello, World!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.Path == storageName {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == "GET" && r.URL.Path == storageName {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte(body))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	viper.Set("Origin.HttpServiceUrl", srv.URL)

	fed := fed_test_utils.NewFedTest(t, httpsOriginConfig)
	storageName = fed.Exports[0].StoragePrefix + "/hello_world"
	discoveryHost := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	// Download the test file
	tmpPath := t.TempDir()
	transferResults, err := client.DoGet(
		fed.Ctx,
		"pelican://"+discoveryHost+"/my-prefix/hello_world",
		filepath.Join(tmpPath, "hw"),
		false,
	)
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, transferResults[0].TransferredBytes, int64(len(body)))
	}
}
