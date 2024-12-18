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

package origin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestSuccessfulCreateNewIssuerKey(t *testing.T) {
	server_utils.ResetTestState()

	tDir := t.TempDir()
	iksDir := filepath.Join(tDir, "test-issuer-keys")
	viper.Set("IssuerKeysDirectory", iksDir)
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

	router := gin.Default()
	router.GET("/api/v1.0/origin_ui/newIssuerKey", createNewIssuerKey)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1.0/origin_ui/newIssuerKey", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response server_structs.SimpleApiResp
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, server_structs.RespOK, response.Status)
	assert.Equal(t, "Created a new issuer key", response.Msg)

	files, err := os.ReadDir(iksDir)
	require.NoError(t, err)
	require.Len(t, files, 1, "A new .pem file should be created in the directory")
	newKeyFile := filepath.Join(iksDir, files[0].Name())
	assert.FileExists(t, newKeyFile, "The new .pem file does not exist")
}

func TestFailedCreateNewIssuerKey(t *testing.T) {
	server_utils.ResetTestState()

	tDir := t.TempDir()
	viper.Set("IssuerKeysDirectory", filepath.Join(tDir, "test-issuer-keys"))
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

	router := gin.Default()
	router.GET("/api/v1.0/origin_ui/newIssuerKey", createNewIssuerKey)

	// Mock GeneratePEM
	originalGeneratePEM := GeneratePEM
	GeneratePEM = func(dir string) (jwk.Key, error) {
		return nil, assert.AnError
	}
	defer func() { GeneratePEM = originalGeneratePEM }()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1.0/origin_ui/newIssuerKey", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response server_structs.SimpleApiResp
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, server_structs.RespFailed, response.Status)
	assert.Equal(t, "Error creating a new private key in a new .pem file", response.Msg)
}
