//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

package client_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/client"
	config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTPC(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()

	viper.Set("Logging.Level", "debug")
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/test")
	require.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/test")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	destDir := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir, os.FileMode(0755)))
	log.Debugln("Will create origin file at", destDir)
	fileContents := []byte("test file content")
	err = os.WriteFile(filepath.Join(destDir, "test.txt"), fileContents, fs.FileMode(0644))
	require.NoError(t, err)
	downloadURL := fmt.Sprintf("pelican://%s:%s%s/test/test.txt", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
		fed.Exports[0].FederationPrefix)
	uploadURL := fmt.Sprintf("pelican://%s:%s%s/test/test_up.txt", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
		fed.Exports[0].FederationPrefix)
	copyDestURL := fmt.Sprintf("pelican://%s:%s%s/test/test_copy.txt", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
		fed.Exports[0].FederationPrefix)

	// Verify simple download / upload works.
	localDir := t.TempDir()
	_, err = client.DoGet(fed.Ctx, downloadURL, localDir, false, client.WithToken(tkn))
	require.NoError(t, err)
	_, err = client.DoPut(fed.Ctx, filepath.Join(localDir, "test.txt"), uploadURL, false, client.WithToken(tkn))
	require.NoError(t, err)

	_, err = client.DoCopy(fed.Ctx, uploadURL, copyDestURL, false, client.WithToken(tkn), client.WithSourceToken(tkn))
	require.NoError(t, err)

	transferResults, err := client.DoGet(fed.Ctx, copyDestURL, localDir, false, client.WithToken(tkn))
	require.NoError(t, err)
	require.Len(t, transferResults, 1)
	require.Equal(t, int64(len(fileContents)), transferResults[0].TransferredBytes)
}
