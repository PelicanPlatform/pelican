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

package web_ui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/sync/errgroup"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func setupTestAuthDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := path.Join(tmpDir, "authdb")
	_, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	passFile, err := htpasswd.New(dbPath, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	require.NoError(t, err)

	authDB.Store(passFile)
}

func cleanupAuthDB() {
	authDB.Store(nil)
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	defer func() {
		if err := egrp.Wait(); err != nil {
			fmt.Println("Failure when shutting down service:", err)
			os.Exit(1)
		}
	}()
	defer cancel()

	//set a temporary password file:
	tempFile, err := os.CreateTemp("", "web-ui-passwd")
	if err != nil {
		fmt.Println("Failed to setup web-ui-passwd file")
		os.Exit(1)
	}
	tempPasswdFile = tempFile
	//Override viper default for testing
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		fmt.Println("Error making temp jwk dir")
		os.Exit(1)
	}

	//Override viper default for testing
	viper.Set("IssuerKey", filepath.Join(tempJWKDir, "issuer.jwk"))

	// Ensure we load up the default configs.
	dirname, err := os.MkdirTemp("", "tmpDir")
	if err != nil {
		fmt.Println("Error making temp config dir")
		os.Exit(1)
	}
	viper.Set("ConfigDir", dirname)
	config.InitConfig()
	viper.Set("Server.UILoginRateLimit", 100)

	if err := config.InitServer(ctx, config.OriginType); err != nil {
		fmt.Println("Failed to configure the test module")
		os.Exit(1)
	}

	//Get keys
	_, err = config.GetIssuerPublicJWKS()
	if err != nil {
		fmt.Println("Error issuing jwks")
		os.Exit(1)
	}
	router = gin.Default()

	//Configure Web API
	err = ConfigureServerWebAPI(ctx, router, egrp)
	if err != nil {
		fmt.Println("Error configuring web UI")
		os.Exit(1)
	}
	//Run the tests
	exitCode := m.Run()

	//Clean up created files by removing them and exit
	os.Remove(tempPasswdFile.Name())
	os.RemoveAll(tempJWKDir)
	os.Exit(exitCode)
}

func TestHandleWebUIAuth(t *testing.T) {
	route := gin.New()
	route.GET("/view/*requestPath", handleWebUIAuth, func(ctx *gin.Context) { ctx.Status(200) })

	t.Run("html-redirect-to-init-without-db", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/initialization/code/", r.Result().Header.Get("Location"))
	})

	t.Run("no-redirect-for-unauthed-users", func(t *testing.T) {
		// We don't redirect unauthed user at the backend, so that frontend can
		// properly handle the redirect
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		authDB.Store(nil)
	})

	t.Run("skip-check-on-non-html-file", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.js", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-director", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/director/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-registry", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/registry/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})
}
