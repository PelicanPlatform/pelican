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

package origin_ui

import (
	"embed"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
)

var (

	//go:embed src/out/*
	webAssets embed.FS
)

func ConfigOriginUI(engine *gin.Engine) {
	engine.GET("/view/*path", func(ctx *gin.Context) {
		path := ctx.Param("path")

		if strings.HasSuffix(path, "/") {
			path += "index.html"
		}

		filePath := "src/out" + path
		file, _ := webAssets.ReadFile(filePath)
		ctx.Data(
			http.StatusOK,
			mime.TypeByExtension(filePath),
			file,
		)
	})
}

// Configure XrootD directory for both self-based and director-based file transfer tests
func ConfigureXrootdMonitoringDir() error {
	pelicanMonitoringPath := filepath.Join(param.Xrootd_RunLocation.GetString(),
		"export", "pelican", "monitoring")

	uid, err := config.GetDaemonUID()
	if err != nil {
		return err
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}
	username, err := config.GetDaemonUser()
	if err != nil {
		return err
	}

	err = config.MkdirAll(pelicanMonitoringPath, 0755, uid, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create pelican file trasnfer monitoring directory %v",
			pelicanMonitoringPath)
	}
	if err = os.Chown(pelicanMonitoringPath, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of pelican file trasnfer monitoring directory %v"+
			" to desired daemon user %v", pelicanMonitoringPath, username)
	}

	return nil
}
