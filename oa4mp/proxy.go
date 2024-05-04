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

package oa4mp

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	// We have a custom transport object based on the common code in `config`;
	// this is because we need a custom dialer to talk to OA4MP over a socket.
	transport *http.Transport

	onceTransport sync.Once
)

func getTransport() *http.Transport {
	onceTransport.Do(func() {
		socketName := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(),
			"var", "http.sock")
		var copyTransport http.Transport = *config.GetTransport()
		transport = &copyTransport
		// When creating a new socket out to the remote server, ignore the actual
		// requested address and return a Unix socket instead.
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketName)
		}
	})
	return transport
}

func oa4mpProxy(ctx *gin.Context) {
	var user string
	if ctx.Request.URL.Path == "/api/v1.0/issuer/device" {
		web_ui.RequireAuthMiddleware(ctx)
		if ctx.IsAborted() {
			return
		}
		user = ctx.GetString("User")
		if user == "" {
			// Should be impossible; proxy ought to be called via a middleware which always
			// sets this variable
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "User authentication not set",
			})
			return
		}
	}

	origPath := ctx.Request.URL.Path
	origPath = strings.TrimPrefix(origPath, "/api/v1.0/issuer")
	ctx.Request.URL.Path = "/scitokens-server" + origPath
	ctx.Request.URL.Scheme = "http"
	ctx.Request.URL.Host = "localhost"
	if user == "" {
		ctx.Request.Header.Del("X-Pelican-User")
	} else {
		ctx.Request.Header.Set("X-Pelican-User", user)
	}

	log.Debugln("Will proxy request to URL", ctx.Request.URL.String())
	transport = getTransport()
	resp, err := transport.RoundTrip(ctx.Request)
	if err != nil {
		log.Infoln("Failed to talk to OA4MP service:", err)
		ctx.JSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unable to contact token issuer",
		})
		return
	}
	defer resp.Body.Close()

	utils.CopyHeader(ctx.Writer.Header(), resp.Header)
	ctx.Writer.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(ctx.Writer, resp.Body); err != nil {
		log.Warningln("Failed to copy response body from OA4MP to client:", err)
	}
}

func ConfigureOA4MPProxy(router *gin.Engine) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	router.Any("/api/v1.0/issuer", oa4mpProxy)
	router.Any("/api/v1.0/issuer/*path", oa4mpProxy)

	return nil
}
