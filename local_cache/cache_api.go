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

package local_cache

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// Launch the unix socket listener as a separate goroutine
func (lc *LocalCache) LaunchListener(ctx context.Context, egrp *errgroup.Group) (err error) {
	socketName := param.LocalCache_Socket.GetString()
	if err = os.MkdirAll(filepath.Dir(socketName), fs.FileMode(0755)); err != nil {
		err = errors.Wrap(err, "failed to create socket directory")
		return
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketName, Net: "unix"})
	if err != nil {
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		transferStatusStr := r.Header.Get("X-Transfer-Status")
		sendTrailer := false
		if transferStatusStr == "true" {
			for _, encoding := range r.Header.Values("TE") {
				if encoding == "trailers" {
					sendTrailer = true
					w.Header().Set("Trailer", "X-Transfer-Status")
					break
				}
			}
		}

		authzHeader := r.Header.Get("Authorization")
		bearerToken := ""
		if strings.HasPrefix(authzHeader, "Bearer ") {
			bearerToken = authzHeader[7:] // len("Bearer ") == 7
		}
		path := path.Clean(r.URL.Path)

		var headerTimeout time.Duration = 0
		timeoutStr := r.Header.Get("X-Pelican-Timeout")
		if timeoutStr != "" {
			if headerTimeout, err = time.ParseDuration(timeoutStr); err != nil {
				log.Debugln("Invalid X-Pelican-Timeout value:", timeoutStr)
			}
		}
		log.Debugln("Setting header timeout:", timeoutStr)

		var size uint64
		var reader io.ReadCloser
		if r.Method == "HEAD" {
			size, err = lc.Stat(path, bearerToken)
			if err == nil {
				w.Header().Set("Content-Length", strconv.FormatUint(size, 10))
			}
		} else {
			ctx = context.Background()
			if headerTimeout > 0 {
				var cancelReqFunc context.CancelFunc
				ctx, cancelReqFunc = context.WithTimeout(ctx, headerTimeout)
				defer cancelReqFunc()
			}
			reader, err = lc.Get(ctx, path, bearerToken)
		}
		if errors.Is(err, authorizationDenied) {
			w.WriteHeader(http.StatusForbidden)
			if _, err = w.Write([]byte("Authorization Denied")); err != nil {
				log.Errorln("Failed to write authorization denied to client")
			}
			return
		} else if errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(http.StatusGatewayTimeout)
			if _, err = w.Write([]byte("Upstream response timeout")); err != nil {
				log.Errorln("Failed to write gateway timeout to client")
			}
			return
		} else if err != nil {
			log.Errorln("Failed to get file from cache:", err)
			var sce *client.StatusCodeError
			if errors.As(err, &sce) {
				w.WriteHeader(int(*sce))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				if _, err = w.Write([]byte("Unexpected internal error")); err != nil {
					log.Errorln("Failed to write internal error message to client")
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == "HEAD" {
			return
		}
		if _, err = io.Copy(w, reader); err != nil && sendTrailer {
			// TODO: Enumerate more error values
			w.Header().Set("X-Transfer-Status", fmt.Sprintf("%d: %s", 500, err))
		} else if sendTrailer {
			w.Header().Set("X-Transfer-Status", "200: OK")
		}
	}
	srv := http.Server{
		Handler: http.HandlerFunc(handler),
	}
	egrp.Go(func() error {
		return srv.Serve(listener)
	})
	egrp.Go(func() error {
		<-ctx.Done()
		return srv.Shutdown(ctx)
	})
	return
}

// Register the control & monitoring routines with Gin
func (lc *LocalCache) Register(ctx context.Context, router *gin.RouterGroup) {
	router.POST("/api/v1.0/localcache/purge", func(ginCtx *gin.Context) { lc.purgeCmd(ginCtx) })
}

// Authorize the request then trigger the purge routine
func (lc *LocalCache) purgeCmd(ginCtx *gin.Context) {

	status, verified, err := token.Verify(ginCtx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Localcache_Purge},
	})
	if err != nil {
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		ginCtx.AbortWithStatusJSON(
			status,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	} else if !verified {
		ginCtx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Unknown verification error"})
		return
	}

	err = lc.purge()
	if err != nil {
		if err == purgeTimeout {
			// Note we don't use server_structs.RespTimeout here; that is reserved for a long-poll timeout.
			ginCtx.AbortWithStatusJSON(
				http.StatusRequestTimeout,
				server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		} else {
			// Note we don't pass uncategorized errors to the user to avoid leaking potentially sensitive information.
			ginCtx.AbortWithStatusJSON(
				http.StatusInternalServerError,
				server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to successfully run purge"})
		}
		return
	}
	ginCtx.JSON(
		http.StatusOK,
		server_structs.SimpleApiResp{Status: server_structs.RespOK})
}
