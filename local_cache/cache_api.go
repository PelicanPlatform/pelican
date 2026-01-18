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
	socketDir := filepath.Dir(socketName)

	if err = os.MkdirAll(socketDir, fs.FileMode(0755)); err != nil {
		err = errors.Wrap(err, "failed to create socket directory")
		return
	}

	var startupDir string
	// Create a temporary directory for the socket; once we are listening on the socket, we rename
	// the temporary directory to the final socket name. This allows us to avoid outages if multiple
	// processes are trying to create the socket at the same time (or if the socket already exists
	// from a previous startup that didn't clean up properly).
	//
	// Note: Linux has relatively short limits on the name length of a Unix socket.
	// We use the terse "lc-*" prefix to avoid exceeding the limit.
	if startupDir, err = os.MkdirTemp(socketDir, "lc-*"); err != nil {
		err = errors.Wrap(err, "failed to create temporary directory for launching local cache socket")
		return
	}
	// Allow other users to access the socket
	if err = os.Chmod(startupDir, 0755); err != nil {
		err = errors.Wrap(err, "failed to set permissions on temporary directory for local cache socket")
		return
	}
	defer func() {
		var matches []string
		matches, err2 := filepath.Glob(filepath.Join(socketDir, "lc-*"))
		if err2 != nil {
			err2 = errors.Wrap(err2, "failed to list temporary directories for cleaning up local cache socket")
			if err == nil {
				err = err2
			}
			return
		}
		for _, dir := range matches {
			if err2 := os.RemoveAll(dir); err2 != nil {
				log.Warningf("Failed to remove temporary directory %s: %v", dir, err2)
			}
		}
	}()

	startupSockName := filepath.Join(startupDir, filepath.Base(socketName))
	var listener *net.UnixListener
	if listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: startupSockName, Net: "unix"}); err != nil {
		err = errors.Wrap(err, "failed to create unix socket for local cache")
		log.Warningf("Failed to create socket %s: %v", startupSockName, err)
		return err
	}

	// Allow other users to write to the socket
	if err = os.Chmod(startupSockName, 0777); err != nil {
		err = errors.Wrap(err, "failed to set permissions on local cache socket")
		if err2 := listener.Close(); err2 != nil {
			log.Errorf("Failed to close socket listener: %v", err2)
		}
		return err
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
			ctx := context.Background()
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	})

	if err = os.Rename(startupSockName, socketName); err != nil {
		err = errors.Wrap(err, "failed to rename temporary socket to final socket name for local cache")
	}
	return
}

// Register the control & monitoring routines with Gin
func (lc *LocalCache) Register(ctx context.Context, router *gin.RouterGroup) {
	router.POST("/api/v1.0/localcache/purge", func(ginCtx *gin.Context) { lc.purgeCmd(ginCtx) })
	router.POST("/api/v1.0/localcache/purge_first", func(ginCtx *gin.Context) { lc.purgeFirstCmd(ginCtx) })
}

// Authorize the request then trigger the purge routine
func (lc *LocalCache) purgeCmd(ginCtx *gin.Context) {

	status, verified, err := token.Verify(ginCtx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
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

func (lc *LocalCache) purgeFirstCmd(ginCtx *gin.Context) {
	log.Infoln("Received request to move object to purge first heap")
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
	var req struct {
		Path string `json:"path"`
	}

	if err = ginCtx.ShouldBindJSON(&req); err != nil {
		log.Warningln("Received invalid JSON request")
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "Invalid request format"})
		return
	}

	log.Debugf("Request received to move object (path: %s)", req.Path)
	status, err = lc.MarkObjectPurgeFirst(req.Path)
	if err != nil {
		log.Warningf("Failed to move object to purge first heap (path: %s, error: %v)", req.Path, err)
		ginCtx.AbortWithStatusJSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: err.Error()})
		return
	}

	log.Infof("Successfully moved object to purge first heap (path: %s)", req.Path)
	ginCtx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK})
}
