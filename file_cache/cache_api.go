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

package simple_cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// Launch the unix socket listener as a separate goroutine
func LaunchListener(ctx context.Context, egrp *errgroup.Group) error {
	socketName := param.FileCache_DataLocation.GetString()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketName, Net: "unix"})
	if err != nil {
		return err
	}
	sc, err := NewSimpleCache(ctx, egrp)
	if err != nil {
		return err
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		transferStatusStr := r.Header.Get("X-Transfer-Status")
		sendTrailer := false
		if transferStatusStr == "true" {
			for _, encoding := range r.Header.Values("TE") {
				if encoding == "trailers" {
					sendTrailer = true
					break
				}
			}
		}

		authzHeader := r.Header.Get("Authorization")
		bearerToken := ""
		if strings.HasPrefix(bearerToken, "Bearer ") {
			bearerToken = authzHeader[7:] // len("Bearer ") == 7
		}
		reader, err := sc.Get(r.URL.Path, bearerToken)
		if errors.Is(err, authorizationDenied) {
			w.WriteHeader(http.StatusForbidden)
			if _, err = w.Write([]byte("Authorization Denied")); err != nil {
				log.Errorln("Failed to write authorization denied to client")
			}
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err = w.Write([]byte("Unexpected internal error")); err != nil {
				log.Errorln("Failed to write internal error message to client")
			}
			log.Errorln("Failed to get file from cache:", err)
			return
		}
		w.WriteHeader(http.StatusOK)
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
		return srv.Shutdown(ctx)
	})
	return nil
}
