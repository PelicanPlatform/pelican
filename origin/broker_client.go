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
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	// We have a custom transport object to force all our connections to the
	// localhost to avoid potentially going over the external network to talk
	// to our xrootd child process.
	proxyTransport *http.Transport

	onceTransport sync.Once

	// It's possible to overwhelm the XRootD listen socket with requests.  This rate
	// limiter will allow no more than 32 requests / second and 8 new ones in a burst
	xrdConnLimit *rate.Limiter = rate.NewLimiter(32, 8)
)

// Return a custom HTTP transport object; starts with the default transport for
// Pelican but forces all connections to go to the local xrootd port.
func getTransport() *http.Transport {
	onceTransport.Do(func() {
		proxyTransport = config.GetTransport().Clone()
		// When creating a new socket out to the remote server, ignore the actual
		// requested address and return a localhost socket.
		proxyTransport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			if err := xrdConnLimit.Wait(ctx); err != nil {
				err = errors.Wrap(err, "Failed to rate-limit local connection")
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", "localhost:"+strconv.Itoa(param.Origin_Port.GetInt()))
		}
	})
	return proxyTransport
}

func proxyOrigin(resp http.ResponseWriter, req *http.Request) {
	url := req.URL
	url.Scheme = "https"
	url.Host = param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Origin_Port.GetInt())

	log.Debugln("Will proxy request to URL", url.String())
	transport := getTransport()
	xrdResp, err := transport.RoundTrip(req)
	if err != nil {
		log.Infoln("Failed to talk to xrootd service:", err)
		resp.WriteHeader(http.StatusServiceUnavailable)
		if _, err := resp.Write([]byte(`Failed to connect to local xrootd instance`)); err != nil {
			log.Infoln("Failed to write response to client:", err)
		}
		return
	}
	defer xrdResp.Body.Close()

	utils.CopyHeader(resp.Header(), xrdResp.Header)
	resp.WriteHeader(xrdResp.StatusCode)
	if _, err = io.Copy(resp, xrdResp.Body); err != nil {
		log.Warningln("Failed to copy response body from Xrootd to remote cache:", err)
	}
}

// Launch goroutines that continuously poll the broker
func LaunchBrokerListener(ctx context.Context, egrp *errgroup.Group) (err error) {
	listenerChan := make(chan any)
	// Startup 5 continuous polling routines
	for cnt := 0; cnt < 5; cnt += 1 {
		err = broker.LaunchRequestMonitor(ctx, egrp, listenerChan)
		if err != nil {
			return
		}
	}
	// Start routine which receives the reverse listener and then launches
	// a simple proxying HTTPS server for that connection
	egrp.Go(func() (err error) {
		for {
			select {
			case <-ctx.Done():
				return
			case res := <-listenerChan:
				if err, ok := res.(error); ok {
					log.Errorln("Callback failed:", err)
					break
				}
				listener, ok := res.(net.Listener)
				if !ok {
					log.Errorln("Failed to determine callback result:", res)
					break
				}
				srv := http.Server{
					Handler: http.HandlerFunc(proxyOrigin),
				}
				go func() {
					// A one-shot listener should do a single "accept" then shutdown.
					err = srv.Serve(listener)
					if !errors.Is(err, net.ErrClosed) {
						log.Errorln("Failed to serve reverse connection:", err)
					}
				}()
			}
		}
	})
	return
}
