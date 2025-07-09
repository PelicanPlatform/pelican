/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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

	PelicanBrokerConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_broker_connections_total",
		Help: "The number of connections made to the service via a connection broker.",
	}, []string{"server_type"})

	PelicanBrokerApiRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_broker_api_requests_total",
		Help: "The number of API requests made to the service via a connection broker.",
	}, []string{"server_type"})

	PelicanBrokerObjectRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_broker_object_requests_total",
		Help: "The number of object requests made to the service via a connection broker.",
	})
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

func proxyOrigin(resp http.ResponseWriter, req *http.Request, engine *gin.Engine) {
	if strings.HasPrefix(req.URL.Path, "/api") {
		PelicanBrokerApiRequests.WithLabelValues("origin").Inc()
		engine.ServeHTTP(resp, req)
		return
	}
	PelicanBrokerObjectRequests.Inc()
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
func LaunchBrokerListener(ctx context.Context, egrp *errgroup.Group, engine *gin.Engine) (err error) {
	listenerChan := make(chan any)
	externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return
	}
	originUrl, err := url.Parse(param.Origin_Url.GetString())
	if err != nil {
		return
	}

	// Startup 5 continuous polling routines
	for cnt := 0; cnt < 5; cnt += 1 {
		err = broker.LaunchRequestMonitor(ctx, egrp, server_structs.OriginType, externalWebUrl.Host, listenerChan)
		if err != nil {
			return
		}
		err = broker.LaunchRequestMonitor(ctx, egrp, server_structs.OriginType, originUrl.Host, listenerChan)
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
				return nil
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
					Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { proxyOrigin(resp, req, engine) }),
				}
				PelicanBrokerConnections.WithLabelValues("origin").Inc()
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
