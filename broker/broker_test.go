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

package broker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type (
	ConnLogger struct {
		net.Conn
	}
)

// Return a transport that always dials the given connection
func getTransport(conn net.Conn) (tr *http.Transport) {
	tr = config.GetTransport().Clone()
	tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return &ConnLogger{conn}, nil
	}
	return
}

// Returns a HTTP HandlerFunc that always returns the plaintext "Hello world"
func getHelloWorldHandler(t *testing.T) func(resp http.ResponseWriter, req *http.Request) {
	return func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		_, err := resp.Write([]byte("Hello world"))
		assert.NoError(t, err)
	}
}

func TestBroker(t *testing.T) {
	dirpath := t.TempDir()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()
	viper.Set("Server.WebPort", "0")
	viper.Set("Registry.DbLocation", filepath.Join(dirpath, "ns-registry.sqlite"))
	viper.Set("Origin.NamespacePrefix", "/foo")

	err := config.InitServer(ctx, config.BrokerType)
	require.NoError(t, err)

	err = registry.InitializeDB(ctx)
	require.NoError(t, err)

	keyset, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	keysetBytes, err := json.Marshal(keyset)
	require.NoError(t, err)

	err = registry.AddNamespace(&registry.Namespace{
		ID:       1,
		Prefix:   "/caches/" + param.Server_Hostname.GetString(),
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
	})
	require.NoError(t, err)
	err = registry.AddNamespace(&registry.Namespace{
		ID:       2,
		Prefix:   "/foo",
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
	})
	require.NoError(t, err)

	// Setup the broker APIs
	engine, err := web_ui.GetEngine()
	require.NoError(t, err)
	rootGroup := engine.Group("/")
	RegisterBroker(ctx, rootGroup)
	RegisterBrokerCallback(ctx, rootGroup)
	registry.RegisterRegistryAPI(rootGroup)
	// Register routes for APIs to registry Web UI
	err = registry.RegisterRegistryWebAPI(rootGroup)
	require.NoError(t, err)

	egrp.Go(func() error {
		<-ctx.Done()
		return registry.ShutdownDB()
	})

	// Run the web engine, wait for it to be online.
	err = web_ui.RunEngineRoutine(ctx, engine, egrp, false)
	require.NoError(t, err)
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/", "Web UI", http.StatusNotFound)
	require.NoError(t, err)

	// Create a HTTP server we'll use to serve up the reversed connection
	srv := http.Server{
		Handler: http.HandlerFunc(getHelloWorldHandler(t)),
	}

	// Launch the origin-side monitoring of requests.
	viper.Set("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString())
	viper.Set("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString())
	listenerChan := make(chan any)
	ctxQuick, deadlineCancel := context.WithTimeout(ctx, 5*time.Second) // Have shorter timeout for this handshake
	err = LaunchRequestMonitor(ctxQuick, egrp, listenerChan)
	require.NoError(t, err)

	// Initiate the callback using the cache-based routines.
	brokerUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)

	brokerUrl.Path = "/api/v1.0/broker/reverse"
	query := brokerUrl.Query()
	query.Set("origin", param.Server_Hostname.GetString())
	query.Set("prefix", "/foo")
	brokerUrl.RawQuery = query.Encode()
	clientConn, err := ConnectToOrigin(ctxQuick, brokerUrl.String(), "/foo", param.Server_Hostname.GetString())
	require.NoError(t, err)
	log.Debugf("Cache got reversed client connection with cache side %s and origin side %s", clientConn.LocalAddr(), clientConn.RemoteAddr())

	// Wait on the origin channel until a connection is made.
	var listener net.Listener
	select {
	case res := <-listenerChan:
		if err, ok := res.(error); ok {
			require.NoError(t, err)
		} else if listener, ok = res.(net.Listener); ok {
			log.Debugln("Origin got reversed listener socket listening at local", listener.Addr())
			break
		} else {
			require.Fail(t, "Unable to interpret listener result")
		}
		break
	case <-ctx.Done():
		t.Error("Timeout when waiting on callback")
		deadlineCancel()
		return
	}
	deadlineCancel()

	// Launch the simple HTTP server on the reversed connection
	errChan := make(chan error)

	go func() {
		log.Debug("Starting reversed server for connection")
		err = srv.Serve(listener)
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		errChan <- err
	}()

	egrp.Go(func() (err error) {
		select {
		case <-ctx.Done():
			listener.Close()
		case err = <-errChan:
			break
		}
		return
	})

	// Make a simple HTTP request against our server
	tr := getTransport(clientConn)
	client := http.Client{Transport: tr}
	url := param.Server_ExternalWebUrl.GetString()
	//url := "http://" + clientConn.RemoteAddr().String()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello world", string(respBody))
	log.Debugln("Finished HTTPS client call to the origin server")
}
