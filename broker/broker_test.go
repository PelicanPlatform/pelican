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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
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

func Setup(t *testing.T, ctx context.Context, egrp *errgroup.Group) {
	dirpath := t.TempDir()

	viper.Reset()
	viper.Set("Logging.Level", "Debug")
	viper.Set("ConfigDir", filepath.Join(dirpath, "config"))
	config.InitConfig()
	viper.Set("Server.WebPort", "0")
	viper.Set("Registry.DbLocation", filepath.Join(dirpath, "ns-registry.sqlite"))
	viper.Set("Origin.FederationPrefix", "/foo")

	err := config.InitServer(ctx, config.BrokerType)
	require.NoError(t, err)

	err = registry.InitializeDB()
	require.NoError(t, err)

	keyset, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	keysetBytes, err := json.Marshal(keyset)
	require.NoError(t, err)

	err = registry.AddNamespace(&server_structs.Namespace{
		ID:       1,
		Prefix:   "/caches/" + param.Server_Hostname.GetString(),
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
	})
	require.NoError(t, err)
	err = registry.AddNamespace(&server_structs.Namespace{
		ID:       2,
		Prefix:   "/foo",
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
	})
	require.NoError(t, err)

	LaunchNamespaceKeyMaintenance(ctx, egrp)
}

// Perform a single retrieve request, return (but don't parse)
// result
func doRetrieveRequest(t *testing.T, ctx context.Context, dur time.Duration) (*http.Response, error) {
	brokerEndpoint := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/broker/retrieve"
	originUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)

	oReq := originRequest{
		Origin: originUrl.Hostname(),
		Prefix: param.Origin_FederationPrefix.GetString(),
	}
	reqBytes, err := json.Marshal(&oReq)
	require.NoError(t, err)

	reqReader := bytes.NewReader(reqBytes)

	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err)
	brokerAud, err := url.Parse(fedInfo.BrokerEndpoint)
	require.NoError(t, err)
	brokerAud.Path = ""

	token, err := createToken(param.Origin_FederationPrefix.GetString(), param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Retrieve)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", brokerEndpoint, reqReader)
	require.NoError(t, err)

	req.Header.Set("X-Pelican-Timeout", dur.String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

	req.Header.Set("Authorization", "Bearer "+token)

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	return client.Do(req)
}

// End-to-end test of the broker doing a TCP reversal
func TestBroker(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	Setup(t, ctx, egrp)

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
		return registry.ShutdownRegistryDB()
	})

	// Run the web engine, wait for it to be online.
	err = web_ui.RunEngineRoutine(ctx, engine, egrp, false)
	require.NoError(t, err)
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/", "Web UI", http.StatusNotFound, false)
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

// Ensure the retrieve handler times out
func TestRetrieveTimeout(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	Setup(t, ctx, egrp)

	// Setup the broker APIs
	engine, err := web_ui.GetEngine()
	require.NoError(t, err)
	rootGroup := engine.Group("/")
	RegisterBroker(ctx, rootGroup)
	registry.RegisterRegistryAPI(rootGroup)

	egrp.Go(func() error {
		<-ctx.Done()
		return registry.ShutdownRegistryDB()
	})

	// Run the web engine, wait for it to be online.
	err = web_ui.RunEngineRoutine(ctx, engine, egrp, false)
	require.NoError(t, err)
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/", "Web UI", http.StatusNotFound, false)
	require.NoError(t, err)

	viper.Set("Federation.BrokerUrl", param.Server_ExternalWebUrl.GetString())
	viper.Set("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString())

	resp, err := doRetrieveRequest(t, ctx, time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	brokerResp := &brokerRetrievalResp{}
	err = json.Unmarshal(responseBytes, &brokerResp)
	require.NoError(t, err)

	assert.Equal(t, server_structs.RespPollTimeout, brokerResp.Status)

	ctx, cancelFunc := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelFunc()
	_, err = doRetrieveRequest(t, ctx, 10*time.Second)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}
