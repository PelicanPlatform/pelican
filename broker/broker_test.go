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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
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

// setupTestEngine creates a gin engine for testing, similar to web_ui.GetEngine()
func setupTestEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	return engine
}

// runTestEngine starts an HTTPS server with the given gin engine for testing
// Note: This uses HTTPS (not HTTP) to match production behavior and the broker's
// reversed connection mechanism which always uses TLS
func runTestEngine(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	config.UpdateConfigFromListener(ln)

	certFile := param.Server_TLSCertificateChain.GetString()
	keyFile := param.Server_TLSKey.GetString()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   engine,
		TLSConfig: tlsConfig,
	}

	egrp.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	})

	egrp.Go(func() error {
		defer ln.Close()
		if err := server.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	return nil
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

	server_utils.ResetTestState()
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	require.NoError(t, param.Set("ConfigDir", filepath.Join(dirpath, "config")))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), "0"))
	require.NoError(t, param.Set(param.Server_DbLocation.GetName(), filepath.Join(dirpath, "ns-registry.sqlite")))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/foo"))

	test_utils.MockFederationRoot(t, nil, nil)

	err := config.InitServer(ctx, server_structs.BrokerType)
	require.NoError(t, err)

	err = database.InitServerDatabase(server_structs.RegistryType)
	require.NoError(t, err)

	keyset, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	keysetBytes, err := json.Marshal(keyset)
	require.NoError(t, err)

	err = registry.AddRegistration(&server_structs.Registration{
		ID:       1,
		Prefix:   "/caches/" + param.Server_Hostname.GetString(),
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
		AdminMetadata: server_structs.AdminMetadata{
			SiteName: "Test-Site-Name",
		},
	})
	require.NoError(t, err)
	err = registry.AddRegistration(&server_structs.Registration{
		ID:       2,
		Prefix:   "/foo",
		Pubkey:   string(keysetBytes),
		Identity: "test_data",
		AdminMetadata: server_structs.AdminMetadata{
			SiteName: "Test-Site-Name",
		},
	})
	require.NoError(t, err)

	namespaceKeys = nil
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	Setup(t, ctx, egrp)

	// Setup the broker APIs
	engine := setupTestEngine()
	rootGroup := engine.Group("/")
	RegisterBroker(ctx, rootGroup)
	RegisterBrokerCallback(ctx, rootGroup)
	registry.RegisterRegistryAPI(rootGroup)
	// Register routes for APIs to registry Web UI
	err := registry.RegisterRegistryWebAPI(rootGroup)
	require.NoError(t, err)

	egrp.Go(func() error {
		<-ctx.Done()
		return database.ShutdownDB()
	})

	// Run the web engine, wait for it to be online.
	err = runTestEngine(ctx, engine, egrp)
	require.NoError(t, err)
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/", "Web UI", http.StatusNotFound, false)
	require.NoError(t, err)

	// Create an HTTPS server we'll use to serve up the reversed connection
	// The reversed connection uses TLS by design
	srv := http.Server{
		Handler: http.HandlerFunc(getHelloWorldHandler(t)),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{},
			// Load the server certificate
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(
					param.Server_TLSCertificateChain.GetString(),
					param.Server_TLSKey.GetString(),
				)
				return &cert, err
			},
		},
	}

	// Launch the origin-side monitoring of requests.
	require.NoError(t, param.Set("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString()))
	require.NoError(t, param.Set("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString()))
	listenerChan := make(chan any)
	ctxQuick, deadlineCancel := context.WithTimeout(ctx, 5*time.Second) // Have shorter timeout for this handshake
	defer deadlineCancel()

	externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)

	err = LaunchRequestMonitor(ctxQuick, egrp, server_structs.CacheType, externalWebUrl.Hostname(), "", listenerChan)
	require.NoError(t, err)

	// Initiate the callback using the cache-based routines.
	brokerUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)

	brokerUrl.Path = "/api/v1.0/broker/reverse"
	query := brokerUrl.Query()
	query.Set("origin", param.Server_Hostname.GetString())
	query.Set("prefix", "/caches/"+externalWebUrl.Hostname())
	brokerUrl.RawQuery = query.Encode()
	clientConn, err := ConnectToService(ctxQuick, brokerUrl.String(), "/caches/"+externalWebUrl.Hostname(), param.Server_Hostname.GetString())
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
		// Use ServeTLS since the server has TLS config
		err := srv.ServeTLS(listener, "", "")
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

	// Wrap the client connection in TLS to match the origin's TLS listener
	// The broker's reversed connection mechanism always uses TLS
	tlsConfig := config.GetTransport().TLSClientConfig
	tlsConn := tls.Client(clientConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	require.NoError(t, err)

	// Make a simple HTTPS request against the reversed connection server
	tr := getTransport(tlsConn)
	client := http.Client{Transport: tr}
	url := "https://" + clientConn.RemoteAddr().String()
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	Setup(t, ctx, egrp)

	// Setup the broker APIs
	engine := setupTestEngine()
	rootGroup := engine.Group("/")
	RegisterBroker(ctx, rootGroup)
	registry.RegisterRegistryAPI(rootGroup)

	egrp.Go(func() error {
		<-ctx.Done()
		return database.ShutdownDB()
	})

	// Run the web engine, wait for it to be online.
	err := runTestEngine(ctx, engine, egrp)
	require.NoError(t, err)
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/", "Web UI", http.StatusNotFound, false)
	require.NoError(t, err)

	require.NoError(t, param.Set("Federation.BrokerUrl", param.Server_ExternalWebUrl.GetString()))
	require.NoError(t, param.Set("Federation.RegistryUrl", param.Server_ExternalWebUrl.GetString()))

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
