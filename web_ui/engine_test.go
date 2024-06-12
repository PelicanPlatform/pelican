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

package web_ui

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Setup a gin engine that will serve up a /ping endpoint on a Unix domain socket.
func setupPingEngine(t *testing.T, ctx context.Context, egrp *errgroup.Group) (chan bool, context.CancelFunc, string) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Logging.Level", "Debug")
	viper.Set("ConfigDir", dirname)
	viper.Set("Server.WebPort", 8444)
	viper.Set("Origin.Port", 8443)
	config.InitConfig()
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(ctx)

	engine, err := GetEngine()
	require.NoError(t, err)

	engine.GET("/ping", func(ctx *gin.Context) {
		ctx.Data(http.StatusOK, "text/plain; charset=utf-8", []byte("pong"))
	})

	// Setup a domain socket instead of listening on TCP
	socketLocation := filepath.Join(dirname, "engine.sock")
	ln, err := net.Listen("unix", socketLocation)
	require.NoError(t, err)

	doneChan := make(chan bool)
	egrp.Go(func() error {
		err = runEngineWithListener(ctx, ln, engine, egrp)
		require.NoError(t, err)
		doneChan <- true
		return err
	})

	transport := *config.GetTransport()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", socketLocation)
	}
	httpc := http.Client{
		Transport: &transport,
	}

	engineReady := false
	for idx := 0; idx < 20; idx++ {
		time.Sleep(10 * time.Millisecond)
		log.Debug("Checking for engine ready")

		var resp *http.Response
		resp, err = httpc.Get("https://" + param.Server_Hostname.GetString() + "/ping")
		if err != nil {
			continue
		}
		assert.Equal(t, "200 OK", resp.Status)
		var body []byte
		body, err = io.ReadAll(resp.Body)
		assert.Equal(t, string(body), "pong")
	}
	if !engineReady {
		require.NoError(t, err)
	}

	return doneChan, cancel, socketLocation
}

// Test the engine startup, serving a single request using
// TLS validation, then a clean shutdown.
func TestRunEngine(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	doneChan, cancel, _ := setupPingEngine(t, ctx, egrp)

	// Shutdown the engine
	cancel()
	timeout := time.Tick(3 * time.Second)
	select {
	case ok := <-doneChan:
		require.True(t, ok)
	case <-timeout:
		require.Fail(t, "Timeout when shutting down the engine")
	}
}

// Ensure that if the TLS certificate is updated on disk then new
// connections will use the new version.
func TestUpdateCert(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	doneChan, pingCancel, socketLocation := setupPingEngine(t, ctx, egrp)
	defer pingCancel()

	getCurrentFingerprint := func() [sha256.Size]byte {

		conn, err := net.Dial("unix", socketLocation)
		require.NoError(t, err)
		defer conn.Close()

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         param.Server_WebHost.GetString(),
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		require.NoError(t, err)

		currentCert := tlsConn.ConnectionState().PeerCertificates[0]
		return sha256.Sum256(currentCert.Raw)
	}

	// First, compare the current fingerprint against that on disk
	currentFingerprint := getCurrentFingerprint()

	certFile := param.Server_TLSCertificate.GetString()
	keyFile := param.Server_TLSKey.GetString()
	getDiskFingerprint := func() [sha256.Size]byte {
		diskCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		require.NoError(t, err)
		return sha256.Sum256(diskCert.Certificate[0])
	}

	diskFingerprint := getDiskFingerprint()
	assert.Equal(t, currentFingerprint, diskFingerprint)

	// Next, trigger a reload of the cert
	require.NoError(t, os.Remove(certFile))
	require.NoError(t, os.Remove(keyFile))
	require.NoError(t, config.InitServer(ctx, config.OriginType))

	newDiskFingerprint := getDiskFingerprint()
	assert.NotEqual(t, diskFingerprint, newDiskFingerprint)

	log.Debugln("Will look for updated TLS certificate")
	sawUpdate := false
	for idx := 0; idx < 10; idx++ {
		time.Sleep(50 * time.Millisecond)
		log.Debugln("Checking current fingerprint")
		currentFingerprint := getCurrentFingerprint()
		if currentFingerprint == newDiskFingerprint {
			sawUpdate = true
			break
		} else {
			require.Equal(t, currentFingerprint, diskFingerprint)
		}
	}
	assert.True(t, sawUpdate)

	cancel()
	timeout := time.Tick(3 * time.Second)
	select {
	case ok := <-doneChan:
		require.True(t, ok)
	case <-timeout:
		require.Fail(t, "Timeout when shutting down the engine")
	}
}
