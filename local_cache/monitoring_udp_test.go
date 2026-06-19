//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestCacheMonitoringUDPCapture is a full handler-level end-to-end test: it
// stands up a real persistent cache, serves an HTTP GET through serveObject,
// runs the real monitoring shoveler forwarding to a UDP collector, and asserts
// that the XRootD-style monitoring packets are captured off the wire.
//
// It deliberately avoids the (slow) e2e_fed_tests federation harness: the cache
// is built with DeferConfig (no director fetch) against a stub federation, and
// a public namespace is injected directly so a tokenless GET is served.
func TestCacheMonitoringUDPCapture(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	// Stub federation so NewPersistentCache resolves offline (no discovery).
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://cache.example:8443",
		DirectorEndpoint:  "https://cache.example:8443",
	})

	// UDP collector that stands in for a monitoring aggregator.
	collector, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = collector.Close() })
	collectorPort := collector.LocalAddr().(*net.UDPAddr).Port

	// Configure and launch the real shoveler, forwarding to our collector.  The
	// message queue is required by config but we only use the UDP-forwarding
	// path; the STOMP backend points at an unreachable URL and merely retries in
	// the background.
	require.NoError(t, param.Logging_Level.Set("error")) // configShoveler parses this
	require.NoError(t, param.Shoveler_Enable.Set(true))
	require.NoError(t, param.Shoveler_MessageQueueProtocol.Set("stomp"))
	require.NoError(t, param.Shoveler_URL.Set("stomp://127.0.0.1:1"))
	require.NoError(t, param.Shoveler_OutputDestinations.Set([]string{fmt.Sprintf("127.0.0.1:%d", collectorPort)}))
	// Let the shoveler's own UDP listener bind an arbitrary free port.
	require.NoError(t, param.Shoveler_PortLower.Set(0))
	require.NoError(t, param.Shoveler_PortHigher.Set(1))
	_, err = metrics.LaunchShoveler(ctx, egrp)
	require.NoError(t, err)

	// Build a real persistent cache offline.  DeferConfig skips the initial
	// director namespace fetch; everything else (db, storage, transfer engine,
	// authorizer) is wired normally.
	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	// Inject a public namespace so the tokenless GET authorizes.
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAdV2{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	// Pre-store a cached object under the instance hash that resolveObject will
	// look up for this path (latest ETag is empty since none is recorded).
	const objectPath = "/test/hello_world.txt"
	const etag = "monitoring-test-etag"
	normalized := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(normalized)
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	var diskID StorageID
	for id := range pc.storage.GetDirs() {
		diskID = id
	}
	data := bytes.Repeat([]byte("monitoring-udp-capture-test\n"), 500) // ~14 KiB, multiple blocks
	storeTestObject(t, ctx, pc.storage, instanceHash, data, diskID, NamespaceID(1))
	// Register the latest-ETag mapping so resolveObject treats this as a cache
	// hit (it only loads metadata when a latest ETag is recorded).
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))

	// Serve the cache's object handler over real HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pc.serveObject(w, r)
	}))
	t.Cleanup(srv.Close)

	// Issue the GET that should produce monitoring packets.
	resp, err := http.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET failed: %s", string(body))
	require.Equal(t, data, body, "served body should match the cached object")

	// Capture forwarded datagrams from the collector and decode the raw XRootD
	// monitoring packets out of the shoveler's JSON envelope.
	var rawPackets [][]byte
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, collector.SetReadDeadline(deadline))
	buf := make([]byte, 65536)
	sawUser, sawFStream, sawPath := false, false, false
	for {
		n, _, rerr := collector.ReadFromUDP(buf)
		if rerr != nil {
			break // deadline reached
		}
		var env struct {
			Data string `json:"data"`
		}
		if jsonErr := json.Unmarshal(buf[:n], &env); jsonErr != nil {
			continue
		}
		pkt, decErr := base64.StdEncoding.DecodeString(env.Data)
		if decErr != nil || len(pkt) == 0 {
			continue
		}
		rawPackets = append(rawPackets, pkt)
		switch pkt[0] {
		case 'u':
			sawUser = true
		case 'f':
			sawFStream = true
			if bytes.Contains(pkt, []byte(objectPath)) {
				sawPath = true
			}
		}
		if sawUser && sawFStream && sawPath {
			break
		}
		require.NoError(t, collector.SetReadDeadline(deadline))
	}

	require.NotEmpty(t, rawPackets, "expected to capture monitoring packets over UDP")
	assert.True(t, sawUser, "expected a user-login ('u') packet")
	assert.True(t, sawFStream, "expected an f-stream ('f') packet")
	assert.True(t, sawPath, "expected the object path to appear in an f-stream packet")
}
