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

package bgp_advertise

import (
	"context"
	"net"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// candidateFreePort asks the OS for an ephemeral port and immediately releases
// it.  On its own this is racy (the port may be taken before it is reused), so
// callers must treat the returned port as a *candidate* and handle bind failure
// -- see startPeerRouter, which retries on a fresh candidate until GoBGP's own
// listener actually binds.  GoBGP creates its own listener and exposes neither a
// way to inject one nor the port it bound when asked to use an ephemeral port,
// so bind-with-retry is the robust way to give it a free port.
func candidateFreePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

// startPeerRouter starts a second, in-process GoBGP instance that acts as the
// BGP peer (router) receiving our advertisements.  It binds an OS-chosen free
// port on 127.0.0.1, retrying on a fresh candidate if the port is taken between
// selection and bind (so there is no reliance on a reserved port staying free),
// and returns the server together with the port it actually bound.  It expects a
// neighbor connecting from 127.0.0.1 with the given ASN.
func startPeerRouter(t *testing.T, localASN, neighborASN uint32) (*server.BgpServer, uint32) {
	t.Helper()
	s := server.NewBgpServer()
	go s.Serve()
	ctx := context.Background()

	const maxAttempts = 25
	var boundPort uint32
	for attempt := 0; attempt < maxAttempts; attempt++ {
		port := candidateFreePort(t)
		// StartBgp creates the TCP listener synchronously and returns the bind
		// error if the port was taken in the race window; on failure it returns
		// before mutating server state, so we can simply retry on a new port.
		err := s.StartBgp(ctx, &api.StartBgpRequest{
			Global: &api.Global{
				Asn:             localASN,
				RouterId:        "10.255.0.2",
				ListenPort:      int32(port),
				ListenAddresses: []string{"127.0.0.1"},
			},
		})
		if err == nil {
			boundPort = port
			break
		}
		t.Logf("peer StartBgp on candidate port %d failed (%v); retrying with a new port", port, err)
	}
	require.NotZero(t, boundPort, "failed to bind a BGP listen port after %d attempts", maxAttempts)

	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: "127.0.0.1",
				PeerAsn:         neighborASN,
			},
			Transport: &api.Transport{
				// Accept the inbound connection from the advertiser; do not
				// actively dial it back (it has no listener).
				PassiveMode: true,
			},
		},
	}))

	t.Cleanup(func() {
		_ = s.StopBgp(ctx, &api.StopBgpRequest{})
		s.Stop()
	})
	return s, boundPort
}

// peerHasRoute reports whether the peer's global RIB currently contains prefix.
func peerHasRoute(t *testing.T, peer *server.BgpServer, prefix string) bool {
	t.Helper()
	found := false
	err := peer.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
	}, func(d *api.Destination) {
		if d.Prefix == prefix {
			found = true
		}
	})
	require.NoError(t, err)
	return found
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return cond()
}

// TestAdvertiseAndWithdraw spins up a peer router and our advertiser, establishes
// the BGP session, and verifies that advertised routes appear in the peer's RIB
// and disappear when withdrawn.
func TestAdvertiseAndWithdraw(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in short mode")
	}

	const (
		advertiserASN = uint32(65001)
		peerASN       = uint32(65002)
		route         = "192.0.2.0/24"
	)
	peer, peerPort := startPeerRouter(t, peerASN, advertiserASN)

	adv, err := New(Config{
		RouterID:     "10.255.0.1",
		LocalASN:     advertiserASN,
		PeerAddress:  "127.0.0.1",
		PeerASN:      peerASN,
		LocalAddress: "127.0.0.1",
		Port:         peerPort,
		NextHop:      "127.0.0.1",
		Routes:       []string{route},
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, adv.Start(ctx))
	t.Cleanup(func() { _ = adv.Close() })

	require.NoError(t, adv.Advertise(ctx))
	assert.True(t, adv.IsAdvertising())

	// The peer should learn the route once the session establishes.
	require.True(t, waitFor(30*time.Second, func() bool {
		return peerHasRoute(t, peer, route)
	}), "peer did not receive advertised route %s", route)

	// Withdrawing should remove it from the peer's RIB.
	require.NoError(t, adv.Withdraw(ctx))
	assert.False(t, adv.IsAdvertising())
	require.True(t, waitFor(30*time.Second, func() bool {
		return !peerHasRoute(t, peer, route)
	}), "peer still has route %s after withdrawal", route)
}

// TestAdvertiseIdempotent verifies repeated Advertise/Withdraw calls are safe.
func TestAdvertiseIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in short mode")
	}
	_, peerPort := startPeerRouter(t, 65002, 65001)

	adv, err := New(Config{
		RouterID:     "10.255.0.1",
		LocalASN:     65001,
		PeerAddress:  "127.0.0.1",
		PeerASN:      65002,
		LocalAddress: "127.0.0.1",
		Port:         peerPort,
		NextHop:      "127.0.0.1",
		Routes:       []string{"192.0.2.0/24", "198.51.100.0/24"},
	})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, adv.Start(ctx))
	t.Cleanup(func() { _ = adv.Close() })

	require.NoError(t, adv.Advertise(ctx))
	require.NoError(t, adv.Advertise(ctx)) // second call is a no-op
	assert.True(t, adv.IsAdvertising())

	require.NoError(t, adv.Withdraw(ctx))
	require.NoError(t, adv.Withdraw(ctx)) // second call is a no-op
	assert.False(t, adv.IsAdvertising())
}

func TestStartRequiredBeforeAdvertise(t *testing.T) {
	adv, err := New(Config{
		RouterID:    "10.255.0.1",
		LocalASN:    65001,
		PeerAddress: "127.0.0.1",
		PeerASN:     65002,
		NextHop:     "127.0.0.1",
		Routes:      []string{"192.0.2.0/24"},
	})
	require.NoError(t, err)
	// Advertise before Start should error.
	assert.Error(t, adv.Advertise(context.Background()))
}
