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

package xrootd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestProbeXrootdEndpointResponsive verifies a peer that completes a TLS handshake is
// considered alive.
func TestProbeXrootdEndpointResponsive(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	require.NoError(t, probeXrootdEndpoint(context.Background(), srv.Listener.Addr().String(), 10*time.Second))
}

// TestProbeXrootdEndpointNoListener verifies a refused connection is a failure.
func TestProbeXrootdEndpointNoListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	err = probeXrootdEndpoint(context.Background(), addr, 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to the XRootD endpoint")
}

// TestProbeXrootdEndpointBacklogOnly is the case this check exists for: the process is
// wedged (as a SIGSTOPped XRootD would be), so the kernel still completes the TCP handshake
// out of the listen backlog but nothing ever answers.  A bare TCP connect would call this
// healthy; the probe must not.
func TestProbeXrootdEndpointBacklogOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Deliberately never call Accept.
	t.Cleanup(func() { _ = listener.Close() })

	err = probeXrootdEndpoint(context.Background(), listener.Addr().String(), 250*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not respond within")
}

// TestProbeXrootdEndpointRespondsWithoutTLS verifies that a peer which answers with
// something other than a usable TLS handshake still counts as alive; the check only asks
// whether XRootD is processing connections.
func TestProbeXrootdEndpointRespondsWithoutTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("not TLS\n"))
			_ = conn.Close()
		}
	}()

	require.NoError(t, probeXrootdEndpoint(context.Background(), listener.Addr().String(), 10*time.Second))
}

func TestProbeXrootdEndpointHonorsCancelledContext(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, probeXrootdEndpoint(ctx, srv.Listener.Addr().String(), 10*time.Second))
}

// TestProbeXrootdEndpointCancelledMidHandshake verifies that a shutdown partway through a
// probe is not mistaken for evidence that XRootD is alive.
func TestProbeXrootdEndpointCancelledMidHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		// Hold the connection open without ever answering the ClientHello.
		<-time.After(30 * time.Second)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	probeErr := make(chan error, 1)
	go func() {
		probeErr <- probeXrootdEndpoint(ctx, listener.Addr().String(), 30*time.Second)
	}()

	<-accepted
	cancel()

	select {
	case err := <-probeErr:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "interrupted")
	case <-time.After(30 * time.Second):
		t.Fatal("probe did not return after its context was cancelled")
	}
}

func TestXrootdLivenessAddress(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Origin_Port.Set(1234))
	require.NoError(t, param.Cache_Port.Set(5678))

	addr, err := xrootdLivenessAddress(false)
	require.NoError(t, err)
	assert.Equal(t, net.JoinHostPort("localhost", strconv.Itoa(1234)), addr)

	addr, err = xrootdLivenessAddress(true)
	require.NoError(t, err)
	assert.Equal(t, net.JoinHostPort("localhost", strconv.Itoa(5678)), addr)

	require.NoError(t, param.Cache_Port.Set(0))
	_, err = xrootdLivenessAddress(true)
	require.Error(t, err)
}

func TestTrackedPIDsForRole(t *testing.T) {
	restartInfos = nil
	t.Cleanup(func() { restartInfos = nil })

	launch := func(ls []daemon.Launcher) ([]int, error) { return nil, nil }
	StoreRestartInfo([]int{11, 12}, launch, nil, true, false, false)
	StoreRestartInfo([]int{21}, launch, nil, false, false, false)

	assert.Equal(t, []int{11, 12}, trackedPIDsForRole(true))
	assert.Equal(t, []int{21}, trackedPIDsForRole(false))
}

// livenessHarness drives runXrootdLivenessCheck without a real XRootD on the other end.
type livenessHarness struct {
	shutdowns        atomic.Int32
	probes           atomic.Int32
	probesAtShutdown atomic.Int32
	probeFails       atomic.Bool
	// probeDelay, in nanoseconds, is how long a stub probe pretends to take.
	probeDelay atomic.Int64
}

// newLivenessHarness configures the liveness knobs for a fast, deterministic loop and
// installs stub probe/shutdown implementations.
func newLivenessHarness(t *testing.T, maxUnresponsive time.Duration) *livenessHarness {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Origin_Port.Set(1))
	require.NoError(t, param.Xrootd_LivenessCheckInterval.Set(time.Millisecond))
	require.NoError(t, param.Xrootd_LivenessCheckTimeout.Set(time.Second))
	require.NoError(t, param.Xrootd_LivenessMaxUnresponsiveTime.Set(maxUnresponsive))

	h := &livenessHarness{}
	shutdownXrootdFn = func(isCache bool) {
		h.probesAtShutdown.Store(h.probes.Load())
		h.shutdowns.Add(1)
	}
	probeXrootdFn = func(ctx context.Context, addr string, timeout time.Duration) error {
		h.probes.Add(1)
		if delay := time.Duration(h.probeDelay.Load()); delay > 0 {
			// A real probe blocks until it answers or its context ends.
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if h.probeFails.Load() {
			return errors.New("simulated unresponsive XRootD")
		}
		return nil
	}
	t.Cleanup(func() {
		shutdownXrootdFn = shutdownHungXrootd
		probeXrootdFn = probeXrootdEndpoint
	})
	return h
}

func (h *livenessHarness) run(t *testing.T) (context.CancelFunc, chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runXrootdLivenessCheck(ctx, false)
	}()
	return cancel, done
}

func (h *livenessHarness) noShutdown() func() bool {
	return func() bool { return h.shutdowns.Load() > 0 }
}

// TestNextCheckDelay pins down the pacing rule: the interval is a floor on the spacing
// between checks, not a delay bolted onto every one of them.
func TestNextCheckDelay(t *testing.T) {
	interval := time.Minute

	t.Run("success waits the whole interval", func(t *testing.T) {
		assert.Equal(t, interval, nextCheckDelay(interval, time.Second, true))
		// Even a slow success is allowed to pace itself further out.
		assert.Equal(t, interval, nextCheckDelay(interval, 5*time.Minute, true))
	})

	t.Run("quick failure waits out the remainder", func(t *testing.T) {
		assert.Equal(t, 40*time.Second, nextCheckDelay(interval, 20*time.Second, false))
	})

	t.Run("failure longer than the interval retries immediately", func(t *testing.T) {
		assert.Equal(t, time.Duration(0), nextCheckDelay(interval, interval, false))
		assert.Equal(t, time.Duration(0), nextCheckDelay(interval, 3*time.Minute, false))
	})
}

// TestLivenessCheckRetriesFailuresWithinTheWindow guards the property that makes a single
// unlucky probe insufficient on its own: a failed check is retried as soon as the interval
// allows, so several of them fit inside the unresponsive window before a shutdown fires.
// With the shipped defaults (1m interval, 3m timeout, 10m window) that works out to three
// failures.  The timings here are scaled down, and the probe deliberately runs longer than
// the interval so the immediate-retry path is the one under test.
func TestLivenessCheckRetriesFailuresWithinTheWindow(t *testing.T) {
	h := newLivenessHarness(t, 150*time.Millisecond)
	require.NoError(t, param.Xrootd_LivenessCheckInterval.Set(20*time.Millisecond))
	h.probeDelay.Store(int64(30 * time.Millisecond))
	h.probeFails.Store(true)

	cancel, done := h.run(t)
	t.Cleanup(cancel)

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("liveness check did not shut XRootD down")
	}
	assert.GreaterOrEqual(t, h.probesAtShutdown.Load(), int32(3),
		"XRootD was shut down without retrying the failed check inside the unresponsive window")
}

// TestLivenessCheckShutsDownUnresponsiveXrootd verifies a sustained probe failure ends in a
// shutdown, and not before the permitted unresponsive window has elapsed.
func TestLivenessCheckShutsDownUnresponsiveXrootd(t *testing.T) {
	const maxUnresponsive = 150 * time.Millisecond
	h := newLivenessHarness(t, maxUnresponsive)
	h.probeFails.Store(true)

	start := time.Now()
	cancel, done := h.run(t)
	t.Cleanup(cancel)

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("liveness check did not shut XRootD down")
	}
	assert.GreaterOrEqual(t, time.Since(start), maxUnresponsive)
	assert.Equal(t, int32(1), h.shutdowns.Load())
}

// TestLivenessCheckToleratesResponsiveXrootd verifies a healthy XRootD is never shut down.
func TestLivenessCheckToleratesResponsiveXrootd(t *testing.T) {
	h := newLivenessHarness(t, 10*time.Millisecond)

	cancel, done := h.run(t)
	assert.Never(t, h.noShutdown(), 200*time.Millisecond, 10*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("liveness check did not exit when its context was cancelled")
	}
}

// TestLivenessCheckRecoveryResetsClock verifies that a single successful probe clears both
// the accumulated unresponsive time and the consecutive-failure count.
func TestLivenessCheckRecoveryResetsClock(t *testing.T) {
	h := newLivenessHarness(t, 100*time.Millisecond)
	h.probeFails.Store(true)

	cancel, done := h.run(t)

	// Let the failures accumulate for a while, then recover before the limit would
	// have been reached had the clock kept running.
	assert.Never(t, h.noShutdown(), 50*time.Millisecond, 5*time.Millisecond)
	h.probeFails.Store(false)
	assert.Never(t, h.noShutdown(), 200*time.Millisecond, 10*time.Millisecond)

	cancel()
	<-done
}

// TestLivenessCheckIgnoresExpectedRestart verifies the monitor holds its fire while a
// deliberate XRootD restart is in flight.
func TestLivenessCheckIgnoresExpectedRestart(t *testing.T) {
	h := newLivenessHarness(t, 50*time.Millisecond)
	h.probeFails.Store(true)
	daemon.SetExpectedRestart(true)
	t.Cleanup(func() { daemon.SetExpectedRestart(false) })

	cancel, done := h.run(t)
	assert.Never(t, h.noShutdown(), 250*time.Millisecond, 10*time.Millisecond)

	cancel()
	<-done
}

// TestLivenessCheckSkipsWithoutPort verifies that a server whose XRootD port is unknown is
// never killed on the strength of our own confusion.
func TestLivenessCheckSkipsWithoutPort(t *testing.T) {
	h := newLivenessHarness(t, 50*time.Millisecond)
	h.probeFails.Store(true)
	require.NoError(t, param.Origin_Port.Set(0))

	cancel, done := h.run(t)
	assert.Never(t, h.noShutdown(), 250*time.Millisecond, 10*time.Millisecond)

	cancel()
	<-done
}

// TestLaunchXrootdLivenessCheckDisabled verifies the hidden kill switch restores the
// historical, purely-passive behavior.
func TestLaunchXrootdLivenessCheckDisabled(t *testing.T) {
	h := newLivenessHarness(t, time.Millisecond)
	h.probeFails.Store(true)
	require.NoError(t, param.Xrootd_DisableLivenessCheck.Set(true))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, egrpCtx := errgroup.WithContext(ctx)
	LaunchXrootdLivenessCheck(egrpCtx, egrp, false)

	assert.Never(t, h.noShutdown(), 100*time.Millisecond, 10*time.Millisecond)
	cancel()
	require.NoError(t, egrp.Wait())
}
