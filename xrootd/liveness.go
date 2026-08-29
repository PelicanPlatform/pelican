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
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

// Test seams for the liveness monitor; overriding these lets the loop be
// exercised without a real XRootD process on the other end.
var (
	probeXrootdFn       = probeXrootdEndpoint
	shutdownXrootdFn    = shutdownHungXrootd
	livenessTLSConfigFn = livenessTLSConfig
)

// LaunchXrootdLivenessCheck starts a goroutine that periodically verifies the locally-launched
// XRootD daemon still answers new connections.  When XRootD has not answered for
// Xrootd.LivenessMaxUnresponsiveTime, the daemon is shut down (SIGTERM, then SIGKILL) so that
// the service manager can replace it; Pelican's usual handling of an unexpected XRootD exit
// then takes the rest of the server down with it.
//
// Only call this for servers that actually launched an XRootD daemon.
func LaunchXrootdLivenessCheck(ctx context.Context, egrp *errgroup.Group, isCache bool) {
	if param.Xrootd_DisableLivenessCheck.GetBool() {
		log.Debugf("XRootD liveness checking is disabled by %s; a hung XRootD will only be reported via the health endpoint",
			param.Xrootd_DisableLivenessCheck.GetName())
		return
	}
	egrp.Go(func() error {
		runXrootdLivenessCheck(ctx, isCache)
		return nil
	})
}

// nextCheckDelay returns how long to wait before the next liveness check, given how long the
// check that just finished took.
//
// The interval is a minimum spacing rather than an added delay: after a failure only the
// remainder of the interval is waited out, so a check that already outran the interval is
// retried immediately instead of stretching the time XRootD spends wedged.  A successful
// check is free to pace itself further out, so it simply waits the whole interval.
func nextCheckDelay(interval, checkDuration time.Duration, succeeded bool) time.Duration {
	if succeeded {
		return interval
	}
	if remaining := interval - checkDuration; remaining > 0 {
		return remaining
	}
	return 0
}

// runXrootdLivenessCheck is the body of the liveness monitor.  It returns when the context is
// cancelled or once it has shut a hung XRootD down.
func runXrootdLivenessCheck(ctx context.Context, isCache bool) {
	// XRootD was just launched; give it until the first failure window before holding
	// it responsible for anything.
	lastSuccess := time.Now()
	consecutiveFailures := 0
	delay := param.Xrootd_LivenessCheckInterval.GetDuration()

	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		interval := param.Xrootd_LivenessCheckInterval.GetDuration()

		// A deliberate restart stops and relaunches XRootD; the gap in service is
		// expected, so it must not count against the daemon.
		if daemon.IsExpectedRestart() {
			lastSuccess = time.Now()
			consecutiveFailures = 0
			delay = interval
			continue
		}

		addr, err := xrootdLivenessAddress(isCache)
		if err != nil {
			// We don't know where to look. That is our problem, not XRootD's, so
			// hold the clock rather than working toward a kill.
			log.WithError(err).Debug("Skipping XRootD liveness check")
			lastSuccess = time.Now()
			consecutiveFailures = 0
			delay = interval
			continue
		}

		checkStart := time.Now()
		probeErr := probeXrootdFn(ctx, addr, param.Xrootd_LivenessCheckTimeout.GetDuration())
		if ctx.Err() != nil {
			return
		}
		delay = nextCheckDelay(interval, time.Since(checkStart), probeErr == nil)

		if probeErr == nil {
			log.Tracef("XRootD liveness check against %s succeeded", addr)
			lastSuccess = time.Now()
			consecutiveFailures = 0
			continue
		}

		consecutiveFailures++
		unresponsiveFor := time.Since(lastSuccess)
		maxUnresponsive := param.Xrootd_LivenessMaxUnresponsiveTime.GetDuration()
		if unresponsiveFor < maxUnresponsive {
			log.Warnf("XRootD liveness check against %s failed (%v); %d consecutive failures over %s of the permitted %s",
				addr, probeErr, consecutiveFailures, unresponsiveFor.Round(time.Second), maxUnresponsive)
			continue
		}

		log.Errorf("XRootD at %s has failed %d consecutive liveness checks and has not responded for %s (limit %s); shutting the daemon down",
			addr, consecutiveFailures, unresponsiveFor.Round(time.Second), maxUnresponsive)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical,
			"XRootD was unresponsive for "+unresponsiveFor.Round(time.Second).String()+" and is being shut down")
		shutdownXrootdFn(isCache)
		return
	}
}

// xrootdLivenessAddress returns the local address of the XRootD endpoint for this server role.
// The loopback interface is used deliberately: the check is meant to catch a wedged local
// daemon, not a network or DNS problem somewhere between here and a client.
func xrootdLivenessAddress(isCache bool) (string, error) {
	portParam := param.Origin_Port
	if isCache {
		portParam = param.Cache_Port
	}
	port := portParam.GetInt()
	if port <= 0 {
		return "", errors.Errorf("%s is not set to a usable port (%d)", portParam.GetName(), port)
	}
	return net.JoinHostPort("localhost", strconv.Itoa(port)), nil
}

// probeXrootdEndpoint reports whether the XRootD daemon listening at addr is still servicing
// new connections.  It returns nil when XRootD is responsive.
//
// A bare TCP connect is not enough on its own: the kernel completes the handshake out of the
// listen backlog, so a completely wedged XRootD (say, one stopped with SIGSTOP) still accepts
// connections until the backlog fills.  Neither HTTP nor the xroot protocol has the server
// speak first, so the probe sends a TLS ClientHello -- every Pelican-generated XRootD config
// enables TLS on this port -- and requires XRootD itself to answer.
func probeXrootdEndpoint(parentCtx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to the XRootD endpoint at %s", addr)
	}
	defer conn.Close()

	// Fall back to the host we dialed if the server has no configured hostname; an empty
	// ServerName makes crypto/tls fail the handshake immediately, which would look like
	// XRootD answering and quietly neuter the whole check.
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}
	tlsConn := tls.Client(conn, livenessTLSConfigFn(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if parentCtx.Err() != nil {
			// Pelican is shutting down; the probe learned nothing either way.
			return errors.Wrap(err, "XRootD liveness probe was interrupted")
		}
		if isProbeTimeout(err) {
			return errors.Wrapf(err, "the XRootD endpoint at %s accepted a connection but did not respond within %s",
				addr, timeout.String())
		}
		// XRootD answered with something we could not complete a handshake against
		// (a client certificate demand, a protocol error, an abrupt close). It is
		// alive and processing connections, which is all this check asks of it.
		log.Debugf("XRootD at %s responded to the liveness check with a TLS error, which still counts as alive: %v", addr, err)
	}
	return nil
}

// livenessTLSConfig returns the TLS settings for the probe: Pelican's own trust roots, and
// the name the server's certificate is issued for rather than the loopback address dialed.
//
// Whether verification succeeds does not actually change the verdict -- a rejected
// certificate is still XRootD answering, and probeXrootdEndpoint treats any non-timeout
// error as alive -- so a certificate problem can never be mistaken for a hung daemon.
// Verifying anyway keeps the probe honest and avoids carrying a disabled certificate check
// around in the tree.
func livenessTLSConfig(fallbackHost string) *tls.Config {
	cfg := &tls.Config{}
	if transport := config.GetTransport(); transport != nil && transport.TLSClientConfig != nil {
		cfg = transport.TLSClientConfig.Clone()
	}
	cfg.ServerName = param.Server_Hostname.GetString()
	if cfg.ServerName == "" {
		cfg.ServerName = fallbackHost
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

// isProbeTimeout reports whether err means the peer never answered, as opposed to answering
// with something unexpected.
func isProbeTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// shutdownHungXrootd terminates the XRootD (and, if configured, cmsd) processes launched for
// the given server role.
func shutdownHungXrootd(isCache bool) {
	pids := trackedPIDsForRole(isCache)
	if len(pids) == 0 {
		log.Error("Unable to shut down the unresponsive XRootD: no tracked PIDs are available")
		return
	}
	log.Warnf("Shutting down unresponsive XRootD processes %v", pids)
	terminateProcesses(pids, param.Xrootd_ShutdownTimeout.GetDuration())
}
