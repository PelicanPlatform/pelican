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

// Package bgp_advertise implements TCP-anycast route advertisement for a cache.
//
// It embeds a GoBGP speaker that peers with a configured BGP router and advertises
// (or withdraws) the cache's anycast net blocks.  Routes are only advertised while
// the cache is healthy and is serving a host certificate with the expected anycast
// hostname as a Subject Alternative Name; the caller (the cache launcher) is
// responsible for evaluating those conditions and calling Advertise/Withdraw
// accordingly.
package bgp_advertise

import (
	"context"
	"net"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// Config holds the BGP peering and route configuration for the anycast advertiser.
type Config struct {
	RouterID     string   // BGP router ID (typically, an IPv4-formatted identifier)
	LocalASN     uint32   // local autonomous system number
	PeerAddress  string   // BGP peer (router) IP address
	PeerASN      uint32   // peer autonomous system number
	LocalAddress string   // optional local address to bind when connecting
	Port         uint32   // TCP port for the BGP session (typically 179)
	Password     string   // optional TCP-MD5 password
	NextHop      string   // next-hop address advertised with the routes
	Routes       []string // CIDR net blocks to advertise (IPv4 and/or IPv6)
}

// Validate checks that the configuration has the mandatory fields needed to
// establish a BGP session and advertise routes.
func (c *Config) Validate() error {
	if c.RouterID == "" {
		return errors.New("BGP router ID must be set")
	}
	if c.LocalASN == 0 {
		return errors.New("local ASN must be set")
	}
	if c.PeerAddress == "" {
		return errors.New("BGP peer address must be set")
	}
	if c.PeerASN == 0 {
		return errors.New("peer ASN must be set")
	}
	if len(c.Routes) == 0 {
		return errors.New("at least one anycast route (CIDR) must be configured")
	}
	if c.NextHop == "" && c.LocalAddress == "" {
		return errors.New("either a next-hop or a local address must be configured")
	}
	for _, r := range c.Routes {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return errors.Wrapf(err, "invalid anycast route %q", r)
		}
	}
	return nil
}

// nextHop returns the next-hop address to advertise, falling back to the local
// address when an explicit next-hop is not configured.
func (c *Config) nextHop() string {
	if c.NextHop != "" {
		return c.NextHop
	}
	return c.LocalAddress
}

// Advertiser manages the embedded GoBGP speaker and the lifecycle of the anycast
// routes.  It is safe for concurrent use.
type Advertiser struct {
	cfg    Config
	server *server.BgpServer

	mu         sync.Mutex
	started    bool
	advertised bool
	paths      []*api.Path // the paths currently (or last) advertised
}

// New constructs an Advertiser for the given configuration.  It validates the
// configuration but does not start the BGP session (call Start for that).
func New(cfg Config) (*Advertiser, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Advertiser{cfg: cfg}, nil
}

// Start brings up the embedded BGP speaker and configures the peer.  It is
// idempotent.  The speaker runs until Close is called (or ctx is cancelled and
// Close is invoked by the caller).
func (a *Advertiser) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return nil
	}

	a.server = server.NewBgpServer(server.LoggerOption(newLogger()))
	go a.server.Serve()

	// ListenPort -1 disables the inbound listener: the cache acts as a pure
	// route injector that actively dials the configured peer, so it does not
	// need to bind the privileged BGP port locally.
	global := &api.Global{
		Asn:        a.cfg.LocalASN,
		RouterId:   a.cfg.RouterID,
		ListenPort: -1,
	}
	if err := a.server.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		a.server.Stop()
		a.server = nil
		return errors.Wrap(err, "failed to start BGP speaker")
	}

	remotePort := a.cfg.Port
	if remotePort == 0 {
		remotePort = 179
	}
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: a.cfg.PeerAddress,
			PeerAsn:         a.cfg.PeerASN,
			AuthPassword:    a.cfg.Password,
		},
		Transport: &api.Transport{
			RemoteAddress: a.cfg.PeerAddress,
			RemotePort:    remotePort,
			LocalAddress:  a.cfg.LocalAddress,
		},
	}
	if err := a.server.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		_ = a.server.StopBgp(ctx, &api.StopBgpRequest{})
		a.server.Stop()
		a.server = nil
		return errors.Wrap(err, "failed to add BGP peer")
	}

	a.started = true
	log.WithField("peer", a.cfg.PeerAddress).Info("Anycast BGP speaker started")
	return nil
}

// buildPath constructs a GoBGP path (NLRI + origin + next-hop attributes) for a
// single CIDR route.
func buildPath(cidr, nextHop string) (*api.Path, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid CIDR %q", cidr)
	}
	prefixLen, _ := ipNet.Mask.Size()

	afi := api.Family_AFI_IP
	if ip.To4() == nil {
		afi = api.Family_AFI_IP6
	}

	nlri, err := apb.New(&api.IPAddressPrefix{
		Prefix:    ipNet.IP.String(),
		PrefixLen: uint32(prefixLen),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode NLRI")
	}
	origin, err := apb.New(&api.OriginAttribute{Origin: 0}) // 0 == IGP
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode origin attribute")
	}
	nh, err := apb.New(&api.NextHopAttribute{NextHop: nextHop})
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode next-hop attribute")
	}

	return &api.Path{
		Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: []*apb.Any{origin, nh},
	}, nil
}

// Advertise installs all configured routes into the BGP RIB so they are
// advertised to the peer.  It is idempotent: calling it while already
// advertising is a no-op.
func (a *Advertiser) Advertise(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started {
		return errors.New("advertiser has not been started")
	}
	if a.advertised {
		return nil
	}

	paths := make([]*api.Path, 0, len(a.cfg.Routes))
	for _, route := range a.cfg.Routes {
		p, err := buildPath(route, a.cfg.nextHop())
		if err != nil {
			return err
		}
		if _, err := a.server.AddPath(ctx, &api.AddPathRequest{
			TableType: api.TableType_GLOBAL,
			Path:      p,
		}); err != nil {
			return errors.Wrapf(err, "failed to advertise route %q", route)
		}
		paths = append(paths, p)
	}
	a.paths = paths
	a.advertised = true
	log.WithField("routes", a.cfg.Routes).Info("Advertising anycast routes via BGP")
	return nil
}

// Withdraw removes all advertised routes from the BGP RIB, withdrawing them from
// the peer.  It is idempotent: calling it while not advertising is a no-op.
func (a *Advertiser) Withdraw(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started || !a.advertised {
		return nil
	}

	var firstErr error
	for i, p := range a.paths {
		if err := a.server.DeletePath(ctx, &api.DeletePathRequest{
			TableType: api.TableType_GLOBAL,
			Path:      p,
		}); err != nil {
			if firstErr == nil {
				firstErr = errors.Wrapf(err, "failed to withdraw route %q", a.cfg.Routes[i])
			}
		}
	}
	a.advertised = false
	a.paths = nil
	if firstErr != nil {
		return firstErr
	}
	log.Info("Withdrew anycast routes from BGP")
	return nil
}

// IsAdvertising reports whether the routes are currently being advertised.
func (a *Advertiser) IsAdvertising() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.advertised
}

// Close withdraws any advertised routes, tears down the BGP session, and stops
// the embedded speaker.  It is safe to call multiple times.
func (a *Advertiser) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started {
		return nil
	}
	ctx := context.Background()
	if a.advertised {
		for _, p := range a.paths {
			_ = a.server.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: p})
		}
		a.advertised = false
		a.paths = nil
	}
	_ = a.server.StopBgp(ctx, &api.StopBgpRequest{})
	a.server.Stop()
	a.server = nil
	a.started = false
	log.Info("Anycast BGP speaker stopped")
	return nil
}
