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

// This file contains methods for a dialer that can use the broker
// functionality to connect to a remote service.

package broker

import (
	"context"
	"net"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	brokerPrefixInfo struct {
		ServerType server_structs.ServerType
		BrokerUrl  string
		Prefix     string
	}

	// BrokerDialer is a dialer that can use the broker
	// functionality to connect to a remote service.
	BrokerDialer struct {
		dialerContext func(ctx context.Context, network, addr string) (net.Conn, error)
		// Map from service name to broker endpoint.
		// If the service name is not found in the cache, then the dialer
		// will use a normal TCP connection to the service.
		brokerEndpoints *ttlcache.Cache[string, brokerPrefixInfo]
	}
)

// NewBrokerDialer creates a new BrokerDialer.
func NewBrokerDialer(ctx context.Context, egrp *errgroup.Group) *BrokerDialer {

	dialer := &net.Dialer{
		Timeout:   param.Transport_DialerTimeout.GetDuration(),
		KeepAlive: param.Transport_DialerKeepAlive.GetDuration(),
	}
	brokerEndpoints := ttlcache.New(
		ttlcache.WithTTL[string, brokerPrefixInfo](param.Transport_BrokerEndpointCacheTTL.GetDuration()),
		ttlcache.WithDisableTouchOnHit[string, brokerPrefixInfo](),
	)

	go brokerEndpoints.Start()
	egrp.Go(func() error {
		<-ctx.Done()
		brokerEndpoints.DeleteAll()
		brokerEndpoints.Stop()
		return nil
	})

	return &BrokerDialer{
		dialerContext:   dialer.DialContext,
		brokerEndpoints: brokerEndpoints,
	}
}

// Set the dialer to use `brokerUrl` as the broker endpoint for
// the service `name`.
func (d *BrokerDialer) UseBroker(serverType server_structs.ServerType, name, brokerUrl, prefix string) {
	d.brokerEndpoints.Set(name, brokerPrefixInfo{
		ServerType: serverType,
		BrokerUrl:  brokerUrl,
		Prefix:     prefix,
	}, ttlcache.DefaultTTL)
}

// HasBrokerEndpoint returns true if the dialer knows about a broker endpoint for the given address.
func (d *BrokerDialer) HasBrokerEndpoint(addr string) bool {
	return d.brokerEndpoints.Get(addr) != nil
}

// DialContext dials a connection to the given network and address using the broker.
func (d *BrokerDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	info := d.brokerEndpoints.Get(addr)
	if info == nil {
		log.Debugf("BrokerDialer: No broker endpoint found for %s, using default dialer", addr)
		// If the endpoint is not found in the cache, use the default dialer.
		return d.dialerContext(ctx, network, addr)
	}

	log.Debugf("BrokerDialer: Using broker to connect to %s via %s", addr, info.Value().BrokerUrl)
	return ConnectToService(ctx, info.Value().BrokerUrl, info.Value().Prefix, addr)
}
