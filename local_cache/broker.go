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
	"net/http"
	"net/url"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/server_structs"
)

// cacheBrokerDialer is the broker-aware dialer the cache uses to reach a
// broker-only (firewalled) origin when mediating client data operations (WS1).
// Set at launch when the cache module is enabled; nil otherwise (no brokering).
var cacheBrokerDialer *broker.BrokerDialer

// SetBrokerDialer records the broker-aware dialer so the cache's origin-facing
// requests can reach a firewalled origin through the broker. It also installs a
// registrar on the client transfer stack so the cache's GET-miss fetches (which
// go through client.TransferClient, not the proxy path) become broker-aware too.
func SetBrokerDialer(d *broker.BrokerDialer) {
	cacheBrokerDialer = d
	client.SetBrokerRegistrar(registerOriginBroker)
}

// registerOriginBroker teaches the broker dialer how to reach an origin at
// dialAddr (host:port, the address the transport will dial) via the broker URL
// the director advertised. The broker URL self-encodes the origin prefix, so the
// reverse request routes correctly. A no-op when the cache has no broker dialer
// or no broker URL was advertised (the origin is directly reachable).
func registerOriginBroker(dialAddr, brokerURL string) {
	if cacheBrokerDialer == nil || brokerURL == "" {
		return
	}
	prefix := ""
	if bu, err := url.Parse(brokerURL); err == nil {
		prefix = bu.Query().Get("prefix")
	}
	cacheBrokerDialer.UseBroker(server_structs.OriginType, dialAddr, brokerURL, prefix)
}

// registerOriginBrokerFromRedirect is the write/PROPFIND-path variant: it reads
// the X-Pelican-Broker header from the director's 307 redirect response.
func registerOriginBrokerFromRedirect(dialAddr string, resp *http.Response) {
	if resp == nil {
		return
	}
	registerOriginBroker(dialAddr, resp.Header.Get("X-Pelican-Broker"))
}
