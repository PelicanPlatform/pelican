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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HTTP/Protocol-level metrics for WebDAV and other HTTP handlers
// These parallel XRootD's transfer and connection metrics but at the HTTP layer

var (
	// Connection metrics
	HttpConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_connections_total",
		Help: "Total number of HTTP connections accepted",
	}, []string{"server_type"}) // server_type: origin/cache

	HttpActiveConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_http_active_connections",
		Help: "Number of currently active HTTP connections",
	}, []string{"server_type"})

	// Request/Transfer operation metrics
	HttpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_requests_total",
		Help: "Total number of HTTP requests processed",
	}, []string{"server_type", "method", "code"}) // method: GET/PUT/DELETE, code: 200/404/500/etc

	HttpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets, // 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
	}, []string{"server_type", "method", "code"})

	// Transfer bytes metrics (similar to XRootD's TransferBytes and BytesXfer)
	HttpBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_bytes_total",
		Help: "Total bytes transferred via HTTP",
	}, []string{"server_type", "direction", "method"}) // direction: in/out, method: GET/PUT/etc

	// Active request tracking (similar to XRootD's Jobs/Queued)
	HttpActiveRequests = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_http_active_requests",
		Help: "Number of currently active HTTP requests being processed",
	}, []string{"server_type", "method"})

	// Error metrics
	HttpErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_errors_total",
		Help: "Total number of HTTP errors (5xx responses)",
	}, []string{"server_type", "method", "code"})

	// Large transfer tracking (similar to slow operations)
	HttpLargeTransfersTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_large_transfers_total",
		Help: "Total number of large HTTP transfers (>100MB)",
	}, []string{"server_type", "method"})

	HttpLargeTransferBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_http_large_transfer_bytes_total",
		Help: "Total bytes in large HTTP transfers (>100MB)",
	}, []string{"server_type", "direction", "method"})
)

// Server type constants for labeling
const (
	ServerTypeOrigin = "origin"
	ServerTypeCache  = "cache"
)

// HTTP method tracking
const (
	MethodGET      = "GET"
	MethodPUT      = "PUT"
	MethodDELETE   = "DELETE"
	MethodMKCOL    = "MKCOL"
	MethodMOVE     = "MOVE"
	MethodCOPY     = "COPY"
	MethodPROPFIND = "PROPFIND"
	MethodOPTIONS  = "OPTIONS"
	MethodHEAD     = "HEAD"
)

// Direction constants for byte transfer metrics
const (
	DirectionIn  = "in"  // Bytes received (e.g., PUT requests)
	DirectionOut = "out" // Bytes sent (e.g., GET requests)
)

// Large transfer threshold (100MB)
const LargeTransferThreshold = 100 * 1024 * 1024
