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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type (
	MetricSimpleStatus    string
	DirectorFTXTestStatus MetricSimpleStatus
	DirectorStatResult    string
)

const (
	MetricSucceeded MetricSimpleStatus = "Succeeded"
	MetricFailed    MetricSimpleStatus = "Failed"

	StatSucceeded  DirectorStatResult = "Succeeded"
	StatNotFound   DirectorStatResult = "NotFound"
	StatTimeout    DirectorStatResult = "Timeout"
	StatCancelled  DirectorStatResult = "Cancelled"
	StatForbidden  DirectorStatResult = "Forbidden"
	StatUnknownErr DirectorStatResult = "UnknownErr"
)

var (
	PelicanDirectorFileTransferTestSuite = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_total_ftx_test_suite",
		Help: "The total number of file transfer test suite the director issued. A new test suite is a new goroutine started at origin's advertisement to the director and is cancelled when such registration expired in director's TTL cache",
	}, []string{"server_name", "server_web_url", "server_type"})

	PelicanDirectorActiveFileTransferTestSuite = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_active_ftx_test_suite",
		Help: "The number of active director file transfer test suite. The number of active goroutines that executes test run",
	}, []string{"server_name", "server_web_url", "server_type"})

	PelicanDirectorFileTransferTestsRuns = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_total_ftx_test_runs",
		Help: "The number of file transfer test runs the director issued. A test run is a cycle of upload/download/delete test file, which is executed per 15s per origin (by default)",
	}, []string{"server_name", "server_web_url", "server_type", "status", "report_status"})

	PelicanDirectorAdvertisementsReceivedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_advertisements_received_total",
		Help: "The total number of advertisement the director received from the origin and cache servers. Labelled by status_code, server_name, serve_type: Origin|Cache, server_web_url",
	}, []string{"server_name", "server_web_url", "server_type", "status_code", "namespace_prefix"})

	PelicanDirectorMapItemsTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_map_items_total",
		Help: "The total number of map items in the director, by the name of the map",
	}, []string{"name"}) // name: healthTestUtils, filteredServers, serverStatUtils, serverStatEntries

	PelicanDirectorTTLCache = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_ttl_cache",
		Help: "The statistics of various TTL caches",
	}, []string{"name", "type"}) // name: serverAds, jwks; type: evictions, insersions, hits, misses, total

	PelicanDirectorStatActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_stat_active",
		Help: "The active stat queries in the director",
	}, []string{"server_name", "server_url", "server_type"})

	PelicanDirectorStatTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_stat_total",
		Help: "The total stat queries the director issues. The status can be Succeeded, Cancelled, Timeout, Forbidden, or UnknownErr",
	}, []string{"server_name", "server_url", "server_type", "result", "cached_result"}) // result: see enums for DirectorStatResult

	PelicanDirectorServerCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_server_count",
		Help: "The number of servers currently recognized by the Director, delineated by pelican/non-pelican and origin/cache",
	}, []string{"server_name", "server_type", "from_topology"})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	PelicanDirectorClientVersionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_client_version_total",
		Help: "The total number of requests from client versions.",
	}, []string{"version", "service"})

	PelicanDirectorClientRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_client_requests_total",
		Help: "The total number of requests from clients.",
	}, []string{"version", "service"})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	PelicanDirectorRedirectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_redirections_total",
		Help: "The total number of redirections the director issued.",
	}, []string{"destination", "status_code", "version", "network"})

	PelicanDirectorRedirectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_redirects_total",
		Help: "The total number of redirects the director issued.",
	}, []string{"destination", "status_code", "version", "network"})

	// TODO: Remove these two metrics (the lines directly below)
	// They're no longer being tracked because they were split into separate client/server metrics
	// (see PelicanDirectorMaxMind{Server,Client}ErrorsTotal) because the error conditions are
	// now different and generated under different internal processes.
	PelicanDirectorGeoIPErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_geoip_errors",
		Help: "[Deprecated] The total number of errors encountered trying to resolve coordinates using the GeoIP MaxMind database",
	}, []string{"network", "source", "proj"})

	PelicanDirectorGeoIPErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_geoip_errors_total",
		Help: "[Deprecated -- split into separate client/server metrics (pelican_director_maxmind_{server,client}_errors_total)] The total number of errors encountered trying to resolve coordinates using the GeoIP MaxMind database",
	}, []string{"network", "source", "proj"})

	// The next two metrics replace the previous two deprecated GeoIP error metrics
	PelicanDirectorMaxMindServerErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_maxmind_server_errors_total",
		Help: "The total number of errors encountered trying to resolve server coordinates using the GeoIP MaxMind database",
	}, []string{"network", "server_name"})

	PelicanDirectorMaxMindClientErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_maxmind_client_errors_total",
		Help: "The total number of errors encountered trying to resolve client coordinates using the GeoIP MaxMind database",
	}, []string{"network", "project"})

	PelicanDirectorRejectedAdvertisements = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_rejected_advertisements",
		Help: "The total number of advertisements rejected by the director",
	}, []string{"hostname"})

	PelicanDirectorStatusWeight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_director_server_statusweight",
		Help: "The EWMA-smoothed status weight generated by the Director for each server",
	}, []string{"server_name", "server_url", "server_type"})
)
