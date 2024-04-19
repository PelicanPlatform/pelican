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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type (
	DirectorFTXTestStatus string
)

const (
	FTXTestSucceeded DirectorFTXTestStatus = "Succeeded"
	FTXTestFailed    DirectorFTXTestStatus = "Failed"
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
		Help: "The number of file transfer test runs the director issued. A test run is a cycle of upload/download/delete test file, which is executed per 15s per origin (by defult)",
	}, []string{"server_name", "server_web_url", "server_type", "status", "report_status"})

	PelicanDirectorTotalAdvertisementsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_director_total_advertisements_received",
		Help: "The total number of advertisement the director received from the origin and cache servers. Labled by status_code, server_name, serve_type: Origin|Cache, server_web_url",
	}, []string{"server_name", "server_web_url", "server_type", "status_code"})
)
