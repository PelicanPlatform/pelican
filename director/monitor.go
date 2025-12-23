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

package director

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// Report the health status of test file transfer to storage server
func reportStatusToServer(ctx context.Context, serverWebUrl string, status string, message string, serverType string, fallback bool) error {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return err
	}

	testTokenCfg := token.NewWLCGToken()
	testTokenCfg.Lifetime = time.Minute
	testTokenCfg.Issuer = fedInfo.DiscoveryEndpoint
	testTokenCfg.AddAudiences(serverWebUrl)
	testTokenCfg.Subject = "director"
	testTokenCfg.AddScopes(token_scopes.Pelican_DirectorTestReport)

	tok, err := testTokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create director test report token")
	}

	reportUrl, err := url.Parse(serverWebUrl)
	if err != nil {
		return errors.Wrap(err, "the server URL is not parseable as an URL")
	}

	if status != "ok" && status != "error" {
		return errors.Errorf("bad status for reporting director test %s", status)
	}

	if serverType == server_structs.OriginType.String() {
		if fallback {
			reportUrl.Path = "/api/v1.0/origin-api/directorTest"
		} else {
			reportUrl.Path = "/api/v1.0/origin/directorTest"
		}
	} else if serverType == server_structs.CacheType.String() {
		reportUrl.Path = "/api/v1.0/cache/directorTest"
	}

	dt := server_structs.DirectorTestResult{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(dt)
	if err != nil {
		return errors.Wrap(err, "failed to parse request body for reporting director test")
	}

	reqBody := bytes.NewBuffer(jsonData)

	log.Debugf("Director is sending %s server test result to %s", string(serverType), reportUrl.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reportUrl.String(), reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to create POST request for reporting director test")
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	tr := config.GetTransport()
	client := http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for reporting director test")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to read response body for reporting director test")
	}

	if resp.StatusCode > 404 { // For all servers, >404 is a failure
		return errors.Errorf("error response %v from reporting director test: %v", resp.StatusCode, string(body))
	}
	if serverType == server_structs.OriginType.String() && resp.StatusCode != 200 {
		return errors.Errorf("error response %v from reporting director test: %v", resp.StatusCode, string(body))
	}

	return nil
}

// isDowntimeActive checks if a downtime is currently active based on the current time.
// A downtime is considered active if the current time is between StartTime and EndTime (inclusive),
// or if EndTime is IndefiniteEndTime and current time is after StartTime.
func isDowntimeActive(downtime server_structs.Downtime, currentTime int64) bool {
	return downtime.StartTime <= currentTime && (downtime.EndTime >= currentTime || downtime.EndTime == server_structs.IndefiniteEndTime)
}

// LaunchPeriodicDirectorTest runs periodic test file transfers against an origin or cache to ensure
// it's responding to director test requests. The test fetches the current server ad
// from the TTL cache on each cycle and stops when the ad is no longer present.
func LaunchPeriodicDirectorTest(ctx context.Context, serverUrlStr string) {
	// Option to disable touch on hit when fetching from cache to avoid extending TTL
	disableTouchOpt := ttlcache.WithDisableTouchOnHit[string, *server_structs.Advertisement]()

	// Fetch the initial server ad to set up metrics
	initialAdItem := serverAds.Get(serverUrlStr, disableTouchOpt)
	if initialAdItem == nil {
		log.Errorf("Failed to start director test suite: server ad not found in cache for URL %s. Test will not be started.", serverUrlStr)
		return
	}
	initialAd := initialAdItem.Value()
	serverAd := initialAd.ServerAd
	serverName := serverAd.Name
	serverUrl := serverAd.URL.String()
	serverWebUrl := serverAd.WebURL.String()

	log.Debug(fmt.Sprintf("Starting a new director test suite for %s server %s at %s", serverAd.Type, serverName, serverUrl))

	metrics.PelicanDirectorFileTransferTestSuite.With(
		prometheus.Labels{
			"server_name": serverName, "server_web_url": serverWebUrl, "server_type": string(serverAd.Type),
		}).Inc()

	metrics.PelicanDirectorActiveFileTransferTestSuite.With(
		prometheus.Labels{
			"server_name": serverName, "server_web_url": serverWebUrl, "server_type": string(serverAd.Type),
		}).Inc()

	customInterval := param.Director_OriginCacheHealthTestInterval.GetDuration()
	if customInterval < 15*time.Second {
		log.Warningf("You set Director.OriginCacheHealthTestInterval to a very small number %s, which will cause high traffic volume to xrootd servers.", customInterval.String())
	}
	if customInterval == 0 {
		customInterval = 15 * time.Second
		log.Error("Invalid config value: Director.OriginCacheHealthTestInterval is 0. Fallback to 15s.")
	}
	ticker := time.NewTicker(customInterval)

	defer ticker.Stop()

	// runDirectorTestCycle executes a single director test cycle and reports the result back to the server.
	// Extracted as a helper to allow running the first test immediately upon registration, avoiding the
	// race condition where the origin/cache 30s timeout fires before the first ticker-driven test.
	// Returns true if the test was run, false if it was skipped (e.g., server not in cache or in downtime).
	runDirectorTestCycle := func() bool {
		// Fetch the current server ad from the TTL cache
		adItem := serverAds.Get(serverUrlStr, disableTouchOpt)
		if adItem == nil {
			log.Infof("The Director doesn't have any advertisements for server with URL %s. Stopping director tests.", serverUrlStr)
			return false
		}
		currentServerAd := adItem.Value().ServerAd

		// Check if the server is in downtime by checking the filteredServers map
		if isServerInDowntime(currentServerAd.Name) {
			log.Debugf("Skipping director test cycle for %s server %s: server is in downtime", currentServerAd.Type, currentServerAd.Name)
			return true // Return true to continue the loop, but don't run the test
		}

		log.Debug(fmt.Sprintf("Starting a director test cycle for %s server %s at %s", currentServerAd.Type, currentServerAd.Name, currentServerAd.URL.String()))
		testSucceeded := true
		var testErr error
		if currentServerAd.Type == server_structs.OriginType.String() {
			fileTests := server_utils.TestFileTransferImpl{}
			testSucceeded, testErr = fileTests.RunTests(ctx, currentServerAd.URL.String(), currentServerAd.URL.String(), "", server_utils.DirectorTest)
		} else if currentServerAd.Type == server_structs.CacheType.String() {
			testErr = runCacheTest(ctx, currentServerAd.URL)
		}

		// Compose the result of this Director-test to report to the server
		var reportStatus, reportMessage string // status (result of the Director-test) and message to report back to the server
		var healthStatus HealthTestStatus
		if testSucceeded && testErr == nil {
			reportStatus = "ok"
			reportMessage = "Director test cycle succeeded at " + time.Now().Format(time.RFC3339)
			healthStatus = HealthStatusOK
			log.Debugf("Director file transfer test cycle succeeded at %s for %s server with URL at %s", time.Now().Format(time.RFC3339), currentServerAd.Type, currentServerAd.URL.String())
		} else {
			reportStatus = "error"
			reportMessage = "Director file transfer test cycle failed for server: " + currentServerAd.URL.String()
			if testErr != nil {
				reportMessage += " " + testErr.Error()
			}
			healthStatus = HealthStatusError
			log.Warningln("Director file transfer test cycle failed for ", currentServerAd.Type, " server: ", currentServerAd.URL.String(), " ", testErr)
		}

		// Update healthTestUtils once per cycle
		func() {
			healthTestUtilsMutex.Lock()
			defer healthTestUtilsMutex.Unlock()
			if existingUtil, ok := healthTestUtils[currentServerAd.URL.String()]; ok {
				existingUtil.Status = healthStatus
			} else {
				log.Debugln("HealthTestUtil missing for ", currentServerAd.Type, " server: ", currentServerAd.URL.String(), " Failed to update internal status")
			}
		}()

		// Determine the metric status label based on test result
		testStatusMetric := metrics.MetricSucceeded
		if !testSucceeded || testErr != nil {
			testStatusMetric = metrics.MetricFailed
		}

		// Report the result of this Director-test back to origin/server (single call)
		reportErr := reportStatusToServer(ctx, currentServerAd.WebURL.String(), reportStatus, reportMessage, currentServerAd.Type, false)

		// Determine report status metric and log if reporting failed
		reportStatusMetric := metrics.MetricSucceeded
		if reportErr != nil {
			reportStatusMetric = metrics.MetricFailed
			log.Warningf("Failed to report director test result to %s server at %s: %v", currentServerAd.Type, currentServerAd.WebURL.String(), reportErr)
		}

		// Record metrics once per cycle
		metrics.PelicanDirectorFileTransferTestsRuns.With(
			prometheus.Labels{
				"server_name":    currentServerAd.Name,
				"server_web_url": currentServerAd.WebURL.String(),
				"server_type":    string(currentServerAd.Type),
				"status":         string(testStatusMetric),
				"report_status":  string(reportStatusMetric),
			},
		).Inc()
		
		return true // Test was run successfully
	}

	// Run the first test immediately to avoid race with origin/cache 30s timeout.
	// Without this, time.NewTicker waits for the first interval before firing,
	// which could cause the origin/cache to report a missed test if registration
	// takes more than 15 seconds after the server started.
	runDirectorTestCycle()

	for {
		select {
		case <-ctx.Done():
			log.Debug(fmt.Sprintf("Stopped the Director test suite for %s server %s at %s", serverAd.Type, serverName, serverUrl))

			metrics.PelicanDirectorActiveFileTransferTestSuite.With(
				prometheus.Labels{
					"server_name": serverName, "server_web_url": serverWebUrl, "server_type": string(serverAd.Type),
				}).Dec()

			return
		case <-ticker.C:
			runDirectorTestCycle()
		}
	}
}
