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

var originReportNotFoundError = errors.New("Origin does not support new reporting API")

// Report the health status of test file transfer to storage server
func reportStatusToServer(ctx context.Context, serverWebUrl string, status string, message string, serverType server_structs.ServerType, fallback bool) error {
	directorUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return errors.Wrapf(err, "failed to parse external URL %v", param.Server_ExternalWebUrl.GetString())
	}

	testTokenCfg := token.NewWLCGToken()
	testTokenCfg.Lifetime = time.Minute
	testTokenCfg.Issuer = directorUrl.String()
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

	if serverType == server_structs.OriginType {
		if fallback {
			reportUrl.Path = "/api/v1.0/origin-api/directorTest"
		} else {
			reportUrl.Path = "/api/v1.0/origin/directorTest"
		}
	} else if serverType == server_structs.CacheType {
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
	if serverType == server_structs.OriginType && resp.StatusCode != 200 {
		return errors.Errorf("error response %v from reporting director test: %v", resp.StatusCode, string(body))
	}
	if serverType == server_structs.CacheType && resp.StatusCode == 404 {
		return errors.New("cache reports a 404 error. For cache version < v7.7.0, director-based test is not supported")
	}
	if serverType == server_structs.OriginType && resp.StatusCode == 404 {
		return originReportNotFoundError
	}

	return nil
}

// Run a periodic test file transfer against an origin to ensure
// it's talking to the director
func LaunchPeriodicDirectorTest(ctx context.Context, serverAd server_structs.ServerAd) {
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

	for {
		select {
		case <-ctx.Done():
			log.Debug(fmt.Sprintf("End director test suite for %s server %s at %s", serverAd.Type, serverName, serverUrl))

			metrics.PelicanDirectorActiveFileTransferTestSuite.With(
				prometheus.Labels{
					"server_name": serverName, "server_web_url": serverWebUrl, "server_type": string(serverAd.Type),
				}).Dec()

			return
		case <-ticker.C:
			log.Debug(fmt.Sprintf("Starting a director test cycle for %s server %s at %s", serverAd.Type, serverName, serverUrl))
			ok := true
			var err error
			if serverAd.Type == server_structs.OriginType {
				fileTests := server_utils.TestFileTransferImpl{}
				ok, err = fileTests.RunTests(ctx, serverUrl, serverUrl, "", server_utils.DirectorTest)
			} else if serverAd.Type == server_structs.CacheType {
				err = runCacheTest(ctx, serverAd.URL)
			}

			// Successfully run a test, no error
			if ok && err == nil {
				log.Debugf("Director file transfer test cycle succeeded at %s for %s server with URL at %s", time.Now().Format(time.RFC3339), serverAd.Type, serverUrl)
				func() {
					healthTestUtilsMutex.Lock()
					defer healthTestUtilsMutex.Unlock()
					if existingUtil, ok := healthTestUtils[serverAd.URL.String()]; ok {
						existingUtil.Status = HealthStatusOK
					} else {
						log.Debugln("HealthTestUtil missing for ", serverAd.Type, " server: ", serverUrl, " Failed to update internal status")
					}
				}()

				// Report error back to origin/server
				if err := reportStatusToServer(
					ctx,
					serverWebUrl,
					"ok", "Director test cycle succeeded at "+time.Now().Format(time.RFC3339),
					serverAd.Type,
					false,
				); err != nil {
					// origin <7.7 only supports legacy report endpoint. Fallback to the legacy one
					if err == originReportNotFoundError {
						newErr := reportStatusToServer(
							ctx,
							serverWebUrl,
							"ok", "Director test cycle succeeded at "+time.Now().Format(time.RFC3339),
							serverAd.Type,
							true, // Fallback to legacy endpoint
						)
						// If legacy endpoint still reports error
						if newErr != nil {
							log.Warningf("Failed to report director test result to %s server at %s: %v", serverAd.Type, serverAd.WebURL.String(), err)
							metrics.PelicanDirectorFileTransferTestsRuns.With(
								prometheus.Labels{
									"server_name":    serverName,
									"server_web_url": serverWebUrl,
									"server_type":    string(serverAd.Type),
									"status":         string(metrics.FTXTestSucceeded),
									"report_status":  string(metrics.FTXTestFailed),
								},
							).Inc()
							// Successfully report to the origin/cache via the legacy endpoint
						} else {
							metrics.PelicanDirectorFileTransferTestsRuns.With(
								prometheus.Labels{
									"server_name":    serverName,
									"server_web_url": serverWebUrl,
									"server_type":    string(serverAd.Type),
									"status":         string(metrics.FTXTestSucceeded),
									"report_status":  string(metrics.FTXTestSucceeded),
								},
							).Inc()
						}
						// If the error is not originReportNotFoundError, then we record the error right away
					} else {
						log.Warningf("Failed to report director test result to %s server at %s: %v", serverAd.Type, serverAd.WebURL.String(), err)
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name":    serverName,
								"server_web_url": serverWebUrl,
								"server_type":    string(serverAd.Type),
								"status":         string(metrics.FTXTestSucceeded),
								"report_status":  string(metrics.FTXTestFailed),
							},
						).Inc()
					}
					// No error when reporting the result, we are good
				} else {
					metrics.PelicanDirectorFileTransferTestsRuns.With(
						prometheus.Labels{
							"server_name":    serverName,
							"server_web_url": serverWebUrl,
							"server_type":    string(serverAd.Type),
							"status":         string(metrics.FTXTestSucceeded),
							"report_status":  string(metrics.FTXTestSucceeded),
						},
					).Inc()
				}
				// The file tests failed. Report failure back to origin/cache
			} else {
				log.Warningln("Director file transfer test cycle failed for ", serverAd.Type, " server: ", serverUrl, " ", err)
				func() {
					healthTestUtilsMutex.Lock()
					defer healthTestUtilsMutex.Unlock()
					if existingUtil, ok := healthTestUtils[serverAd.URL.String()]; ok {
						existingUtil.Status = HealthStatusError
					} else {
						log.Debugln("HealthTestUtil missing for", serverAd.Type, " server: ", serverUrl, " Failed to update internal status")
					}
				}()

				if err := reportStatusToServer(
					ctx,
					serverWebUrl,
					"error", "Director file transfer test cycle failed for origin: "+serverUrl+" "+err.Error(),
					serverAd.Type,
					false,
				); err != nil {
					// origin <7.7 only supports legacy report endpoint. Fallback to the legacy one
					if err == originReportNotFoundError {
						newErr := reportStatusToServer(
							ctx,
							serverWebUrl,
							"ok", "Director test cycle succeeded at "+time.Now().Format(time.RFC3339),
							serverAd.Type,
							true, // Fallback to legacy endpoint
						)
						// If legacy endpoint still reports error
						if newErr != nil {
							log.Warningf("Failed to report director test result to %s server at %s: %v", serverAd.Type, serverAd.WebURL.String(), err)
							metrics.PelicanDirectorFileTransferTestsRuns.With(
								prometheus.Labels{
									"server_name":    serverName,
									"server_web_url": serverWebUrl,
									"server_type":    string(serverAd.Type),
									"status":         string(metrics.FTXTestFailed),
									"report_status":  string(metrics.FTXTestFailed),
								},
							).Inc()
							// Successfully report to the origin/cache via the legacy endpoint
						} else {
							metrics.PelicanDirectorFileTransferTestsRuns.With(
								prometheus.Labels{
									"server_name":    serverName,
									"server_web_url": serverWebUrl,
									"server_type":    string(serverAd.Type),
									"status":         string(metrics.FTXTestFailed),
									"report_status":  string(metrics.FTXTestSucceeded),
								},
							).Inc()
						}
						// If the error is not originReportNotFoundError, then we record the error right away
					} else {
						log.Warningf("Failed to report director test result to %s server at %s: %v", serverAd.Type, serverAd.WebURL.String(), err)
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name":    serverName,
								"server_web_url": serverWebUrl,
								"server_type":    string(serverAd.Type),
								"status":         string(metrics.FTXTestFailed),
								"report_status":  string(metrics.FTXTestFailed),
							},
						).Inc()
					}

				} else {
					// No error when reporting the result, we are good
					metrics.PelicanDirectorFileTransferTestsRuns.With(
						prometheus.Labels{
							"server_name":    serverName,
							"server_web_url": serverWebUrl,
							"server_type":    string(serverAd.Type),
							"status":         string(metrics.FTXTestFailed),
							"report_status":  string(metrics.FTXTestSucceeded),
						},
					).Inc()
				}
			}

		}
	}
}
