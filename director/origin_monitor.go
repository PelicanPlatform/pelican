/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	DirectorTest struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
)

// Report the health status of test file transfer to origin
func reportStatusToOrigin(ctx context.Context, originWebUrl string, status string, message string) error {
	directorUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return errors.Wrapf(err, "failed to parse external URL %v", param.Server_ExternalWebUrl.GetString())
	}

	testTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Version:      "1.0",
		Lifetime:     time.Minute,
		Issuer:       directorUrl.String(),
		Audience:     []string{originWebUrl},
		Subject:      "director",
	}
	testTokenCfg.AddScopes([]token_scopes.TokenScope{token_scopes.Pelican_DirectorTestReport})

	tok, err := testTokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create director test report token")
	}

	reportUrl, err := url.Parse(originWebUrl)
	if err != nil {
		return errors.Wrap(err, "The origin URL is not parseable as a URL")
	}

	if status != "ok" && status != "error" {
		return errors.Errorf("Bad status for reporting director test")
	}

	reportUrl.Path = "/api/v1.0/origin-api/directorTest"

	dt := DirectorTest{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(dt)
	if err != nil {
		// handle error
		return errors.Wrap(err, "Failed to parse request body for reporting director test")
	}

	reqBody := bytes.NewBuffer(jsonData)

	log.Debugln("Director is uploading origin test results to", reportUrl.String())
	req, err := http.NewRequestWithContext(ctx, "POST", reportUrl.String(), reqBody)
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for reporting director test")
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

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from reporting director test: %v", resp.StatusCode, string(body))
	}

	return nil
}

// Run a periodic test file transfer against an origin to ensure
// it's talking to the director
func LaunchPeriodicDirectorTest(ctx context.Context, originAd ServerAd) {
	originName := originAd.Name
	originUrl := originAd.URL.String()
	originWebUrl := originAd.WebURL.String()

	log.Debug(fmt.Sprintf("Starting Director test for origin %s at %s", originName, originUrl))

	metrics.PelicanDirectorFileTransferTestSuite.With(
		prometheus.Labels{
			"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type),
		}).Inc()

	metrics.PelicanDirectorActiveFileTransferTestSuite.With(
		prometheus.Labels{
			"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type),
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

	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	egrp.Go(func() error {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debug(fmt.Sprintf("End director test cycle for origin: %s at %s", originName, originUrl))

				metrics.PelicanDirectorActiveFileTransferTestSuite.With(
					prometheus.Labels{
						"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type),
					}).Dec()

				return nil
			case <-ticker.C:
				log.Debug(fmt.Sprintf("Starting a new Director test cycle for origin: %s at %s", originName, originUrl))
				fileTests := utils.TestFileTransferImpl{}
				ok, err := fileTests.RunTests(ctx, originUrl, originUrl, "", utils.DirectorFileTest)
				if ok && err == nil {
					log.Debugln("Director file transfer test cycle succeeded at", time.Now().Format(time.UnixDate), " for origin: ", originUrl)
					if err := reportStatusToOrigin(ctx, originWebUrl, "ok", "Director test cycle succeeded at "+time.Now().Format(time.RFC3339)); err != nil {
						log.Warningln("Failed to report director test result to origin:", err)
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type), "status": string(metrics.FTXTestSucceeded), "report_status": string(metrics.FTXTestFailed),
							},
						).Inc()
					} else {
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type), "status": string(metrics.FTXTestSucceeded), "report_status": string(metrics.FTXTestSucceeded),
							},
						).Inc()
					}
				} else {
					log.Warningln("Director file transfer test cycle failed for origin: ", originUrl, " ", err)
					if err := reportStatusToOrigin(ctx, originWebUrl, "error", "Director file transfer test cycle failed for origin: "+originUrl+" "+err.Error()); err != nil {
						log.Warningln("Failed to report director test result to origin: ", err)
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type), "status": string(metrics.FTXTestFailed), "report_status": string(metrics.FTXTestFailed),
							},
						).Inc()
					} else {
						metrics.PelicanDirectorFileTransferTestsRuns.With(
							prometheus.Labels{
								"server_name": originName, "server_web_url": originWebUrl, "server_type": string(originAd.Type), "status": string(metrics.FTXTestFailed), "report_status": string(metrics.FTXTestSucceeded),
							},
						).Inc()
					}
				}

			}
		}
	})
}
