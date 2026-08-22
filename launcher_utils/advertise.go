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

// Package launcher_utils contains utility functions for the [github.com/pelicanplatform/pelican/launcher] package.
//
// It should only be imported by the launchers package
// It should NOT be imported to any server packages (origin/cache/registry) or other lower level packages (config/utils/etc)
package launcher_utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type directorResponse struct {
	Error         string `json:"error"`
	ApprovalError bool   `json:"approval_error"`
}

// retryableAdError is a director response that says "not now" rather than
// "no": the ad was not accepted, but nothing about it was judged wrong.
//
// It exists because the cost of treating the two alike is asymmetric. A
// permanent rejection is worth reporting and waiting on; a director that is
// merely not ready yet -- one that has not finished fetching the allowed
// prefixes for caches, say -- clears in seconds, while waiting for the next
// advertisement cycle leaves the federation without this server for
// Server.AdvertisementInterval, a minute by default.
type retryableAdError struct {
	status     int
	retryAfter time.Duration
	msg        string
}

func (e *retryableAdError) Error() string {
	return fmt.Sprintf("director is not ready to accept this advertisement (HTTP %d): %s", e.status, e.msg)
}

// isRetryableAdStatus reports whether a status means "ask again shortly".
//
// Deliberately narrow: 503 is the director saying it is not ready, and 429 is
// it saying not so fast. Everything else -- including 500 -- is treated as a
// real failure, because retrying a genuinely broken director every couple of
// seconds only adds load to something already in trouble.
func isRetryableAdStatus(status int) bool {
	return status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests
}

// parseAdRetryAfter reads a Retry-After header expressed in whole seconds,
// which is the only form Pelican's own services send. An HTTP-date is valid
// per RFC 9110 but is not produced here, and an unparsable or absent value
// simply means "no hint" -- the caller supplies its own delay.
//
// The result is clamped so a hint cannot stall advertisement: a server that
// asks for an hour still gets asked again on the caller's schedule.
func parseAdRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 0 {
		return 0
	}
	hint := time.Duration(seconds) * time.Second
	if hint > maxAdRetryDelay {
		return maxAdRetryDelay
	}
	return hint
}

const (
	// adRetryAttempts is how many extra attempts a retryable rejection buys.
	// Small on purpose: this is here to ride out a director still starting up,
	// not to paper over one that is down. Once these are spent the ordinary
	// advertisement cycle takes over, which is the behavior that existed
	// before.
	adRetryAttempts = 3
	// defaultAdRetryDelay is used when the director sends no Retry-After.
	defaultAdRetryDelay = 2 * time.Second
	// maxAdRetryDelay caps both the hint and the default, keeping the whole
	// retry sequence far short of an advertisement interval.
	maxAdRetryDelay = 5 * time.Second
)

func doAdvertise(ctx context.Context, servers []server_structs.XRootDServer) {
	log.Debugf("About to advertise %d XRootD servers", len(servers))
	start := time.Now()

	err := Advertise(ctx, servers)
	// A director that answered "not yet" is worth asking again right away.
	// Without this the next attempt is a whole advertisement cycle out, so a
	// director that was starting up for a few seconds costs this server a
	// minute of not being matchmade -- the ad is simply missing from the
	// federation for that long.
	for attempt := 1; attempt <= adRetryAttempts; attempt++ {
		var retryable *retryableAdError
		if !errors.As(err, &retryable) {
			break
		}
		delay := retryable.retryAfter
		if delay <= 0 {
			delay = defaultAdRetryDelay
		}
		log.Infof("Director is not ready to accept the advertisement (%v); retrying in %v (attempt %d of %d)",
			retryable.msg, delay, attempt, adRetryAttempts)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			log.Debugln("Advertisement retry abandoned: context cancelled")
			return
		}
		err = Advertise(ctx, servers)
	}

	duration := time.Since(start)
	if err != nil {
		log.Warningf("XRootD server advertise failed (duration %s): %v", duration.String(), err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("XRootD server failed to advertise to the director: %v", err))
	} else {
		log.Debugf("XRootD server advertise successful (duration %v)", duration.String())
		metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
	}
}

// Launch periodic advertise of xrootd servers (origin and cache) to the director, in the errogroup
func LaunchPeriodicAdvertise(ctx context.Context, egrp *errgroup.Group, servers []server_structs.XRootDServer) error {
	metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusWarning, "First attempt to advertise to the director...")
	doAdvertise(ctx, servers)

	advertiseInterval := param.Server_AdvertisementInterval.GetDuration()
	if advertiseInterval > param.Server_AdLifetime.GetDuration()/3 {
		newInterval := param.Server_AdLifetime.GetDuration() / 3
		log.Warningln("The advertise interval", advertiseInterval.String(), "is set to above 1/3 of the ad lifetime.  Decreasing it to", newInterval.String())
		advertiseInterval = newInterval
	}

	shutdownAny := ctx.Value(director.AdvertiseShutdownKey)
	var shutdownChannel <-chan struct{} = nil
	if shutdownCtx, ok := shutdownAny.(context.Context); ok {
		shutdownChannel = shutdownCtx.Done()
	}

	ticker := time.NewTicker(advertiseInterval)
	egrp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-shutdownChannel:
				log.Infoln("Periodic advertise shut down on command")
				return nil
			case <-ticker.C:
				doAdvertise(ctx, servers)
			case <-ctx.Done():
				log.Infoln("Periodic advertisement loop has been terminated")
				return nil
			}
		}
	})

	return nil
}

// Advertise ONCE the xrootd servers (origin and cache) to the director
func Advertise(ctx context.Context, servers []server_structs.XRootDServer) error {
	var firstErr error
	for _, server := range servers {
		err := advertiseInternal(ctx, server)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func advertiseInternal(ctx context.Context, server server_structs.XRootDServer) error {
	metadata, err := server_utils.GetServerMetadata(ctx, server.GetServerType())
	if err != nil {
		return errors.Wrap(err, "failed to determine service name for advertising to director")
	}

	// Keep the server metadata in local database up to date
	if err = database.UpsertServerLocalMetadata(metadata); err != nil {
		return errors.Wrapf(err, "failed to upsert service name %s in local database", metadata.Name)
	}

	if err = server.GetNamespaceAdsFromDirector(); err != nil {
		return errors.Wrapf(err, "%s failed to get namespaceAds from the director", server.GetServerType())
	}
	serverUrl := param.Origin_Url.GetString()
	webUrl := param.Server_ExternalWebUrl.GetString()

	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		serverUrl = param.Cache_Url.GetString()
	}

	// Fetch server's active and future downtimes
	downtimes, err := database.GetIncompleteDowntimes(strings.ToLower(server.GetServerType().String()))
	if err != nil {
		return err
	}

	ad, err := server.CreateAdvertisement(metadata.Name, metadata.ID, serverUrl, webUrl, downtimes)
	if err != nil {
		return err
	}
	ad.Now = time.Now()

	body, err := json.Marshal(*ad)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to generate JSON description of %s", server.GetServerType()))
	}

	egrp := &errgroup.Group{}
	successCount := atomic.Int32{}
	for _, directorAd := range server_utils.GetDirectorAds() {
		adCopy := directorAd
		egrp.Go(func() error {
			directorUrlStr := adCopy.AdvertiseUrl
			if directorUrlStr == "" {
				return errors.New("Director endpoint URL is not known")
			}
			directorUrl, err := url.Parse(directorUrlStr)
			if err != nil {
				return errors.Wrap(err, "failed to parse Federation.DirectorURL")
			}

			directorUrl.Path = "/api/v1.0/director/register" + server.GetServerType().String()

			tok, err := server_utils.GetAdvertisementTok(server, directorUrlStr)
			if err != nil {
				return errors.Wrap(err, "failed to get advertisement token")
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, directorUrl.String(), bytes.NewBuffer(body))
			if err != nil {
				return errors.Wrap(err, "failed to create a POST request for director advertisement")
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			userAgent := "pelican-" + strings.ToLower(server.GetServerType().String()) + "/" + config.GetVersion()
			req.Header.Set("User-Agent", userAgent)

			tr := config.GetTransport()
			client := http.Client{Transport: tr}

			resp, err := client.Do(req)
			if err != nil {
				return errors.Wrap(err, "failed to start the request for director advertisement")
			}
			defer resp.Body.Close()

			respbody, err := io.ReadAll(resp.Body)
			if err != nil {
				return errors.Wrap(err, "failed to read the response body for director advertisement")
			}
			if resp.StatusCode > 299 {
				var respErr directorResponse
				if unmarshalErr := json.Unmarshal(respbody, &respErr); unmarshalErr != nil { // Error creating json
					return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(respbody))
				}
				if respErr.ApprovalError {
					// Removed the "Please contact admin..." section since the director now provides contact information
					return fmt.Errorf("the director rejected the server advertisement: %s", respErr.Error)
				}
				if respErr.Error != "" {
					return errors.Errorf("error during director advertisement: %v", respErr.Error)
				}
				var respSimpleError server_structs.SimpleApiResp
				if unmarshalErr := json.Unmarshal(respbody, &respSimpleError); unmarshalErr != nil { // Error creating json
					return errors.Wrapf(unmarshalErr, "could not decode the director's response, which responded %v from director advertisement: %s", resp.StatusCode, string(respbody))
				}
				log.Warningln("Error response from", directorUrl.String(), "status:", resp.StatusCode, "message:", respSimpleError.Msg)
				if isRetryableAdStatus(resp.StatusCode) {
					// Keep the status and any hint, so the caller can tell
					// "not yet" from "no" instead of waiting a full cycle.
					return &retryableAdError{
						status:     resp.StatusCode,
						retryAfter: parseAdRetryAfter(resp.Header.Get("Retry-After")),
						msg:        respSimpleError.Msg,
					}
				}
				return errors.Errorf("error during director advertisement: %v", respSimpleError.Msg)
			}
			successCount.Add(1)
			return nil
		})
	}
	// If at least one advertise succeeded, we're good
	err = egrp.Wait()
	if successCount.Load() > 0 {
		return nil
	}
	return err
}
