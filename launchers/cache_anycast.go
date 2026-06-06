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

package launchers

import (
	"context"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache/bgp_advertise"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

// anycastConfigFromParams assembles the BGP advertiser configuration from the
// Cache.Anycast.* parameters, applying defaults (the cache's external web URL as
// the probe target) where appropriate.
func anycastConfigFromParams() (bgp_advertise.Config, string, error) {
	probeURL := param.Cache_Anycast_ProbeUrl.GetString()
	if probeURL == "" {
		probeURL = param.Server_ExternalWebUrl.GetString()
	}
	cfg := bgp_advertise.Config{
		RouterID:     param.Cache_Anycast_BGP_RouterID.GetString(),
		LocalASN:     uint32(param.Cache_Anycast_BGP_LocalASN.GetInt()),
		PeerAddress:  param.Cache_Anycast_BGP_PeerAddress.GetString(),
		PeerASN:      uint32(param.Cache_Anycast_BGP_PeerASN.GetInt()),
		LocalAddress: param.Cache_Anycast_BGP_LocalAddress.GetString(),
		Port:         uint32(param.Cache_Anycast_BGP_Port.GetInt()),
		Password:     param.Cache_Anycast_BGP_Password.GetString(),
		NextHop:      param.Cache_Anycast_NextHop.GetString(),
		Routes:       param.Cache_Anycast_Routes.GetStringSlice(),
	}
	if err := cfg.Validate(); err != nil {
		return cfg, probeURL, err
	}
	if param.Cache_Anycast_Hostname.GetString() == "" {
		return cfg, probeURL, errors.New("Cache.Anycast.Hostname must be set when anycast is enabled")
	}
	if probeURL == "" {
		return cfg, probeURL, errors.New("Cache.Anycast.ProbeUrl (or Server.ExternalWebUrl) must be set when anycast is enabled")
	}
	return cfg, probeURL, nil
}

// cacheHealthyExcludingAnycast reports whether every reported health component
// other than the anycast component itself is OK.  The anycast component is
// excluded to avoid a feedback loop: the advertiser sets the anycast component's
// status to reflect whether it is advertising, so including it in the decision
// of whether to advertise would be self-referential.
func cacheHealthyExcludingAnycast() bool {
	status := metrics.GetHealthStatus()
	if len(status.ComponentStatus) == 0 {
		return false
	}
	for component, compStatus := range status.ComponentStatus {
		if component == metrics.Cache_Anycast {
			continue
		}
		if compStatus.Status != metrics.StatusOK.String() {
			return false
		}
	}
	return true
}

// LaunchAnycastAdvertiser starts the TCP-anycast BGP advertiser for the cache
// when Cache.Anycast.Enable is set.  It runs a periodic loop that advertises the
// configured routes while the cache is healthy and serving a certificate with
// the expected anycast hostname as a SAN, and withdraws them otherwise.  The
// advertiser and its routes are torn down when ctx is cancelled.
//
// Anycast is only supported by the persistent (V2) cache; the caller must not
// invoke this for the XRootD cache.
func LaunchAnycastAdvertiser(ctx context.Context, egrp *errgroup.Group) error {
	cfg, probeURL, err := anycastConfigFromParams()
	if err != nil {
		return errors.Wrap(err, "invalid anycast configuration")
	}
	expectedSAN := param.Cache_Anycast_Hostname.GetString()

	advertiser, err := bgp_advertise.New(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to create anycast advertiser")
	}
	if err := advertiser.Start(ctx); err != nil {
		return errors.Wrap(err, "failed to start anycast advertiser")
	}

	metrics.SetComponentHealthStatus(metrics.Cache_Anycast, metrics.StatusWarning,
		"Anycast advertiser started; routes not yet advertised")

	interval := param.Cache_Anycast_ProbeInterval.GetDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	// evaluate runs the health + SAN check and (re)advertises or withdraws.
	evaluate := func() {
		healthy := cacheHealthyExcludingAnycast()
		var sanErr error
		if healthy {
			sanErr = bgp_advertise.VerifyCertSAN(ctx, probeURL, expectedSAN)
		}

		if healthy && sanErr == nil {
			if err := advertiser.Advertise(ctx); err != nil {
				log.WithError(err).Error("Failed to advertise anycast routes")
				metrics.SetComponentHealthStatus(metrics.Cache_Anycast, metrics.StatusCritical,
					"Failed to advertise anycast routes: "+err.Error())
				return
			}
			metrics.SetComponentHealthStatus(metrics.Cache_Anycast, metrics.StatusOK,
				"Advertising anycast routes")
			return
		}

		// Not eligible to advertise: withdraw if we were.
		if err := advertiser.Withdraw(ctx); err != nil {
			log.WithError(err).Error("Failed to withdraw anycast routes")
		}
		reason := "Cache is not healthy; anycast routes withdrawn"
		if !healthy {
			metrics.SetComponentHealthStatus(metrics.Cache_Anycast, metrics.StatusWarning, reason)
		} else {
			reason = "Host certificate SAN check failed; anycast routes withdrawn: " + sanErr.Error()
			metrics.SetComponentHealthStatus(metrics.Cache_Anycast, metrics.StatusWarning, reason)
		}
		log.Debug(reason)
	}

	egrp.Go(func() error {
		defer func() {
			if err := advertiser.Close(); err != nil {
				log.WithError(err).Warn("Error closing anycast advertiser")
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// Run an initial evaluation immediately rather than waiting a full interval.
		evaluate()
		for {
			select {
			case <-ticker.C:
				evaluate()
			case <-ctx.Done():
				return nil
			}
		}
	})

	log.WithField("routes", cfg.Routes).WithField("peer", cfg.PeerAddress).
		Info("Launched TCP anycast BGP advertiser")
	return nil
}
