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

package director

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

type filterType string

const (
	permFiltered     filterType = "permFiltered"     // Read from Director.FilteredServers
	tempFiltered     filterType = "tempFiltered"     // Filtered by web UI, e.g. the server is put in downtime via the director website
	serverFiltered   filterType = "serverFiltered"   // Filtered by the server itself, e.g. the server is put in downtime by the server admin
	shutdownFiltered filterType = "shutdownFiltered" // Filtered by the server itself to block new work during the pre-shutdown drain period
	topoFiltered     filterType = "topologyFiltered" // Filtered by Topology, e.g. the server is put in downtime via the OSDF Topology change
	tempAllowed      filterType = "tempAllowed"      // Read from Director.FilteredServers but mutated by web UI
)

var (
	// The in-memory cache of xrootd server advertisement, with the key being ServerAd.URL.String()
	serverAds = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](param.Director_AdvertisementTTL.GetDuration()),
		ttlcache.WithDisableTouchOnHit[string, *server_structs.Advertisement]())
	// The map holds servers that are disabled, with the key being the ServerAd.Name
	// The map should be idenpendent of serverAds as we want to persist this change in-memory, regardless of the presence of the serverAd
	filteredServers = map[string]filterType{}

	// A map of active and future downtimes set by server (Origin/Cache) admin, with the key being the ServerAd.Name
	serverDowntimes = make(map[string][]server_structs.Downtime)
	// A map of active and future downtimes set by topology, with the key being the ServerAd.Name
	topologyDowntimes = make(map[string][]server_structs.Downtime)
	// A map of active and future downtimes set by the federation admin, with the key being the ServerAd.Name
	federationDowntimes = make(map[string][]server_structs.Downtime)

	// Use a single mutex to protect four global maps
	filteredServersMutex = sync.RWMutex{}

	// The broker dialer we use to connect to services requiring a brokered connection.
	// Typically, this is for connecting to origins behind a firewall but can also be used
	// for contacting caches whose web port (necessary for Prometheus monitoring) is behind
	// a firewall.
	brokerDialer *broker.BrokerDialer = nil
)

func (f filterType) String() string {
	switch f {
	case permFiltered:
		return "Permanently Disabled via the director configuration"
	case tempFiltered:
		return "Temporarily disabled via the admin website"
	case serverFiltered:
		return "Temporarily disabled by the server admin"
	case shutdownFiltered:
		return "Disabled due to the server shutdown in progress"
	case topoFiltered:
		return "Disabled via the Topology policy"
	case tempAllowed:
		return "Temporarily enabled via the admin website"
	case "": // Here is to simplify the empty value at the UI side
		return ""
	default:
		return "Unknown Type"
	}
}

// Set the broker dialer to be used by the director
func SetBrokerDialer(dialer *broker.BrokerDialer) {
	brokerDialer = dialer
}

// Given a server status, return the raw weight that will eventually
// be smoothed in the EWMA status calculation.
// Weights should be bounded by (0, 1], where 1 does not adjust the
// server's ordering and 0 would stick the server at the very end of the list.
// However, 0 is not included because its multiplication with other load-based
// weights would destroy information.
func getRawStatusWeight(status metrics.HealthStatusEnum) float64 {
	// This weight is used when ordering servers on redirects,
	// and is only meant to _decrease_ a server's priority, never _increase_ it.
	// Since these weights are factored into sorting multiplicatively, we assign
	// "unknown" the multiplicative identity weight.
	//
	// There's an additional question about what to do here if the current status
	// is "unknown" but the previous ad had a known status -- should the status be
	// imputed, or should we default to 1? For now, it feels safer to make the choice
	// that doesn't affect sorting, thus "1".
	xt := 1.0
	if status <= metrics.StatusDegraded {
		// Set low weight for degraded or worse.
		// Note that this also covers StatusShuttingDown, although
		// that status is completely filtered via a different mechanism.
		xt = 0.01
	} else if status == metrics.StatusWarning {
		// Warnings may be unrelated to IO load, but it's still probably
		// not great to heavily weight servers reporting warnings.
		xt = 0.5
	}

	return xt
}

// populateEWMAStatusWeight calculates the EWMA status weight for a server advertisement.
// Each calculation needs several inputs that come from the previous and current server advertisements:
//   - The previously-derived EWMA status weight (st_1, from oldSAd)
//   - The current "server status" value (xt, derived from newSAd.Status) -- is bounded by (0, 1] because
//     0 would completely remove the server from sorting, while 1 has no effect on the server's priority.
//   - The time since the last status update (deltaT, derived from oldSAd.StatusWeightLastUpdate)
//
// For more information about EWMA calculations, see https://en.wikipedia.org/wiki/Exponential_smoothing
func populateEWMAStatusWeight(newSAd, oldSAd *server_structs.ServerAd) {
	if newSAd == nil {
		log.Errorf("internal error; populateEWMAStatusWeight called with nil newSAd")
		return
	}

	// Start building pieces from the server ads to apply an EWMA filter
	// to the server's status weight
	var statusWeight float64
	ioStatus := metrics.ParseHealthStatus(newSAd.Status)
	xt := getRawStatusWeight(ioStatus)
	t := time.Now()

	// If there is no existing ad, the weight is just the current status
	if oldSAd == nil {
		newSAd.StatusWeight = xt
		newSAd.StatusWeightLastUpdate = t.Unix()
		return
	}

	st_1 := oldSAd.StatusWeight
	// If we received an out-of-bounds previous status weight,
	// reset it to 1 -- This points to something having gone wrong,
	// so the safest choice is to avoid affecting the server's sorting.
	if st_1 <= 0 || st_1 > 1 {
		st_1 = 1.0
	}
	t_1 := oldSAd.StatusWeightLastUpdate
	deltaT := t.Sub(time.Unix(t_1, 0))
	if deltaT < 0 {
		log.Warningf("Negative deltaT detected while calculating EWMA status weight for server %s: %s (previous time: '%d', current time: '%d'). Resetting to 0.",
			newSAd.Name, deltaT.String(), t_1, t.Unix())
		deltaT = 0
	}

	// Using time constant of 5m based on some experimental hand tests -- this feels
	// reasonably responsive, whereas 10m felt like it overly smoothed things.
	tao := param.Director_AdaptiveSortEWMATimeConstant.GetDuration()
	if tao <= 0 {
		// This should never happen for real servers because config will re-set the value
		// to the default, but this if statement is in place for unit tests so we can
		// avoid dividing by zero without adding a bunch of extra config to tests.
		tao = 5 * time.Minute
	}
	alpha := 1 - math.Exp(-float64(deltaT)/float64(tao))

	// Calculate the new status weight using the EWMA formula
	statusWeight = st_1 + alpha*(xt-st_1)
	if statusWeight <= 0 || statusWeight > 1 {
		log.Errorf(
			"Invalid EWMA status weight for server '%s': computed=%f, previous=%f, raw weight=%f, current status='%s'. "+
				"Value should be in (0,1]. Resetting to 1.0 (will have no effect on sorting).",
			newSAd.Name, statusWeight, st_1, xt, newSAd.Status)
		statusWeight = 1.0
	}
	newSAd.StatusWeight = statusWeight
	newSAd.StatusWeightLastUpdate = t.Unix()

	metrics.PelicanDirectorStatusWeight.With(
		prometheus.Labels{
			"server_name": newSAd.Name,
			"server_url":  newSAd.AuthURL.String(),
			"server_type": newSAd.Type,
		},
	).Set(statusWeight)
}

// recordAd does following for an incoming ServerAd and []NamespaceAdV2 pair:
//
//  1. Update the ServerAd by setting server location and updating server topology attribute
//  2. Record the ServerAd and NamespaceAdV2 to the TTL cache
//  3. Set up the server `stat` call utilities
//  4. Set up utilities for collecting origin/health server file transfer test status
//  5. Return the updated ServerAd. The ServerAd passed in will not be modified
func recordAd(ctx context.Context, sAd server_structs.ServerAd, namespaceAds *[]server_structs.NamespaceAdV2) (updatedAd server_structs.ServerAd) {
	if err := updateLatLong(&sAd); err != nil {
		if geoIPError, ok := err.(geoIPError); ok {
			labels := geoIPError.labels
			// TODO: Remove this metric (the line directly below)
			// The renamed metric was added in v7.16
			metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
			metrics.PelicanDirectorGeoIPErrorsTotal.With(labels).Inc()
		}
		log.Debugln("Failed to lookup GeoIP coordinates for host", sAd.URL.Host)
	}

	if sAd.URL.String() == "" {
		log.Errorf("The URL of the serverAd %#v is empty. Cannot set the TTL cache.", sAd)
		return
	}
	// Since servers from topology always use http, while servers from Pelican always use https
	// we want to ignore the scheme difference when checking duplicates (only consider hostname:port)
	rawURL := sAd.URL.String() // could be http (topology) or https (Pelican or some topology ones)
	httpURL := sAd.URL.String()
	httpsURL := sAd.URL.String()
	if strings.HasPrefix(rawURL, "https") {
		httpURL = "http" + strings.TrimPrefix(rawURL, "https")
	}
	if strings.HasPrefix(rawURL, "http://") {
		httpsURL = "https://" + strings.TrimPrefix(rawURL, "http://")
	}

	// Although we're in `recordAd`, which implies we _DO_ plan to update the incoming
	// advertisement, it's better not to refresh the expiration until we explicitly intend to do so.
	existing := serverAds.Get(httpURL, ttlcache.WithDisableTouchOnHit[string, *server_structs.Advertisement]())
	if existing == nil {
		existing = serverAds.Get(httpsURL, ttlcache.WithDisableTouchOnHit[string, *server_structs.Advertisement]())
	}
	if existing == nil {
		existing = serverAds.Get(rawURL, ttlcache.WithDisableTouchOnHit[string, *server_structs.Advertisement]())
	}

	// There's an existing ad in the cache
	if existing != nil {
		if sAd.FromTopology && !existing.Value().FromTopology {
			// if the incoming is from topology but the existing is from Pelican
			log.Debugf("The ServerAd generated from topology with name %s and URL %s was ignored because there's already a Pelican ad for this server", sAd.Name, sAd.URL.String())
			return
		}
		if !sAd.FromTopology && existing.Value().FromTopology {
			// Pelican server will overwrite topology one. We leave a message to let admin know
			log.Debugf("The existing ServerAd generated from topology with name %s and URL %s is replaced by the Pelican server with name %s", existing.Value().Name, existing.Value().URL.String(), sAd.Name)
			serverAds.Delete(existing.Value().URL.String())
		}
		if !sAd.FromTopology && !existing.Value().FromTopology { // Only copy the IO Load value for Pelican server
			sAd.IOLoad = existing.Value().GetIOLoad() // we copy the value from the existing serverAD to be consistent
		}

		populateEWMAStatusWeight(&sAd, &(existing.Value().ServerAd))
	} else {
		// If there is no existing ad, the status weight will be set to the current raw weight
		populateEWMAStatusWeight(&sAd, nil)
	}

	ad := server_structs.Advertisement{ServerAd: sAd, NamespaceAds: *namespaceAds}

	adTTL := time.Until(sAd.Expiration)
	if sAd.Expiration.IsZero() {
		adTTL = param.Director_AdvertisementTTL.GetDuration()
		// Handle unit tests that do not initialize default config
		if adTTL == 0 {
			log.Info(param.Director_AdvertisementTTL.GetName(), "is set to 0; increasing to 15 minutes")
			adTTL = 15 * time.Minute
		}
	} else if adTTL <= 0 {
		return
	}

	serverAds.Set(ad.URL.String(), &server_structs.Advertisement{ServerAd: sAd, NamespaceAds: *namespaceAds}, adTTL)

	// Inform the global broker dialer about the new server ad
	if sAd.BrokerURL.Host != "" && brokerDialer != nil {
		sType := server_structs.NewServerType()
		sType.SetString(sAd.Type)
		brokerDialer.UseBroker(sType, sAd.WebURL.Host, sAd.BrokerURL.String())
		if sAd.Type == server_structs.OriginType.String() {
			brokerDialer.UseBroker(sType, sAd.URL.Host, sAd.BrokerURL.String())
		}
	}

	// Prepare `stat` call utilities for all servers regardless of its source (topology or Pelican)
	func() {
		statUtilsMutex.Lock()
		defer statUtilsMutex.Unlock()
		statUtil, ok := statUtils[ad.URL.String()]
		if !ok || statUtil.Errgroup == nil {
			baseCtx, cancel := context.WithCancel(ctx)
			concLimit := param.Director_StatConcurrencyLimit.GetInt()
			// If the value is not set or negative, then we provide a modest default;
			// we don't want to permit an unbounded number of queries due to potential
			// memory usage.
			if concLimit <= 0 {
				log.Warningln("Concurrency limit 'Director.StatConcurrencyLimit' must be positive; ignoring value", concLimit, "and using 100 instead")
				concLimit = 100
			}
			statErrGrp := utils.Group{}
			statErrGrp.SetLimit(concLimit)
			cap := param.Director_CachePresenceCapacity.GetInt()
			// Ensure the capacity is a positive integer; zero indicates
			// "unbounded" (bad) and a negative value gets cast to uint64,
			// becoming an effectively unbounded number (also bad)
			if cap <= 0 {
				log.Warningln("Object presence cache limit 'Director.CachePresenceCapacity' must be positive; ignoring value", cap, "and using 100 instead")
				cap = 100
			}
			newUtil := serverStatUtil{
				Errgroup: &statErrGrp,
				Cancel:   cancel,
				Context:  baseCtx,
				ResultCache: ttlcache.New(
					ttlcache.WithTTL[string, *objectMetadata](param.Director_CachePresenceTTL.GetDuration()),
					ttlcache.WithDisableTouchOnHit[string, *objectMetadata](),
					ttlcache.WithCapacity[string, *objectMetadata](uint64(cap)),
				),
			}
			log.Debugln("Creating a new stat cache with capacity", cap, "for endpoint ", ad.URL.String())
			// The result cache TTL is stopped when the `serverAds` struct is evicted.  This  occurs
			// when the server is cleanly shut down, preventing this goroutine from leaking.
			go newUtil.ResultCache.Start()
			statUtils[ad.URL.String()] = &newUtil
		}
	}()

	// We don't have health tests for the topology servers so just return
	if ad.FromTopology {
		return sAd
	}

	if ad.DisableDirectorTest {
		log.Debugf("%s server %s at %s has DisableDirectorTest set. Skip health test for this server.", ad.Type, ad.Name, ad.URL.String())
		return
	}

	// Prepare and launch the director file transfer tests to the origins/caches if it's not from the topology AND it's not already been registered
	func() {
		healthTestUtilsMutex.Lock()
		defer healthTestUtilsMutex.Unlock()

		if existingUtil, ok := healthTestUtils[ad.URL.String()]; ok {
			// Existing registration
			if existingUtil != nil {
				if existingUtil.ErrGrp != nil {
					if existingUtil.ErrGrpContext.Err() != nil {
						// ErrGroup has been Done. Start a new one
						errgrp, errgrpCtx := errgroup.WithContext(ctx)
						cancelCtx, cancel := context.WithCancel(errgrpCtx)

						errgrp.SetLimit(1)
						healthTestUtils[ad.URL.String()] = &healthTestUtil{
							Cancel:        cancel,
							ErrGrp:        errgrp,
							ErrGrpContext: errgrpCtx,
							Status:        HealthStatusInit,
						}
						errgrp.Go(func() error {
							LaunchPeriodicDirectorTest(cancelCtx, sAd)
							return nil
						})
						log.Debugf("New director test suite issued for %s %s. Errgroup was evicted", string(ad.Type), ad.URL.String())
					} else {
						// Existing errorgroup still working
						cancelCtx, cancel := context.WithCancel(existingUtil.ErrGrpContext)
						started := existingUtil.ErrGrp.TryGo(func() error {
							LaunchPeriodicDirectorTest(cancelCtx, sAd)
							return nil
						})
						if !started {
							cancel()
							log.Debugf("New director test suite blocked for %s %s, existing test has been running", string(ad.Type), ad.URL.String())
						} else {
							log.Debugf("New director test suite issued for %s %s. Existing registration", string(ad.Type), ad.URL.String())
							existingUtil.Cancel()
							existingUtil.Cancel = cancel
						}
					}
				} else {
					log.Errorf("%s %s registration didn't start a new director test cycle: errgroup is nil", string(ad.Type), &ad.URL)
				}
			} else {
				log.Errorf("%s %s registration didn't start a new director test cycle: healthTestUtils item is nil", string(ad.Type), &ad.URL)
			}
		} else { // No healthTestUtils found, new registration
			errgrp, errgrpCtx := errgroup.WithContext(ctx)
			cancelCtx, cancel := context.WithCancel(errgrpCtx)

			errgrp.SetLimit(1)
			healthTestUtils[ad.URL.String()] = &healthTestUtil{
				Cancel:        cancel,
				ErrGrp:        errgrp,
				ErrGrpContext: errgrpCtx,
				Status:        HealthStatusInit,
			}
			errgrp.Go(func() error {
				LaunchPeriodicDirectorTest(cancelCtx, sAd)
				return nil
			})
		}
	}()

	return sAd
}

func updateLatLong(ad *server_structs.ServerAd) error {
	if ad == nil {
		return errors.New("Cannot provide a nil ad to UpdateLatLong")
	}
	hostname := strings.Split(ad.URL.Host, ":")[0]
	ip, err := net.LookupIP(hostname)
	if err != nil {
		return err
	}
	if len(ip) == 0 {
		return fmt.Errorf("unable to find an IP address for hostname %s", hostname)
	}
	addr, ok := netip.AddrFromSlice(ip[0])
	if !ok {
		return errors.New("Failed to create address object from IP")
	}
	// NOTE: If GeoIP resolution of this address fails, lat/long are set to 0.0 (the null lat/long)
	// This causes the server to be sorted to the end of the list whenever the Director requires distance-aware sorting.
	lat, long, _, err := getLatLong(addr)
	if err != nil {
		return err
	}
	ad.Latitude = lat
	ad.Longitude = long
	return nil
}

// Get cached downtimes from registry, topology and servers themselves.
// Return downtimes for all servers or a specific server if serverName is provided.
func getCachedDowntimes(serverName string) ([]server_structs.Downtime, error) {
	filteredServersMutex.RLock()
	defer filteredServersMutex.RUnlock()

	// helper to collect one server's downtimes
	collect := func(name string) []server_structs.Downtime {
		out := make([]server_structs.Downtime, 0)
		if list, ok := serverDowntimes[name]; ok {
			out = append(out, list...)
		}
		if list, ok := topologyDowntimes[name]; ok {
			out = append(out, list...)
		}
		if list, ok := federationDowntimes[name]; ok {
			out = append(out, list...)
		}
		return out
	}

	if serverName != "" {
		return collect(serverName), nil
	}

	// If no serverName is provided, return downtimes for all servers
	seen := map[string]struct{}{}
	for name := range serverDowntimes {
		seen[name] = struct{}{}
	}
	for name := range topologyDowntimes {
		seen[name] = struct{}{}
	}
	for name := range federationDowntimes {
		seen[name] = struct{}{}
	}

	result := make([]server_structs.Downtime, 0)
	for name := range seen {
		result = append(result, collect(name)...)
	}

	return result, nil
}

// Get the downtimes set by federation admin in the Registry
func updateDowntimeFromRegistry(ctx context.Context) error {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil || fedInfo.RegistryEndpoint == "" {
		log.Error("Failed to get federation info: ", err)
		return errors.Wrap(err, "failed to get federation info")
	}

	registryEndpointURL, err := url.Parse(fedInfo.RegistryEndpoint)
	if err != nil {
		log.Error("Failed to parse registry endpoint URL: ", err)
		return errors.Wrap(err, "failed to parse registry endpoint URL")
	}

	// Construct the registry downtime list URL to get active and future downtimes
	registryEndpointURL.Path = path.Join(registryEndpointURL.Path, "api", "v1.0", "downtime")
	// Set the query parameter "source" to the Registry.
	q := registryEndpointURL.Query()
	q.Set("source", strings.ToLower(server_structs.RegistryType.String()))
	registryEndpointURL.RawQuery = q.Encode()

	registryDowntimeListURL := registryEndpointURL.String()

	tr := config.GetTransport()
	respData, err := utils.MakeRequest(ctx, tr, registryDowntimeListURL, "GET", nil, nil)
	if err != nil {
		log.Error("Failed to get live servers from the director: ", err)
		return errors.Wrap(err, "failed to get live servers from the director")
	}
	var latestFedDowntimes []server_structs.Downtime
	err = json.Unmarshal(respData, &latestFedDowntimes)
	if err != nil {
		log.Errorf("Failed to marshal response in to JSON: %v", err)
		return errors.Wrap(err, "failed to marshal response in to JSON")
	}

	// If `latestFedDowntimes` is empty, it means there's no downtime set by federation admin,
	// or the downtime is expired (deleted). In either case, we still need to proceed to use
	// it to update `filteredServers` and `federationDowntimes`, clearing out stale info.

	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	// In the Registry, downtime.serverName is prefix, not server name (because Registry doesn't know the server name)
	// So we need to find its corresponding server name in the serverAds and use it to overwrite downtime.serverName

	ads := serverAds.Items() // pull the ads slice once
	// Build a prefix→name map
	prefixToName := make(map[string]string, len(ads))
	for _, ad := range ads {
		prefixToName[ad.Value().RegistryPrefix] = ad.Value().Name
	}
	var runningServersDowntimes []server_structs.Downtime
	for i := 0; i < len(latestFedDowntimes); i++ {
		name, found := prefixToName[latestFedDowntimes[i].ServerName]
		if !found {
			log.Infof("Unable to find server name for prefix %s in the Director. The server with the given prefix is not running now.", latestFedDowntimes[i].ServerName)
			continue
		}
		latestFedDowntimes[i].ServerName = name
		runningServersDowntimes = append(runningServersDowntimes, latestFedDowntimes[i])
	}

	// Remove existing filteredSevers that are fetched from the Registry first
	for key, val := range filteredServers {
		if val == tempFiltered {
			delete(filteredServers, key)
		}
	}

	// Build a new map to replace the in-memory federationDowntimes map
	newFederationDowntimes := make(map[string][]server_structs.Downtime)
	currentTime := time.Now().UTC().UnixMilli()

	for _, downtime := range runningServersDowntimes {
		// Save all active and future downtimes to the new map
		newFederationDowntimes[downtime.ServerName] = append(newFederationDowntimes[downtime.ServerName], downtime)

		// Check existing downtime filter
		originalFilterType, hasOriginalFilter := filteredServers[downtime.ServerName]
		// If this server is already put in downtime, we don't need to do anything to the filteredServers map
		if hasOriginalFilter && originalFilterType != tempAllowed {
			continue
		}
		// Otherwise, if it is an active downtime, we need to put it into the filteredServers map
		if currentTime >= downtime.StartTime && (currentTime <= downtime.EndTime || downtime.EndTime == -1) {
			filteredServers[downtime.ServerName] = tempFiltered
		}
	}

	// Overwrite the in-memory federationDowntimes map with the new data.
	federationDowntimes = newFederationDowntimes
	return nil
}

// Periodically fetch the downtimes set by Federation admin in the Registry
func PeriodicFedDowntimeReload(ctx context.Context, egrp *errgroup.Group) {
	refreshInterval := param.Director_RegistryQueryInterval.GetDuration()
	ticker := time.NewTicker(refreshInterval)

	if err := updateDowntimeFromRegistry(ctx); err != nil {
		log.Errorf("Failed to fetch the downtimes set by federation admin from the Registry: %v", err)
	}
	log.Debug("Federation downtimes updated successfully")

	egrp.Go(func() error {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := updateDowntimeFromRegistry(ctx)
				if err != nil {
					log.Errorf("Failed to fetch the downtimes set by federation admin from the Registry: %v", err)
				}
				log.Debug("Federation downtimes updated successfully")
			case <-ctx.Done():
				log.Debug("Periodic fetch for federation downtimes terminated")
				return nil
			}
		}
	})
}

// Clears the in-memory cache of server ads
func ClearServerAds() {
	serverAds.DeleteAll()
}

// init registers the director ClearServerAds function with the config package
func init() {
	config.ClearServerAdsCallback = ClearServerAds
}
