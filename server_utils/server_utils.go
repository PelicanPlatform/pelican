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

// Package server_utils shares utility functions used across multiple server packages (origin, cache, registry, director).
//
// It should only import lower level packages (config, param, etc), or server_structs package.
// It should never import any server packages (origin, cache, registry, director) or upper level packages (launcher_utils, cmd, etc).
//
// For structs used across multiple server packages, put them in common package instead
package server_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

var xrootdReset func()
var posixv2Reset func()
var brokerReset func()

// RegisterXrootdReset allows the xrootd package to provide a reset hook without introducing import cycles.
func RegisterXrootdReset(fn func()) {
	xrootdReset = fn
}

// RegisterPOSIXv2Reset allows the origin_serve package to provide a reset hook without introducing import cycles.
func RegisterPOSIXv2Reset(fn func()) {
	posixv2Reset = fn
}

// RegisterBrokerReset allows the broker package to provide a reset hook without introducing import cycles.
func RegisterBrokerReset(fn func()) {
	brokerReset = fn
}

// GetTopologyJSON returns the namespaces and caches from OSDF topology
func GetTopologyJSON(ctx context.Context) (*server_structs.TopologyNamespacesJSON, error) {
	topoNamespaceUrl := param.Federation_TopologyNamespaceUrl.GetString()
	if topoNamespaceUrl == "" {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Topology namespaces.json configuration option (`Federation.TopologyNamespaceURL`) not set")
		return nil, errors.New("Topology namespaces.json configuration option (`Federation.TopologyNamespaceURL`) not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, topoNamespaceUrl, nil)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when getting OSDF namespace data from topology")
		return nil, errors.Wrap(err, "Failure when getting OSDF namespace data from topology")
	}

	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()

	// Use the transport to include timeouts
	client := http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when getting response for OSDF namespace data")
		return nil, errors.Wrap(err, "Failure when getting response for OSDF namespace data")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, fmt.Sprintf("Error response %v from OSDF namespace endpoint: %v", resp.StatusCode, resp.Status))
		return nil, fmt.Errorf("error response %v from OSDF namespace endpoint: %v", resp.StatusCode, resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when reading OSDF namespace response")
		return nil, errors.Wrap(err, "Failure when reading OSDF namespace response")
	}

	var namespaces server_structs.TopologyNamespacesJSON
	if err = json.Unmarshal(respBytes, &namespaces); err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, fmt.Sprintf("Failure when parsing JSON response from topology URL %v", topoNamespaceUrl))
		return nil, errors.Wrapf(err, "Failure when parsing JSON response from topology URL %v", topoNamespaceUrl)
	}

	metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusOK, "")

	return &namespaces, nil
}

// Wait until given `reqUrl` returns the expected status.
// Logging messages emitted will refer to `server` (e.g., origin, cache, director)
// The `statusMismatch` param tells the probe not to fail immediately when a bad code is returned, useful
// when the probed endpoint may be able to respond before it's fully initialized.
func WaitUntilWorking(ctx context.Context, method, reqUrl, server string, expectedStatus int, statusMismatch bool) error {
	expiry := time.Now().Add(param.Server_StartupTimeout.GetDuration())
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()

	// We'll fire the test request every 50ms until it succeeds or generates an error
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastConnErr   error // keep track of the last encountered reason the client can't connect to the server
		lastStatusErr error // keep track error info related to status code mismatches
		loggedConn    bool  // only log errors the first time the ticker fires, not every 50ms
		loggedStatus  bool
	)

	// Helper function to handle request logic.
	// Has three return cases:
	// - Tern_True: the probe was successful and the calling function can safely return nil
	// - Tern_Unknown: the probe failed, but there is not yet an error to report because we'll keep trying
	// - Tern_False: the probe failed and we've decided not to continue trying. This indicates a startup failure
	// An error should only be returned alongside Tern_False.
	doRequest := func() (utils.Ternary, error) {
		req, err := http.NewRequestWithContext(ctx, method, reqUrl, nil)
		if err != nil {
			return utils.Tern_False, err
		}
		client := http.Client{
			Transport: config.GetTransport(),
			Timeout:   1 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			// Only record lastConnErr if it's not a context error or we haven't yet recorded any errors.
			// Otherwise we risk overwriting something useful like "no route to host" with a generic "context canceled".
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) || lastConnErr == nil {
				lastConnErr = err
			}
			if !loggedConn {
				log.Infof("Failed to send request to %s at %s; likely server is not up (will retry in 50ms): %v", server, reqUrl, err)
				loggedConn = true
			}
			return utils.Tern_Unknown, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == expectedStatus {
			log.Debugf("%s server appears to be functioning at %s", server, reqUrl)
			return utils.Tern_True, nil
		}

		body, readErr := io.ReadAll(resp.Body)
		var statusErr error
		if readErr != nil {
			statusErr = errors.Errorf("received bad status code from %s: %d (expected %d), and failed to read body: %v", reqUrl, resp.StatusCode, expectedStatus, readErr)
		} else if len(body) > 0 {
			statusErr = errors.Errorf("received bad status code from %s: %d (expected %d), body: %s", reqUrl, resp.StatusCode, expectedStatus, string(body))
		} else {
			statusErr = errors.Errorf("received bad status code from %s: %d (expected %d), empty body", reqUrl, resp.StatusCode, expectedStatus)
		}
		lastStatusErr = statusErr

		if statusMismatch {
			if !loggedStatus {
				log.Info(statusErr, "Will retry until timeout")
				loggedStatus = true
			}
			return utils.Tern_Unknown, nil
		}
		return utils.Tern_False, statusErr // fail immediately if status code mismatch is not permitted
	}

	// Main work loop to fire the test against the url
	for {
		select {
		case <-ticker.C:
			result, err := doRequest()
			switch result {
			case utils.Tern_True:
				return nil
			case utils.Tern_Unknown:
				// continue retrying until success or timeout
				continue
			case utils.Tern_False:
				if err != nil {
					return err // unrecoverable error, or we got a bad status code and statusMismatch is false
				} else {
					// We shouldn't get here because `doRequest` isn't setup to return a false with no
					// error, but just in case...
					return errors.New("unexpected result while testing server startup -- no error was provided, but the result was not a success")
				}
			}
		case <-ctx.Done():
			// Outside of context errors, there are two main classifications of errors we might see:
			// - We tried to connect but never succeeded (e.g. no route to host, TLS handshake failure, etc.)
			// - We connected but didn't get the expected response (e.g. wanted 200, got 403)
			msg := fmt.Sprintf("url %s didn't respond with the expected status code %d within the timeout of %s (%s)",
				reqUrl, expectedStatus, param.Server_StartupTimeout.GetDuration().String(), param.Server_StartupTimeout.GetName())
			if lastStatusErr != nil {
				return errors.Wrap(lastStatusErr, msg)
			}
			if lastConnErr != nil {
				return errors.Wrap(lastConnErr, msg)
			}
			return errors.Wrap(ctx.Err(), msg) // context was canceled or deadline exceeded
		}
	}
}

// Launch a maintenance goroutine.
// The maintenance routine will watch the directory `dirPath`, invoking `maintenanceFunc` whenever
// an event occurs in the directory.  Note the behavior of directory watching differs across platforms;
// for example, an atomic rename might be one or two events for the destination file depending on Mac OS X or Linux.
//
// Even if the filesystem watcher fails, this will invoke `maintenanceFunc` every `sleepTime` duration.
// The maintenance function will be called with `true` if invoked due to a directory change, false otherwise
// When generating error messages, `description` will be used to describe the task.
func LaunchWatcherMaintenance(ctx context.Context, dirPaths []string, description string, sleepTime time.Duration, maintenanceFunc func(notifyEvent bool) error) {
	select_count := 4
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warningf("%s routine failed to create new watcher", description)
		select_count -= 2
	} else {
		uniquePaths := map[string]bool{}
		for _, dirPath := range dirPaths {
			uniquePaths[dirPath] = true
		}
		for dirPath := range uniquePaths {
			if err = watcher.Add(dirPath); err != nil {
				log.Warningf("%s routine failed to add directory %s to watch: %v", description, dirPath, err)
				select_count -= 2
				break
			}
		}
	}
	cases := make([]reflect.SelectCase, select_count)
	ticker := time.NewTicker(sleepTime)
	cases[0].Dir = reflect.SelectRecv
	cases[0].Chan = reflect.ValueOf(ticker.C)
	cases[1].Dir = reflect.SelectRecv
	cases[1].Chan = reflect.ValueOf(ctx.Done())
	if err == nil {
		cases[2].Dir = reflect.SelectRecv
		cases[2].Chan = reflect.ValueOf(watcher.Events)
		cases[3].Dir = reflect.SelectRecv
		cases[3].Chan = reflect.ValueOf(watcher.Errors)
	}
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}
	egrp.Go(func() error {
		defer watcher.Close()
		defer ticker.Stop()
		for {
			chosen, recv, ok := reflect.Select(cases)
			if chosen == 0 {
				if !ok {
					return errors.Errorf("Ticker failed in the %s routine; exiting", description)
				}
				err := maintenanceFunc(false)
				if err != nil {
					log.Warningf("Failure during %s routine: %v", description, err)
				}
			} else if chosen == 1 {
				log.Infof("%s routine has been cancelled. Shutting down", description)
				return nil
			} else if chosen == 2 { // watcher.Events
				if !ok {
					return errors.Errorf("Watcher events failed in %s routine; exiting", description)
				}
				if event, ok := recv.Interface().(fsnotify.Event); ok {
					log.Debugf("Got filesystem event (%v); will run %s", event, description)
					err := maintenanceFunc(true)
					if err != nil {
						log.Warningf("Failure during %s routine: %v", description, err)
					}
				} else {
					return errors.New("Watcher returned an unknown event")
				}
			} else if chosen == 3 { // watcher.Errors
				if !ok {
					return errors.Errorf("Watcher error channel closed in %s routine; exiting", description)
				}
				if err, ok := recv.Interface().(error); ok {
					log.Errorf("Watcher failure in the %s routine: %v", description, err)
				} else {
					return errors.New("Watcher error channel has internal error; exiting")
				}
				time.Sleep(time.Second)
			}
		}
	})
}

// Reset the testing state, including:
// 1. viper settings, 2. preferred prefix, 3. transport object, 4. Federation metadata, 5. origin exports
func ResetTestState() {
	config.ResetConfig()
	param.ClearCallbacks()
	if xrootdReset != nil {
		xrootdReset()
	}
	if posixv2Reset != nil {
		posixv2Reset()
	}
	if brokerReset != nil {
		brokerReset()
	}
	ResetOriginExports()
	logging.ResetLogFlush()
	logging.ResetGlobalManager()
	baseAdOnce = sync.Once{}
	baseAd = server_structs.ServerBaseAd{}
	baseAdErr = nil
	directorEndpoints.Store(nil)
	if err := database.ShutdownDB(); err != nil {
		log.Errorf("Failed to shutdown the database: %v", err)
	}
}

// Given a slice of NamespaceAdV2 objects, return a slice of unique top-level prefixes.
//
// For example, given:
//   - /foo
//   - /foo/bar
//   - /foo/bar/baz
//   - /goo
//   - /some/path
//
// the function should return /foo, /goo, and /some/path.
func FilterTopLevelPrefixes(nsAds []server_structs.NamespaceAdV2) []server_structs.NamespaceAdV2 {
	prefixMap := make(map[string]server_structs.NamespaceAdV2)
	for _, nsAd := range nsAds {
		if !strings.HasSuffix(nsAd.Path, "/") {
			nsAd.Path = nsAd.Path + "/"
		}

		add := true
		for prefix := range prefixMap {
			if strings.HasPrefix(nsAd.Path, prefix) {
				add = false
				break
			}
			// Consider the case where we may have already added a longer path
			// and we need to remove it in favor of the shorter path
			if strings.HasPrefix(prefix, nsAd.Path) {
				delete(prefixMap, prefix)
			}
		}
		if add {
			prefixMap[nsAd.Path] = nsAd
		}
	}

	var uniquePrefixes []server_structs.NamespaceAdV2
	for _, nsAd := range prefixMap {
		uniquePrefixes = append(uniquePrefixes, nsAd)
	}
	return uniquePrefixes
}

// Get an advertisement token for the given server. Advertisement tokens are signed by the server
// and passed to the Director, which can then use them to check the server's identity. Tokens are
// valid when the Director can query the public key for the given server from the Registry.
func GetAdvertisementTok(server server_structs.XRootDServer, directorUrl string) (tok string, err error) {
	tokCfg, err := server.GetAdTokCfg(directorUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to get advertisement token configuration")
		return
	}

	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = tokCfg.Issuer
	advTokenCfg.AddAudiences(tokCfg.Audience)
	// RFC 7519, Section 4.1.2 indicates the "sub" claim MUST be unique within its issuer scope,
	// or better yet globally unique. Use the server's host:port to fulfill global uniqueness.
	advTokenCfg.Subject = tokCfg.Subject
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	tok, err = advTokenCfg.CreateToken()
	if err != nil {
		err = errors.Wrap(err, "failed to create director advertisement token")
	}

	return
}

// GetFedTok retrieves a federation token from the Director, which can be passed to other
// federation services as proof of federation membership.
func CreateFedTok(ctx context.Context, server server_structs.XRootDServer) (tok string, err error) {
	// Note: This is iterating over advertisements for _Directors_, not for Origins/Caches at a specific Director
	// (the function naming is a bit confusing, but `GetDirectorAds` does not get ads from a Director, it gets all the
	// known advertisements _of_ Directors in a HA setup)
	for _, ad := range GetDirectorAds() {
		directorUrl := ad.AdvertiseUrl
		var directorEndpoint string
		if directorEndpoint, err = url.JoinPath(directorUrl, "api", "v1.0", "director", "getFedToken"); err != nil {
			err = errors.Wrap(err, "unable to join director url")
			continue
		}
		var query *url.URL
		if query, err = url.Parse(directorEndpoint); err != nil {
			err = errors.Wrap(err, "the configured Director URL appears malformed")
			continue
		}

		var adTok string
		if adTok, err = GetAdvertisementTok(server, directorUrl); err != nil {
			err = errors.Wrap(err, "failed to get advertisement token")
			continue
		}

		// NOTE: The first implementation of this always used the hostname in the query
		// parameter, but this prevented the Director from validating advertise tokens from
		// services registered under their 'Xrootd.Sitename`
		var registrationName string
		sType := server.GetServerType()
		if sType == server_structs.OriginType {
			registrationName = param.Server_Hostname.GetString()
		} else if sType == server_structs.CacheType {
			// Note that the default value for `Xrootd.Sitename` is the hostname
			// Thus, if no sitename is set, this behaves the same as origins
			registrationName = param.Xrootd_Sitename.GetString()
		} else {
			return "", errors.New("attempted to get a federation token for a server that is not an origin or cache")
		}

		// The fed token endpoint wants to know the host (registration name) and server type,
		// which it needs to verify the token
		params := url.Values{}
		params.Add("host", registrationName)
		params.Add("sType", sType.String())
		query.RawQuery = params.Encode()

		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, "GET", query.String(), nil); err != nil {
			err = errors.Wrap(err, "failed to create the request to get a federation token")
			continue
		}
		req.Header.Set("Authorization", "Bearer "+adTok)
		userAgent := "pelican-" + strings.ToLower(server.GetServerType().String()) + "/" + config.GetVersion()
		req.Header.Set("User-Agent", userAgent)

		tr := config.GetTransport()
		client := http.Client{Transport: tr}

		var resp *http.Response
		if resp, err = client.Do(req); err != nil {
			err = errors.Wrap(err, "failed to start the request for director advertisement")
			continue
		}
		defer resp.Body.Close()

		var body []byte
		if body, err = io.ReadAll(resp.Body); err != nil {
			err = errors.Wrap(err, "failed to read the response body for director advertisement")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// Unmarshal the body as a simple api response
			var apiResp server_structs.SimpleApiResp
			if err = json.Unmarshal(body, &apiResp); err != nil {
				err = errors.Wrap(err, "failed to unmarshal error response from Director's federation token endpoint")
				continue
			}

			err = errors.New(apiResp.Msg)
			continue
		}

		// Attempt to unmarshal the body into our token struct
		var tokResponse server_structs.TokenResponse
		if err = json.Unmarshal(body, &tokResponse); err != nil {
			// Check for a simple api error response
			var apiResp server_structs.SimpleApiResp
			if err = json.Unmarshal(body, &apiResp); err == nil {
				err = errors.New(apiResp.Msg)
				continue
			}

			err = errors.Wrap(err, "failed to unmarshal the response body for director advertisement")
			continue
		}

		return tokResponse.AccessToken, nil
	}
	if err == nil {
		err = errors.New("unknown error when retrieving a federation token")
	}
	return
}

// SetFedTok does an atomic write of a federation token to the server's token location.
func SetFedTok(ctx context.Context, server server_structs.XRootDServer, tok string) error {
	tokLoc := server.GetFedTokLocation()
	if tokLoc == "" {
		return errors.New("token location is empty")
	}

	dir := filepath.Dir(tokLoc)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrap(err, "failed to create fed token directories")
	}

	// Create a temporary file for storing the token. Later we'll do an atomic rename
	filenamePattern := fmt.Sprintf(".fedtoken.%d.*", time.Now().UnixNano())
	tmpFile, err := os.CreateTemp(dir, filenamePattern)
	if err != nil {
		return errors.Wrap(err, "failed to create temporary token file")
	}
	tmpName := tmpFile.Name()

	defer func() {
		tmpFile.Close()
		os.Remove(tmpName)
	}()

	// Change ownership to xrootd user
	uid, err := config.GetDaemonUID()
	if err != nil {
		return errors.Wrap(err, "failed to get daemon UID")
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to get daemon GID")
	}

	if err := os.Chown(tmpName, uid, gid); err != nil {
		return errors.Wrapf(err, "failed to change token file ownership of %s to %d:%d", tmpName, uid, gid)
	}

	if _, err := tmpFile.WriteString(tok); err != nil {
		return errors.Wrap(err, "failed to write token to temporary file")
	}

	if err := tmpFile.Sync(); err != nil {
		return errors.Wrap(err, "failed to sync token file")
	}

	if err := tmpFile.Close(); err != nil {
		return errors.Wrap(err, "failed to close temporary token file")
	}

	if err := os.Rename(tmpName, tokLoc); err != nil {
		return errors.Wrap(err, "failed to move token file to final location")
	}

	return nil
}

// Launch the origin/cache's concurrency monitoring routine
//
// The routine periodically scrapes the servers own prometheus endpoint to gather information
// about the IO concurrency it's seen over the last period. This is used to set a health status
// that gets reported to the Director, which can help inform the Director whether it needs to
// cool down redirects to the server.
func LaunchConcurrencyMonitoring(ctx context.Context, egrp *errgroup.Group, sType server_structs.ServerType) {
	if !param.Monitoring_EnablePrometheus.GetBool() {
		log.Infoln("Prometheus is not enabled, skipping IO concurrency monitoring")
		return
	}

	doLoadMonitoring := func(ctx context.Context) error {
		var concParam param.IntParam
		var concThresholdParam param.IntParam
		switch sType {
		case server_structs.CacheType:
			concParam = param.Cache_Concurrency
			concThresholdParam = param.Cache_ConcurrencyDegradedThreshold
		case server_structs.OriginType:
			concParam = param.Origin_Concurrency
			concThresholdParam = param.Origin_ConcurrencyDegradedThreshold
		default:
			return errors.New("concurrency monitoring can only be launched for Origin or Cache servers")
		}

		// Although these values should be validated at startup, double check here in case
		// this is being invoked by a test that doesn't properly init config.
		concLimit := concParam.GetInt()
		concThreshold := concThresholdParam.GetInt()
		if concLimit <= 0 {
			return errors.Errorf("invalid config value: %s is %d. Must be greater than 0", concParam.GetName(), concLimit)
		}
		if concThreshold < 0 || concThreshold > 100 {
			return errors.Errorf("invalid config value: %s is %d. Must be between 0 and 100", concThresholdParam.GetName(), concThreshold)
		}

		// TODO: Do we need to make this configurable?
		concQuery := `avg_over_time(xrootd_server_io_active[1m])`

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				log.Debug("Starting a new concurrency monitoring cycle")

				qResult, err := QueryMyPrometheus(ctx, concQuery)
				if err != nil {
					log.Errorf("Failed to query prometheus for current xrootd concurrency value; query: %s; error: %v", concQuery, err)
					continue
				}

				if qResult.ResultType != "vector" {
					log.Errorf("Failed to query prometheus for current xrootd concurrency value: Expected a vector but Prometheus returned response of type %s", qResult.ResultType)
					continue
				}
				for _, item := range qResult.Result {
					for _, pair := range item.Values {
						avgConc, err := strconv.ParseFloat(pair.Value, 64)
						if err != nil {
							log.Errorf("Could not parse Prometheus-supplied xrootd concurrency value %q as float: %v\n", pair.Value, err)
							continue
						}

						log.Tracef("Average 1m IO concurrency value from Prometheus is %.2f", avgConc)
						degradedThreshold := float64(concLimit) * (float64(concThreshold) / 100.0)
						if avgConc >= degradedThreshold {
							log.Debugf(
								"Entering degraded state: average 1m concurrency %.2f exceeds %.0f%% of configured limit (%d). Threshold: %.2f",
								avgConc, float64(concThreshold), concLimit, degradedThreshold,
							)
							metrics.SetComponentHealthStatus(
								metrics.OriginCache_IOConcurrency,
								metrics.StatusDegraded,
								fmt.Sprintf(
									"Concurrency %.2f exceeds degraded threshold (%.0f%% of limit %d = %.2f)",
									avgConc, float64(concThreshold), concLimit, degradedThreshold,
								),
							)
						} else {
							log.Debugf(
								"Concurrency OK: average 1m concurrency %.2f is below degraded threshold (%.0f%% of limit %d = %.2f)",
								avgConc, float64(concThreshold), concLimit, degradedThreshold,
							)
							metrics.SetComponentHealthStatus(
								metrics.OriginCache_IOConcurrency,
								metrics.StatusOK,
								fmt.Sprintf(
									"Concurrency %.2f is within threshold (%.0f%% of limit %d = %.2f)",
									avgConc, float64(concThreshold), concLimit, degradedThreshold,
								),
							)
						}
					}
				}
			}
		}
	}

	egrp.Go(func() error {
		return doLoadMonitoring(ctx)
	})
}
