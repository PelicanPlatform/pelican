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
)

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
// Pass true to statusMismatch to allow a mismatch of expected status code and what's returned not fail immediately
func WaitUntilWorking(ctx context.Context, method, reqUrl, server string, expectedStatus int, statusMismatch bool) error {
	expiry := time.Now().Add(param.Server_StartupTimeout.GetDuration())
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	success := false
	logged := false
	var statusError error
	statusErrLogged := false

	for !(success || time.Now().After(expiry)) {
		select {
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, method, reqUrl, nil)
			if err != nil {
				return err
			}
			httpClient := http.Client{
				Transport: config.GetTransport(),
				Timeout:   1 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				if !logged {
					log.Infof("Failed to send request to %s at %s; likely server is not up (will retry in 50ms): %v", server, reqUrl, err)
					logged = true
				}
			} else {
				if resp.StatusCode == expectedStatus {
					log.Debugf("%s server appears to be functioning at %s", server, reqUrl)
					return nil
				}
				bytes, err := io.ReadAll(resp.Body)
				if err != nil {
					statusError = errors.Errorf("Received bad status code in reply to server ping at %s: %d. Expected %d. Can't read response body with error %v.", reqUrl, resp.StatusCode, expectedStatus, err)
					if statusMismatch {
						if !statusErrLogged {
							log.Info(statusError, "Will retry until timeout")
							statusErrLogged = true
						}
					} else {
						// We didn't get the expected status
						return statusError
					}
				} else {
					if len(bytes) != 0 {
						statusError = errors.Errorf("Received bad status code in reply to server ping at %s: %d. Expected %d. Response body: %s", reqUrl, resp.StatusCode, expectedStatus, string(bytes))
						if statusMismatch {
							if !statusErrLogged {
								log.Info(statusError, "Will retry until timeout")
								statusErrLogged = true
							}
						} else {
							// We didn't get the expected status
							return statusError
						}
					} else {
						statusError = errors.Errorf("Received bad status code in reply to server ping at %s: %d. Expected %d. Response body is empty.", reqUrl, resp.StatusCode, expectedStatus)
						if statusMismatch {
							if !statusErrLogged {
								log.Info(statusError, "Will retry until timeout")
								statusErrLogged = true
							}
						} else {
							return statusError
						}
					}
				}

			}
		case <-ctx.Done():
			if statusError != nil {
				return errors.Wrapf(statusError, "url %s didn't respond with the expected status code %d within %s", reqUrl, expectedStatus, param.Server_StartupTimeout.GetDuration().String())
			}
			return ctx.Err()
		}
	}

	if statusError != nil {
		return errors.Wrapf(statusError, "url %s didn't respond with the expected status code %d within 10s", reqUrl, expectedStatus)
	} else {
		return errors.Errorf("The %s server at %s either did not startup or did not respond quickly enough after %s of waiting", server, reqUrl, param.Server_StartupTimeout.GetDuration().String())
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
	ResetOriginExports()
	logging.ResetLogFlush()
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

		host := param.Server_Hostname.GetString()
		var adTok string
		if adTok, err = GetAdvertisementTok(server, directorUrl); err != nil {
			err = errors.Wrap(err, "failed to get advertisement token")
			continue
		}

		// The fed token endpoint wants to know the host and server type,
		// which it needs to verify the token
		params := url.Values{}
		params.Add("host", host)
		params.Add("sType", server.GetServerType().String())
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

	doLoadMonitoring := func(ctx context.Context) error {
		var concLimit int
		var paramName string
		if sType == server_structs.CacheType {
			concLimit = param.Cache_Concurrency.GetInt()
			paramName = param.Cache_Concurrency.GetName()
		} else if sType == server_structs.OriginType {
			concLimit = param.Origin_Concurrency.GetInt()
			paramName = param.Origin_Concurrency.GetName()
		}

		if concLimit <= 0 {
			return errors.Errorf("invalid config value: %s is %d. Must be greater than 0.", paramName, concLimit)
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

				qResult, err := QueryMyPrometheus(ctx, concQuery, true, sType.String())
				if err != nil {
					log.Errorf("Failed to query prometheus for current xrootd concurrency value; query: %s; error: %v", concQuery, err)
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
						if avgConc >= float64(concLimit) {
							log.Debugf("Putting IO Concurrency health status into degraded state; the average 1m concurrency value of %f is higher than the configured limit %d", avgConc, concLimit)
							metrics.SetComponentHealthStatus(metrics.OriginCache_IOConcurrency, metrics.StatusDegraded, "The server is currently experiencing more than its configured IO concurrency limit, performance may degraded")
						} else {
							log.Debugln("Putting IO Concurrency health status into OK state")
							metrics.SetComponentHealthStatus(metrics.OriginCache_IOConcurrency, metrics.StatusOK, "The server is within its configured IO concurrency limits")
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
