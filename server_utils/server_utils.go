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

// Package server_utils shares utility functions used across multiple server pacakges (origin, cache, registry, director).
//
// It should only import lower level packages (config, param, etc), or server_structs package.
// It should never import any server pacakges (origin, cache, registry, director) or upeer level packages (launcher_utils, cmd, etc).
//
// For structs used across multiple server pacakges, put them in common package instead
package server_utils

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
)

// Wait until given `reqUrl` returns the expected status.
// Logging messages emitted will refer to `server` (e.g., origin, cache, director)
// Pass true to statusMismatch to allow a mismatch of expected status code and what's returned not fail immediately
func WaitUntilWorking(ctx context.Context, method, reqUrl, server string, expectedStatus int, statusMismatch bool) error {
	expiry := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
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
				return errors.Wrapf(statusError, "url %s didn't respond with the expected status code %d within 10s", reqUrl, expectedStatus)
			}
			return ctx.Err()
		}
	}

	if statusError != nil {
		return errors.Wrapf(statusError, "url %s didn't respond with the expected status code %d within 10s", reqUrl, expectedStatus)
	} else {
		return errors.Errorf("The %s server at %s either did not startup or did not respond quickly enough after 10s of waiting", server, reqUrl)
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
