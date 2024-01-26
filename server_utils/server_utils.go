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

package server_utils

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// Wait until given `reqUrl` returns a HTTP 200.
// Logging messages emitted will refer to `server` (e.g., origin, cache, director)
func WaitUntilWorking(ctx context.Context, method, reqUrl, server string, expectedStatus int) error {
	expiry := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	success := false
	logged := false
	for !(success || time.Now().After(expiry)) {
		select {
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, method, reqUrl, nil)
			if err != nil {
				return err
			}
			httpClient := http.Client{
				Transport: config.GetTransport(),
				Timeout:   50 * time.Millisecond,
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				if !logged {
					log.Infoln("Failed to send request to "+server+"; likely server is not up (will retry in 50ms):", err)
					logged = true
				}
			} else {
				if resp.StatusCode == expectedStatus {
					log.Debugln(server + " server appears to be functioning")
					return nil
				}
				// We didn't get the expected status
				return errors.Errorf("Received bad status code in reply to server ping: %d. Expected %d,", resp.StatusCode, expectedStatus)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return errors.Errorf("Server %s at %s did not startup after 10s of waiting", server, reqUrl)
}

// For calling from within the server. Returns the server's issuer URL/port
func GetServerIssuerURL() (*url.URL, error) {
	if param.Server_IssuerUrl.GetString() == "" {
		return nil, errors.New("The server failed to determine its own issuer url. Something is wrong!")
	}

	issuerUrl, err := url.Parse(param.Server_IssuerUrl.GetString())
	if err != nil {
		return nil, errors.Wrapf(err, "The server's issuer URL is malformed: %s. Something is wrong!", param.Server_IssuerUrl.GetString())
	}

	return issuerUrl, nil
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
