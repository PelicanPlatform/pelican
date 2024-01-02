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
	"net/url"
	"reflect"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

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
func LaunchWatcherMaintenance(ctx context.Context, dirPath string, description string, sleepTime time.Duration, maintenanceFunc func(notifyEvent bool) error) {
	select_count := 4
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warningf("%s routine failed to create new watcher", description)
		select_count -= 2
	} else if err = watcher.Add(dirPath); err != nil {
		log.Warningf("%s routine failed to add directory %s to watch: %v", description, dirPath, err)
		select_count -= 2
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
	go func() {
		defer watcher.Close()
		for {
			chosen, recv, ok := reflect.Select(cases)
			if chosen == 0 {
				if !ok {
					log.Panicf("Ticker failed in the %s routine; exiting", description)
				}
				err := maintenanceFunc(false)
				if err != nil {
					log.Warningf("Failure during %s routine: %v", description, err)
				}
			} else if chosen == 1 {
				log.Infof("%s routine has been cancelled.  Shutting down", description)
				return
			} else if chosen == 2 { // watcher.Events
				if !ok {
					log.Panicf("Watcher events failed in %s routine; exiting", description)
				}
				if event, ok := recv.Interface().(fsnotify.Event); ok {
					log.Debugf("Got filesystem event (%v); will run %s", event, description)
					err := maintenanceFunc(true)
					if err != nil {
						log.Warningf("Failure during %s routine: %v", description, err)
					}
				} else {
					log.Panicln("Watcher returned an unknown event")
				}
			} else if chosen == 3 { // watcher.Errors
				if !ok {
					log.Panicf("Watcher error channel closed in %s routine; exiting", description)
				}
				if err, ok := recv.Interface().(error); ok {
					log.Errorf("Watcher failure in the %s routine: %v", description, err)
				} else {
					log.Panicln("Watcher error channel has internal error; exiting")
				}
				time.Sleep(time.Second)
			}
		}
	}()
}
