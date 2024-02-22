/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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

package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/sync/errgroup"
)

type (
	progressStatus struct {
		xfer      int64 // Number of bytes transferred
		size      int64 // Total size of object to move
		completed bool  // Whether the object is complete
	}

	progressBar struct {
		progressStatus
		bar *mpb.Bar
	}

	progressBars struct {
		lock   sync.RWMutex
		done   chan bool
		status map[string]progressStatus
		egrp   *errgroup.Group
	}
)

func newProgressBar() *progressBars {
	return &progressBars{
		done:   make(chan bool),
		status: make(map[string]progressStatus),
	}
}

func (pb *progressBars) callback(path string, xfer int64, size int64, completed bool) {
	pb.lock.Lock()
	defer pb.lock.Unlock()
	stat := pb.status[path]
	stat.completed = completed
	stat.size = size
	stat.xfer = xfer
	pb.status[path] = stat
}

func (pb *progressBars) shutdown() {
	if pb.egrp != nil {
		pb.done <- true
		if err := pb.egrp.Wait(); err != nil {
			log.Debugln("Failure to shut down progress bar:", err)
		}
	}
}

func (pb *progressBars) launchDisplay(ctx context.Context) {
	progressCtr := mpb.NewWithContext(ctx)
	log.SetOutput(progressCtr)
	pb.egrp, _ = errgroup.WithContext(ctx)
	log.Debugln("Launch progress bars display")

	pb.egrp.Go(func() error {
		defer func() {
			log.SetOutput(os.Stdout)
			progressCtr.Wait()
		}()

		tickDuration := 200 * time.Millisecond
		ticker := time.NewTicker(tickDuration)
		pbMap := make(map[string]*progressBar)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-pb.done:
				for path := range pbMap {
					pbMap[path].bar.Abort(true)
					pbMap[path].bar.Wait()
				}
				return nil
			case <-ticker.C:
				func() {
					pb.lock.RLock()
					defer pb.lock.RUnlock()
					for path := range pbMap {
						pbMap[path].xfer = -1
					}
					for path := range pb.status {
						if pbMap[path] == nil {
							pbMap[path] = &progressBar{
								bar: progressCtr.AddBar(0,
									mpb.PrependDecorators(
										decor.Name(filepath.Base(path), decor.WCSyncSpaceR),
										decor.CountersKibiByte("% .2f / % .2f"),
									),
									mpb.AppendDecorators(
										decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, 15), ""),
										decor.OnComplete(decor.Name(" ] "), ""),
										decor.OnComplete(decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 15), "Done!"),
									),
								),
							}
						}
						oldStatus := pbMap[path].progressStatus
						newStatus := pb.status[path]
						if oldStatus.size == 0 && newStatus.size > 0 {
							pbMap[path].bar.SetTotal(newStatus.size, false)
						}
						pbMap[path].bar.EwmaSetCurrent(newStatus.xfer, tickDuration)
						pbMap[path].progressStatus = newStatus
					}
					toDelete := make([]string, 0)
					for path := range pbMap {
						if pbMap[path].xfer == -1 {
							toDelete = append(toDelete, path)
						}
					}
					for _, path := range toDelete {
						bar := pbMap[path].bar
						bar.Abort(true)
						bar.Wait()
						delete(pbMap, path)
					}
				}()
			}
		}

	})
}
