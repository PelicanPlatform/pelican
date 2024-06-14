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

package local_cache

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/option"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	LocalCache struct {
		ctx           context.Context
		egrp          *errgroup.Group
		te            *client.TransferEngine
		tc            *client.TransferClient
		cancelReq     chan cancelReq
		basePath      string
		sizeReq       chan availSizeReq
		mutex         sync.RWMutex
		purgeMutex    sync.Mutex
		downloads     map[string]*activeDownload
		directorURL   *url.URL
		ac            *authConfig
		wasConfigured bool

		// Cache static configuration
		highWater uint64
		lowWater  uint64

		// LRU implementation
		hitChan   chan lruEntry // Notifies the central handler the cache has been used
		lru       lru           // Manages a LRU of cache entries
		lruLookup map[string]*lruEntry
		cacheSize uint64 // Total cache size
	}

	lruEntry struct {
		lastUse time.Time
		path    string
		size    int64
	}

	lru []*lruEntry

	waiterInfo struct {
		id     uuid.UUID
		size   int64
		notify chan *downloadStatus
	}

	// The waiters type fulfills the heap interface, allowing
	// them to be used as a sorted priority queue
	waiters []waiterInfo

	activeDownload struct {
		tj         *client.TransferJob
		status     *downloadStatus
		waiterList waiters
	}

	downloadStatus struct {
		curSize atomic.Int64
		size    atomic.Int64
		err     atomic.Pointer[error]
		done    atomic.Bool
	}

	cacheReader struct {
		sc      *LocalCache
		offset  int64
		path    string
		token   string
		size    int64
		avail   int64
		fdOnce  sync.Once
		fd      *os.File
		openErr error
		status  chan *downloadStatus
		buf     []byte
	}

	req struct {
		id    uuid.UUID
		path  string
		token string
	}

	cancelReq struct {
		req  req
		done chan bool
	}

	availSizeReq struct {
		ctx     context.Context
		request req
		size    int64
		results chan *downloadStatus
	}

	LocalCacheOption                 = option.Interface
	identLocalCacheOptionDeferConfig struct{}
)

var (
	authorizationDenied error = errors.New("authorization denied")
	purgeTimeout        error = errors.New("purge attempt has timed out")
)

const (
	reqSize = 2 * 1024 * 1024
)

func newRequest(path, token string) (req req, err error) {
	req.id, err = uuid.NewV7()
	if err != nil {
		return
	}
	req.path = path
	req.token = token
	return
}

func (waiters waiters) Len() int {
	return len(waiters)
}

func (waiters waiters) Less(i, j int) bool {
	return waiters[i].size < waiters[j].size
}

func (waiters waiters) Swap(i, j int) {
	waiters[i], waiters[j] = waiters[j], waiters[i]
}

func (waiters *waiters) Push(x any) {
	*waiters = append(*waiters, x.(waiterInfo))
}

func (waiters *waiters) Pop() any {
	old := *waiters
	n := len(old)
	x := old[n-1]
	*waiters = old[0 : n-1]
	return x
}

func (lru lru) Len() int {
	return len(lru)
}

func (lru lru) Less(i, j int) bool {
	return lru[i].lastUse.Before(lru[j].lastUse)
}

func (lru lru) Swap(i, j int) {
	lru[i], lru[j] = lru[j], lru[i]
}

func (lru *lru) Push(x any) {
	*lru = append(*lru, x.(*lruEntry))
}

func (lru *lru) Pop() any {
	old := *lru
	n := len(old)
	x := old[n-1]
	*lru = old[0 : n-1]
	return x
}

func (ds *downloadStatus) String() string {
	errP := ds.err.Load()
	if errP == nil {
		return fmt.Sprintf("{size=%d,total=%d,done=%v}", ds.curSize.Load(), ds.size.Load(), ds.done.Load())
	} else {
		return fmt.Sprintf("{size=%d,total=%d,err=%s,done=%v}", ds.curSize.Load(), ds.size.Load(), *errP, ds.done.Load())
	}
}

// Create an option to defer the configuration of the local cache
//
// Useful in cases where the cache should be created before the web interface
// is up -- but the web interface is needed to complete configuration.
func WithDeferConfig(deferConfig bool) LocalCacheOption {
	return option.New(identLocalCacheOptionDeferConfig{}, deferConfig)
}

// Create a local cache object
//
// Launches background goroutines associated with the cache
func NewLocalCache(ctx context.Context, egrp *errgroup.Group, options ...LocalCacheOption) (lc *LocalCache, err error) {
	deferConfig := false
	for _, option := range options {
		switch option.Ident() {
		case identLocalCacheOptionDeferConfig{}:
			deferConfig = option.Value().(bool)
		}
	}

	// Setup cache on disk
	cacheDir := param.LocalCache_DataLocation.GetString()
	if cacheDir == "" {
		err = errors.New("LocalCache.DataLocation is not set; cannot determine where to place file cache's data")
		return
	}
	if err = os.RemoveAll(cacheDir); err != nil {
		return
	}
	if err = os.MkdirAll(cacheDir, os.FileMode(0700)); err != nil {
		return
	}

	cacheSize, err := getCacheSize(cacheDir)
	if err != nil {
		return
	}
	highWaterPercentage := param.LocalCache_HighWaterMarkPercentage.GetInt()
	lowWaterPercentage := param.LocalCache_LowWaterMarkPercentage.GetInt()
	highWater := (cacheSize / 100) * uint64(highWaterPercentage)
	lowWater := (cacheSize / 100) * uint64(lowWaterPercentage)
	log.Infof("Cache size is %d bytes; for purge, high water mark is %d bytes, low water mark is %d bytes", cacheSize, highWater, lowWater)

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return
	}
	directorUrl, err := url.Parse(fedInfo.DirectorEndpoint)
	if err != nil {
		return
	}

	// Ensure to initialize the client before getting a transfer engine
	err = config.InitClient()
	if err != nil {
		return
	}

	te, err := client.NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	lc = &LocalCache{
		ctx:         ctx,
		egrp:        egrp,
		te:          te,
		downloads:   make(map[string]*activeDownload),
		hitChan:     make(chan lruEntry, 64),
		highWater:   (cacheSize / 100) * uint64(highWaterPercentage),
		lowWater:    (cacheSize / 100) * uint64(lowWaterPercentage),
		cacheSize:   0,
		basePath:    cacheDir,
		ac:          newAuthConfig(ctx, egrp),
		sizeReq:     make(chan availSizeReq),
		directorURL: directorUrl,
		lruLookup:   make(map[string]*lruEntry),
	}

	lc.tc, err = lc.te.NewClient(client.WithAcquireToken(false), client.WithCallback(lc.callback))
	if err != nil {
		shutdownErr := lc.te.Shutdown()
		if shutdownErr != nil {
			log.Errorln("Failed to shutdown transfer engine")
		}
		return
	}
	if !deferConfig {
		if err = lc.Config(egrp); err != nil {
			log.Warningln("First attempt to update cache's authorization failed:", err)
		}
	}

	egrp.Go(lc.runMux)

	log.Debugln("Successfully created a new local cache object")
	return
}

// Try to configure the local cache and launch the reconfigure goroutine
func (lc *LocalCache) Config(egrp *errgroup.Group) (err error) {
	if lc.wasConfigured {
		return
	}
	lc.wasConfigured = true
	if err = lc.updateConfig(); err != nil {
		log.Warningln("First attempt to update cache's authorization failed:", err)
	}
	egrp.Go(lc.periodicUpdateConfig)
	return
}

// Callback for in-progress transfers
//
// The TransferClient will invoke the callback as it progresses;
// the callback info will be used to help the waiters progress.
func (sc *LocalCache) callback(path string, downloaded int64, size int64, completed bool) {
	ds := func() (ds *downloadStatus) {
		sc.mutex.RLock()
		defer sc.mutex.RUnlock()
		dl := sc.downloads[path]
		if dl != nil {
			ds = dl.status
		}
		return
	}()
	if ds != nil {
		ds.curSize.Store(downloaded)
		ds.size.Store(size)
		ds.done.Store(completed)
	}
}

// The main goroutine for managing the cache and its requests
func (sc *LocalCache) runMux() error {
	results := sc.tc.Results()

	type result struct {
		path    string
		ds      *downloadStatus
		channel chan *downloadStatus
	}
	tmpResults := make([]result, 0)
	cancelRequest := make([]chan bool, 0)
	activeJobs := make(map[string]*activeDownload)
	jobPath := make(map[string]string)
	ticker := time.NewTicker(100 * time.Millisecond)
	clientClosed := false
	for {
		lenResults := len(tmpResults)
		lenCancel := len(cancelRequest)
		lenChan := lenResults + lenCancel
		cases := make([]reflect.SelectCase, lenResults+6)
		for idx, info := range tmpResults {
			cases[idx].Dir = reflect.SelectSend
			cases[idx].Chan = reflect.ValueOf(info.channel)
			cases[idx].Send = reflect.ValueOf(info.ds)
		}
		for idx, channel := range cancelRequest {
			cases[lenResults+idx].Dir = reflect.SelectSend
			cases[lenResults+idx].Chan = reflect.ValueOf(channel)
			cases[lenResults+idx].Send = reflect.ValueOf(true)
		}
		cases[lenChan].Dir = reflect.SelectRecv
		cases[lenChan].Chan = reflect.ValueOf(sc.ctx.Done())
		cases[lenChan+1].Dir = reflect.SelectRecv
		cases[lenChan+1].Chan = reflect.ValueOf(results)
		if clientClosed {
			cases[lenChan+1].Chan = reflect.ValueOf(nil)
		}
		cases[lenChan+2].Dir = reflect.SelectRecv
		cases[lenChan+2].Chan = reflect.ValueOf(ticker.C)
		cases[lenChan+3].Dir = reflect.SelectRecv
		cases[lenChan+3].Chan = reflect.ValueOf(sc.sizeReq)
		cases[lenChan+4].Dir = reflect.SelectRecv
		cases[lenChan+4].Chan = reflect.ValueOf(sc.cancelReq)
		cases[lenChan+5].Dir = reflect.SelectRecv
		cases[lenChan+5].Chan = reflect.ValueOf(sc.hitChan)
		chosen, recv, ok := reflect.Select(cases)

		if chosen < lenResults {
			// Sent a result to the waiter
			tmpResults = slices.Delete(tmpResults, chosen, chosen+1)
		} else if chosen < lenChan {
			// Acknowledged a cancellation
			cancelRequest = slices.Delete(cancelRequest, chosen-lenResults, chosen-lenResults+1)
		} else if chosen == lenChan {
			// Cancellation; shut down
			return nil
		} else if chosen == lenChan+1 {
			// New transfer results
			if !ok {
				// Client has closed, last notification for everyone
				for path, ad := range activeJobs {
					ad.status.done.Store(true)
					for _, waiter := range ad.waiterList {
						tmpResults = append(tmpResults, result{path: path, channel: waiter.notify})
					}
				}
				clientClosed = true
				continue
			}
			results := recv.Interface().(client.TransferResults)
			reqPath := jobPath[results.ID()]
			if reqPath == "" {
				log.Errorf("Transfer results from job %s but no corresponding path known", results.ID())
				continue
			}
			delete(jobPath, results.ID())
			ad := activeJobs[reqPath]
			if ad == nil {
				log.Errorf("Transfer results from job %s returned for path %s but no active job known", results.ID(), reqPath)
				continue
			}
			delete(activeJobs, reqPath)
			func() {
				localPath := filepath.Join(sc.basePath, path.Clean(reqPath))
				sc.mutex.Lock()
				defer sc.mutex.Unlock()
				delete(sc.downloads, localPath)
			}()
			if results.Error != nil {
				ad.status.err.Store(&results.Error)
			}
			ad.status.curSize.Store(results.TransferredBytes)
			ad.status.size.Store(results.TransferredBytes)
			ad.status.done.Store(true)
			for _, waiter := range ad.waiterList {
				tmpResults = append(tmpResults, result{ds: ad.status, path: reqPath, channel: waiter.notify})
			}
			if results.Error == nil {
				if fp, err := os.OpenFile(filepath.Join(sc.basePath, reqPath)+".DONE", os.O_CREATE|os.O_WRONLY, os.FileMode(0600)); err != nil {
					log.Debugln("Unable to save a DONE file for cache path", reqPath)
				} else {
					fp.Close()
				}
				sc.lruHit(lruEntry{lastUse: time.Now(), path: reqPath, size: results.TransferredBytes})
			}
		} else if chosen == lenChan+2 {
			// Ticker has fired - update progress
			jobsToDelete := make([]string, 0)
			for path, dl := range activeJobs {
				if _, err := dl.tj.GetLookupStatus(); err != nil {
					dl.status.err.Store(&err)
					for _, waiter := range dl.waiterList {
						tmpResults = append(tmpResults, result{path: path, channel: waiter.notify, ds: dl.status})
					}
					jobsToDelete = append(jobsToDelete, path)
					delete(jobPath, dl.tj.ID())
					continue
				}

				curSize := dl.status.curSize.Load()
				for {
					if dl.waiterList.Len() > 0 && dl.waiterList[0].size <= curSize {
						waiter := heap.Pop(&dl.waiterList).(waiterInfo)
						tmpResults = append(tmpResults, result{path: path, channel: waiter.notify, ds: dl.status})
					} else {
						break
					}
				}
			}
			for _, path := range jobsToDelete {
				delete(activeJobs, path)
			}
			func() {
				sc.mutex.Lock()
				defer sc.mutex.Unlock()
				for _, lpath := range jobsToDelete {
					localPath := filepath.Join(sc.basePath, path.Clean(lpath))
					delete(sc.downloads, localPath)
				}
			}()
		} else if chosen == lenChan+3 {
			// New request
			req := recv.Interface().(availSizeReq)

			// See if we can add the request to the waiter list
			if ds := activeJobs[req.request.path]; ds != nil {
				heap.Push(&ds.waiterList, waiterInfo{
					size:   req.size,
					notify: req.results,
				})
				continue
			}
			// Start a new download
			localPath := filepath.Join(sc.basePath, path.Clean(req.request.path))

			// Ensure there's no .DONE file placed since the request was made.
			if fpDone, err := os.Open(localPath + ".DONE"); err == nil {
				fpDone.Close()
				ds := &downloadStatus{}
				ds.done.Store(true)
				if fi, err := os.Stat(localPath); err == nil {
					ds.curSize.Store(fi.Size())
					ds.size.Store(fi.Size())
					tmpResults = append(tmpResults, result{
						path:    req.request.path,
						channel: req.results,
						ds:      ds,
					})
					sc.lruHit(lruEntry{lastUse: time.Now(), path: req.request.path, size: fi.Size()})
				}
			}

			sourceURL := *sc.directorURL
			sourceURL.Path = path.Join(sourceURL.Path, path.Clean(req.request.path))
			sourceURL.Scheme = "pelican"
			tj, err := sc.tc.NewTransferJob(req.ctx, &sourceURL, localPath, false, false, client.WithToken(req.request.token))
			if err != nil {
				ds := &downloadStatus{}
				ds.err.Store(&err)
				tmpResults = append(tmpResults, result{
					path:    req.request.path,
					channel: req.results,
					ds:      ds,
				})
				continue
			}
			ad := &activeDownload{
				tj:         tj,
				status:     &downloadStatus{},
				waiterList: make(waiters, 0),
			}
			ad.waiterList = append(ad.waiterList, waiterInfo{
				size:   req.size,
				notify: req.results,
			})
			if err := sc.tc.Submit(tj); err != nil {
				ds := &downloadStatus{}
				ds.err.Store(&err)
				tmpResults = append(tmpResults, result{
					path:    req.request.path,
					channel: req.results,
					ds:      ds,
				})
			}
			activeJobs[req.request.path] = ad
			jobPath[tj.ID()] = req.request.path
			func() {
				sc.mutex.Lock()
				defer sc.mutex.Unlock()
				sc.downloads[localPath] = ad
			}()
		} else if chosen == lenChan+4 {
			// Cancel a given request.
			req := recv.Interface().(cancelReq)
			ds := activeJobs[req.req.path]
			if ds != nil {
				var idx int
				found := false
				var waiter waiterInfo
				for idx, waiter = range ds.waiterList {
					if waiter.id == req.req.id {
						break
					}
				}
				if found {
					heap.Remove(&ds.waiterList, idx)
				}
			}
			cancelRequest = append(cancelRequest, req.done)
		} else if chosen == lenChan+5 {
			// Notification there was a cache hit.
			hit := recv.Interface().(lruEntry)
			sc.lruHit(hit)
		}
	}
}

func (lc *LocalCache) lruHit(hit lruEntry) {
	entry := lc.lruLookup[hit.path]
	if entry == nil {
		entry = &hit
		lc.lruLookup[hit.path] = entry
		lc.lru = append(lc.lru, entry)
		lc.cacheSize += uint64(hit.size)
		if lc.cacheSize > lc.highWater {
			if err := lc.purge(); err != nil {
				log.Warningln("Failure when purging cache:", err)
			}
		}
	}
	entry.lastUse = hit.lastUse
	if hit.size > entry.size {
		entry.size = hit.size
	}
}

func (lc *LocalCache) purge() (err error) {
	log.Debugln("Starting purge routine")
	lc.purgeMutex.Lock()
	defer lc.purgeMutex.Unlock()
	heap.Init(&lc.lru)
	start := time.Now()
	log.Debugf("Purge running with cache size %d and low watermark of %d", lc.cacheSize, lc.lowWater)
	for lc.cacheSize > lc.lowWater {
		if len(lc.lru) == 0 {
			err = errors.New("purge ran until cache was empty")
			log.Warningln("Potential consistency error: purge ran until cache was empty")
			break
		}
		entry := heap.Pop(&lc.lru).(*lruEntry)
		if entry == nil {
			log.Warningln("Consistency error: purge run but no entry provided")
			continue
		}
		if entry.path == "" {
			log.Warningln("Consistency error: purge ran on an empty path")
			continue
		}
		localPath := path.Join(lc.basePath, path.Clean(entry.path))
		if rmErr := os.Remove(localPath + ".DONE"); rmErr != nil {
			log.Warningln("Failed to purge DONE file:", rmErr)
			if err == nil {
				err = rmErr
			}
		}
		if rmErr := os.Remove(localPath); rmErr != nil {
			log.Warningln("Failed to purge file:", rmErr)
			if err == nil {
				err = rmErr
			}
		}
		lc.cacheSize -= uint64(entry.size)
		// Since purge is called from the mux thread, blocking can cause
		// other failures; do a time-based break even if we've not hit the low-water
		if time.Since(start) > 3*time.Second {
			err = purgeTimeout
			break
		}
	}
	return
}

// Given a URL, return a reader from the disk cache
//
// If there is no sentinal $NAME.DONE file, then returns nil
func (sc *LocalCache) getFromDisk(localPath string) *os.File {
	localPath = filepath.Join(sc.basePath, path.Clean(localPath))
	fp, err := os.Open(localPath + ".DONE")
	if err != nil {
		return nil
	}
	defer fp.Close()
	if fpReal, err := os.Open(localPath); err == nil {
		return fpReal
	}
	return nil
}

func (sc *LocalCache) newCacheReader(ctx context.Context, path, token string) (reader *cacheReader, err error) {
	reader = &cacheReader{
		path:   path,
		token:  token,
		sc:     sc,
		size:   -1,
		status: nil,
	}
	err = reader.peekError(ctx)
	return
}

// Get path from the cache
func (sc *LocalCache) Get(ctx context.Context, path, token string) (io.ReadCloser, error) {
	if !sc.ac.authorize(token_scopes.Storage_Read, path, token) {
		return nil, authorizationDenied
	}

	if fp := sc.getFromDisk(path); fp != nil {
		finfo, err := fp.Stat()
		if err != nil {
			log.Warningf("Able to open %s in cache but unable to stat it: %v", path, err)
		}
		sc.hitChan <- lruEntry{lastUse: time.Now(), path: path, size: finfo.Size()}
		return fp, nil
	}

	return sc.newCacheReader(ctx, path, token)

}

func (lc *LocalCache) Stat(path, token string) (uint64, error) {
	if !lc.ac.authorize(token_scopes.Storage_Read, path, token) {
		return 0, authorizationDenied
	}

	if fp := lc.getFromDisk(path); fp != nil {
		finfo, err := fp.Stat()
		if err != nil {
			return 0, errors.New("Failed to determine cached file size for object")
		}
		return uint64(finfo.Size()), nil
	}

	dUrl := *lc.directorURL
	dUrl.Path = path
	dUrl.Scheme = "pelican"
	statInfo, err := client.DoStat(context.Background(), dUrl.String(), client.WithToken(token))
	return uint64(statInfo.Size), err
}

func (sc *LocalCache) updateConfig() error {
	// Get the endpoint of the director
	var respNS []server_structs.NamespaceAdV2

	fedInfo, err := config.GetFederation(sc.ctx)
	if err != nil {
		return err
	}
	directorEndpoint := fedInfo.DirectorEndpoint
	if directorEndpoint == "" {
		return errors.New("No director specified; give the federation name (-f)")
	}

	directorEndpointURL, err := url.Parse(directorEndpoint)
	if err != nil {
		return errors.Wrap(err, "Unable to parse director url")
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpointURL.String(), "api", "v2.0", "director", "listNamespaces")
	if err != nil {
		return errors.Wrap(err, "Unable to generate the director's listNamespaces endpoint")
	}

	respData, err := utils.MakeRequest(sc.ctx, directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		return err
	} else {
		err = json.Unmarshal(respData, &respNS)
		if err != nil {
			return errors.Wrapf(err, "Failed to marshal response in to JSON: %v", err)
		}
	}

	return sc.ac.updateConfig(respNS)
}

// Periodically update the cache configuration from the registry
func (sc *LocalCache) periodicUpdateConfig() error {
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-sc.ctx.Done():
			return nil
		case <-ticker.C:
			err := sc.updateConfig()
			if err != nil {
				log.Warningln("Failed to update the file cache config:", err)
			}
		}
	}
}

// Read bytes from a file in the cache
//
// Does not request more data if bytes are not found
func (cr *cacheReader) readFromFile(p []byte, off int64) (n int, err error) {
	cr.fdOnce.Do(func() {
		cr.fd, cr.openErr = os.Open(filepath.Join(cr.sc.basePath, path.Clean(cr.path)))
	})
	if cr.openErr != nil {
		err = cr.openErr
		return
	}
	return cr.fd.ReadAt(p, off)
}

// Peek at the contents of the upstream of the cache reader; if there's
// an error, return that.  Otherwise, return nil
func (cr *cacheReader) peekError(ctx context.Context) (err error) {
	cr.buf = make([]byte, 4096)
	n, err := cr.readRaw(ctx, cr.buf)
	if n >= 0 {
		cr.buf = cr.buf[:n]
	}
	if err == io.EOF {
		return nil
	}
	return err
}

func (cr *cacheReader) Read(p []byte) (n int, err error) {
	if cr.buf != nil && len(cr.buf) > 0 {
		bytesCopied := copy(p, cr.buf)
		if len(cr.buf) > bytesCopied {
			cr.buf = cr.buf[bytesCopied:]
		} else {
			cr.buf = nil
		}
		return bytesCopied, nil
	}
	return cr.readRaw(context.Background(), p)
}

func (cr *cacheReader) readRaw(ctx context.Context, p []byte) (n int, err error) {
	neededSize := cr.offset + int64(len(p))
	if cr.size >= 0 && neededSize > cr.size {
		neededSize = cr.size
	}
	if neededSize > cr.avail && cr.fd != nil {
		finfo, err := cr.fd.Stat()
		if err == nil {
			cr.avail = finfo.Size()
		} else {
			log.Warningln("Unable to stat open file handle:", err)
		}
	}
	if neededSize > cr.avail {
		// Insufficient available data; request more from the cache
		if cr.status == nil {
			// Send a request to the cache
			var req req
			req, err = newRequest(cr.path, cr.token)
			if err != nil {
				return
			}

			// Bump up the size we're waiting on; only get notifications every 2MB
			if len(p) < reqSize {
				if cr.size >= 0 && cr.offset+reqSize > cr.size {
					neededSize = cr.size
				} else {
					neededSize = cr.offset + reqSize
				}
			}
			cr.status = make(chan *downloadStatus)
			sizeReq := availSizeReq{
				ctx:     ctx,
				request: req,
				size:    neededSize,
				results: cr.status,
			}
			select {
			case <-cr.sc.ctx.Done():
				err = cr.sc.ctx.Err()
				return
			case cr.sc.sizeReq <- sizeReq:
			}
		}
		select {
		case <-cr.sc.ctx.Done():
			return 0, cr.sc.ctx.Err()
		case availSize, ok := <-cr.status:
			cr.status = nil
			if !ok {
				err = errors.New("unable to get response from cache engine")
				return
			}
			if availSize == nil {
				err = errors.New("internal error - cache sent a nil result")
				return
			}
			dlErr := availSize.err.Load()
			if dlErr != nil && *dlErr != nil {
				err = *dlErr
				return
			}
			done := availSize.done.Load()
			dlSize := availSize.curSize.Load()
			cr.size = availSize.size.Load()
			cr.avail = dlSize
			if dlSize < neededSize && !done {
				err = errors.New("download thread returned too-short read")
				return
			} else {
				n, err = cr.readFromFile(p, cr.offset)
				if err != nil && err != io.EOF {
					return
				}
				cr.offset += int64(n)
				return
			}
		}
	} else {
		n, err = cr.readFromFile(p, cr.offset)
		if err != nil && err != io.EOF {
			return
		}
		cr.offset += int64(n)
		return
	}
}

func (cr *cacheReader) Close() error {
	return nil
}
