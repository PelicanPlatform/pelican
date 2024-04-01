/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/option"
	"github.com/opensaucerer/grab/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
	"github.com/vbauerster/mpb/v8"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/param"
)

var (
	progressCtrOnce sync.Once
	progressCtr     *mpb.Progress

	successTTL = ttlcache.DefaultTTL
	failureTTL = 5 * time.Minute

	loader = ttlcache.LoaderFunc[string, cacheItem](
		func(c *ttlcache.Cache[string, cacheItem], key string) *ttlcache.Item[string, cacheItem] {
			ctx := context.Background()
			// Note: setting this timeout mostly for unit tests
			ctx, cancel := context.WithTimeout(ctx, param.Transport_ResponseHeaderTimeout.GetDuration())
			defer cancel()
			urlFederation, err := config.DiscoverUrlFederation(ctx, key)
			if err != nil {
				// Set a shorter TTL for failures
				item := c.Set(key, cacheItem{err: err}, failureTTL)
				return item
			}
			// Set a longer TTL for successes
			item := c.Set(key, cacheItem{
				url: pelicanUrl{
					DirectorUrl: urlFederation.DirectorEndpoint,
				},
			}, successTTL)
			return item
		},
	)

	suppressedLoader = ttlcache.NewSuppressedLoader(loader, new(singleflight.Group))
)

type (
	cacheItem struct {
		url pelicanUrl
		err error
	}

	// Error type for when the transfer started to return data then completely stopped
	StoppedTransferError struct {
		Err string
	}

	// SlowTransferError is an error that is returned when a transfer takes longer than the configured timeout
	SlowTransferError struct {
		BytesTransferred int64
		BytesPerSecond   int64
		BytesTotal       int64
		Duration         time.Duration
	}

	// ConnectionSetupError is an error that is returned when a connection to the remote server fails
	ConnectionSetupError struct {
		URL string
		Err error
	}

	// Represents the results of a single object transfer,
	// potentially across multiple attempts / retries.
	TransferResults struct {
		jobId            uuid.UUID // The job ID this result corresponds to
		job              *TransferJob
		Error            error
		TransferredBytes int64
		Scheme           string
		Attempts         []TransferResult
	}

	TransferResult struct {
		Number            int     // indicates which attempt this is
		TransferFileBytes int64   // how much each attempt downloaded
		TimeToFirstByte   float64 // how long it took to download the first byte
		TransferEndTime   int64   // when the transfer ends
		TransferTime      int64   // amount of time we were transferring per attempt (in seconds)
		Endpoint          string  // which origin did it use
		ServerVersion     string  // version of the server
		Error             error   // what error the attempt returned (if any)
	}

	clientTransferResults struct {
		id      uuid.UUID       // ID of the client that created the job
		results TransferResults // Actual transfer results
	}

	// A structure representing a single endpoint we will attempt a transfer against.
	transferAttemptDetails struct {
		// Url of the server's hostname and port
		Url *url.URL

		// Proxy specifies if a proxy should be used
		Proxy bool

		// If the Url scheme is unix, this is the path to connect to
		UnixSocket string

		// Specifies the pack option in the transfer URL
		PackOption string
	}

	// A structure representing a single file to transfer.
	transferFile struct {
		ctx        context.Context
		engine     *TransferEngine
		job        *TransferJob
		callback   TransferCallbackFunc
		remoteURL  *url.URL
		localPath  string
		token      string
		upload     bool
		packOption string
		attempts   []transferAttemptDetails
		project    string
		err        error
	}

	// A representation of a "transfer job".  The job
	// can be submitted to the client library, resulting
	// in one or more transfers (if recursive is true).
	// We assume the transfer job is potentially queued for a
	// long time and all the transfers generated by this job will
	// use the same namespace and token.
	TransferJob struct {
		ctx           context.Context
		cancel        context.CancelFunc
		callback      TransferCallbackFunc
		uuid          uuid.UUID
		remoteURL     *url.URL
		lookupDone    atomic.Bool
		lookupErr     error
		activeXfer    atomic.Int64
		totalXfer     int
		localPath     string
		upload        bool
		recursive     bool
		skipAcquire   bool
		caches        []*url.URL
		useDirector   bool
		tokenLocation string
		token         string
		project       string
		namespace     namespaces.Namespace
	}

	// A TransferJob associated with a client's request
	clientTransferJob struct {
		uuid uuid.UUID
		job  *TransferJob
	}

	// A transferFile associated with a client request
	clientTransferFile struct {
		uuid  uuid.UUID
		jobId uuid.UUID
		file  *transferFile
	}

	// An object able to process transfer jobs.
	TransferEngine struct {
		ctx             context.Context // The context provided upon creation of the engine.
		cancel          context.CancelFunc
		egrp            *errgroup.Group // The errgroup for the worker goroutines
		work            chan *clientTransferJob
		files           chan *clientTransferFile
		results         chan *clientTransferResults
		jobLookupDone   chan *clientTransferJob // Indicates the job lookup handler is done with the job
		workersActive   int
		resultsMap      map[uuid.UUID]chan *TransferResults
		workMap         map[uuid.UUID]chan *TransferJob
		notifyChan      chan bool
		closeChan       chan bool
		closeDoneChan   chan bool
		ewmaTick        *time.Ticker
		ewma            ewma.MovingAverage
		ewmaVal         atomic.Int64
		ewmaCtr         atomic.Int64
		clientLock      sync.RWMutex
		pelicanURLCache *ttlcache.Cache[string, cacheItem]
	}

	TransferCallbackFunc = func(path string, downloaded int64, totalSize int64, completed bool)

	// A client to the transfer engine.
	TransferClient struct {
		id            uuid.UUID
		ctx           context.Context
		cancel        context.CancelFunc
		callback      TransferCallbackFunc
		skipAcquire   bool   // Enable/disable the token acquisition logic.  Defaults to acquiring a token
		tokenLocation string // Location of a token file to use for transfers
		token         string // Token that should be used for transfers
		work          chan *TransferJob
		closed        bool
		caches        []*url.URL
		results       chan *TransferResults
		finalResults  chan TransferResults
		setupResults  sync.Once
	}

	TransferOption                   = option.Interface
	identTransferOptionCaches        struct{}
	identTransferOptionCallback      struct{}
	identTransferOptionTokenLocation struct{}
	identTransferOptionAcquireToken  struct{}
	identTransferOptionToken         struct{}

	transferDetailsOptions struct {
		NeedsToken bool
		PackOption string
	}

	pelicanUrl struct {
		DirectorUrl string // Note: needs to be public because of tests being outside of the package
	}
)

const (
	ewmaInterval = 15 * time.Second
)

// The progress container object creates several
// background goroutines.  Instead of creating the object
// globally, create it on first use.  This avoids having
// the progress container routines launch in the server.
func getProgressContainer() *mpb.Progress {
	progressCtrOnce.Do(func() {
		progressCtr = mpb.New()
	})
	return progressCtr
}

func (e *StoppedTransferError) Error() string {
	return e.Err
}

type HttpErrResp struct {
	Code int
	Err  string
}

func (e *HttpErrResp) Error() string {
	return e.Err
}

func (e *SlowTransferError) Error() string {
	return "cancelled transfer, too slow.  Detected speed: " +
		ByteCountSI(e.BytesPerSecond) +
		"/s, total transferred: " +
		ByteCountSI(e.BytesTransferred) +
		", total transfer time: " +
		e.Duration.String()
}

func (e *SlowTransferError) Is(target error) bool {
	_, ok := target.(*SlowTransferError)
	return ok
}

// Determines whether or not we can interact with the site HTTP proxy
func isProxyEnabled() bool {
	if _, isSet := os.LookupEnv("http_proxy"); !isSet {
		return false
	}
	if param.Client_DisableHttpProxy.GetBool() {
		return false
	}
	return true
}

// Determine whether we are allowed to skip the proxy as a fallback
func CanDisableProxy() bool {
	return !param.Client_DisableProxyFallback.GetBool()
}

func (e *ConnectionSetupError) Error() string {
	if e.Err != nil {
		if len(e.URL) > 0 {
			return "failed connection setup to " + e.URL + ": " + e.Err.Error()
		} else {
			return "failed connection setup: " + e.Err.Error()
		}
	} else {
		return "Connection to remote server failed"
	}

}

func (e *ConnectionSetupError) Unwrap() error {
	return e.Err
}

func (e *ConnectionSetupError) Is(target error) bool {
	_, ok := target.(*ConnectionSetupError)
	return ok
}

// hasPort test the host if it includes a port
func hasPort(host string) bool {
	var checkPort = regexp.MustCompile("^.*:[0-9]+$")
	return checkPort.MatchString(host)
}

// Create a new transfer results object
func newTransferResults(job *TransferJob) TransferResults {
	return TransferResults{
		job:      job,
		jobId:    job.uuid,
		Attempts: make([]TransferResult, 0),
	}
}

func (tr TransferResults) ID() string {
	return tr.jobId.String()
}

func (te *TransferEngine) NewPelicanURL(remoteUrl *url.URL) (pelicanURL pelicanUrl, err error) {
	scheme := remoteUrl.Scheme
	if remoteUrl.Host != "" {
		if scheme == "osdf" || scheme == "stash" {
			// in the osdf/stash case, fix url's that have a hostname
			joinedPath, err := url.JoinPath(remoteUrl.Host, remoteUrl.Path)
			// Prefix with a / just in case
			remoteUrl.Path = path.Join("/", joinedPath)
			if err != nil {
				log.Errorln("Failed to join remote destination url path:", err)
				return pelicanUrl{}, err
			}
		} else if scheme == "pelican" {
			// If we have a host and url is pelican, we need to extract federation data from the host
			log.Debugln("Detected pelican:// url, getting federation metadata from specified host", remoteUrl.Host)
			federationUrl := &url.URL{}
			// federationUrl, _ := url.Parse(remoteUrl.String())
			federationUrl.Scheme = "https"
			federationUrl.Path = ""
			federationUrl.Host = remoteUrl.Host

			// Check if cache has key of federationURL, if not, loader will add it:
			pelicanUrlItem := te.pelicanURLCache.Get(federationUrl.String())
			if pelicanUrlItem.Value().err != nil {
				return pelicanUrl{}, pelicanUrlItem.Value().err
			} else {
				pelicanURL = pelicanUrlItem.Value().url
			}
		}
	}

	// With an osdf:// url scheme, we assume the user will be using the OSDF so load in our osdf metadata for our url
	if scheme == "osdf" {
		// If we are using an osdf/stash binary, we discovered the federation already --> load into local url metadata
		if config.GetPreferredPrefix() == "OSDF" {
			log.Debugln("In OSDF mode with osdf:// url; populating metadata with OSDF defaults")
			if param.Federation_DirectorUrl.GetString() == "" || param.Federation_DiscoveryUrl.GetString() == "" || param.Federation_RegistryUrl.GetString() == "" {
				return pelicanUrl{}, fmt.Errorf("OSDF default metadata is not populated in config")
			} else {
				pelicanURL.DirectorUrl = param.Federation_DirectorUrl.GetString()
			}
		} else if config.GetPreferredPrefix() == "PELICAN" {
			// We hit this case when we are using a pelican binary but an osdf:// url, therefore we need to disover the osdf federation
			log.Debugln("In Pelican mode with an osdf:// url, populating metadata with OSDF defaults")
			// Check if cache has key of federationURL, if not, loader will add it:
			pelicanUrlItem := te.pelicanURLCache.Get("osg-htc.org")
			if pelicanUrlItem.Value().err != nil {
				err = pelicanUrlItem.Value().err
				return
			} else {
				pelicanURL = pelicanUrlItem.Value().url
			}
		}
	} else if scheme == "pelican" && remoteUrl.Host == "" {
		// We hit this case when we do not have a hostname with a pelican:// url
		if param.Federation_DiscoveryUrl.GetString() == "" {
			return pelicanUrl{}, fmt.Errorf("Pelican url scheme without discovery-url detected, please provide a federation discovery-url " +
				"(e.g. pelican://<federation-url-in-hostname.org></namespace></path/to/file>) within the hostname or with the -f flag")
		} else {
			// Check if cache has key of federationURL, if not, loader will add it:
			pelicanUrlItem := te.pelicanURLCache.Get(param.Federation_DiscoveryUrl.GetString())
			if pelicanUrlItem != nil {
				pelicanURL = pelicanUrlItem.Value().url
			} else {
				return pelicanUrl{}, fmt.Errorf("Issue getting metadata information from cache")
			}
		}
	} else if scheme == "" {
		// If we don't have a url scheme, then our metadata information should be in the config
		log.Debugln("No url scheme detected, getting metadata information from configuration")
		pelicanURL.DirectorUrl = param.Federation_DirectorUrl.GetString()

		// If the values do not exist, exit with failure
		if pelicanURL.DirectorUrl == "" {
			return pelicanUrl{}, fmt.Errorf("Missing metadata information in config, ensure Federation DirectorUrl, RegistryUrl, and DiscoverUrl are all set")
		}
	}
	return
}

// Returns a new transfer engine object whose lifetime is tied
// to the provided context.  Will launcher worker goroutines to
// handle the underlying transfers
func NewTransferEngine(ctx context.Context) *TransferEngine {
	ctx, cancel := context.WithCancel(ctx)
	egrp, _ := errgroup.WithContext(ctx)
	work := make(chan *clientTransferJob)
	files := make(chan *clientTransferFile)
	results := make(chan *clientTransferResults, 5)
	pelicanURLCache := ttlcache.New(
		ttlcache.WithTTL[string, cacheItem](30*time.Minute),
		ttlcache.WithLoader(suppressedLoader),
	)

	// Start our cache for url metadata
	go pelicanURLCache.Start()

	te := &TransferEngine{
		ctx:             ctx,
		cancel:          cancel,
		egrp:            egrp,
		work:            work,
		files:           files,
		results:         results,
		resultsMap:      make(map[uuid.UUID]chan *TransferResults),
		workMap:         make(map[uuid.UUID]chan *TransferJob),
		jobLookupDone:   make(chan *clientTransferJob),
		notifyChan:      make(chan bool),
		closeChan:       make(chan bool),
		closeDoneChan:   make(chan bool),
		ewmaTick:        time.NewTicker(ewmaInterval),
		ewma:            ewma.NewMovingAverage(),
		pelicanURLCache: pelicanURLCache,
	}
	workerCount := param.Client_WorkerCount.GetInt()
	if workerCount <= 0 {
		log.Errorln("Worker count must be a positive integer")
		return nil
	}
	for idx := 0; idx < workerCount; idx++ {
		egrp.Go(func() error {
			return runTransferWorker(ctx, te.files, te.results)
		})
	}
	te.workersActive = workerCount
	egrp.Go(te.runMux)
	egrp.Go(te.runJobHandler)
	return te
}

// Create an option that provides a callback for a TransferClient
//
// The callback is invoked periodically by one of the transfer workers,
// with inputs of the local path (e.g., source on upload), the current
// bytes transferred, and the total object size
func WithCallback(callback TransferCallbackFunc) TransferOption {
	return option.New(identTransferOptionCallback{}, callback)
}

// Create an option to override the cache list
func WithCaches(caches ...*url.URL) TransferOption {
	return option.New(identTransferOptionCaches{}, caches)
}

// Create an option to override the token locating logic
//
// This will force the transfer to use a specific file for the token
// contents instead of doing any sort of auto-detection
func WithTokenLocation(location string) TransferOption {
	return option.New(identTransferOptionTokenLocation{}, location)
}

// Create an option to provide a specific token to the transfer
//
// The contents of the token will be used as part of the HTTP request
func WithToken(token string) TransferOption {
	return option.New(identTransferOptionToken{}, token)
}

// Create an option to specify the token acquisition logic
//
// Token acquisition (e.g., using OAuth2 to get a token when one
// isn't found in the environment) defaults to `true` but can be
// disabled with this options
func WithAcquireToken(enable bool) TransferOption {
	return option.New(identTransferOptionAcquireToken{}, enable)
}

// Create a new client to work with an engine
func (te *TransferEngine) NewClient(options ...TransferOption) (client *TransferClient, err error) {
	log.Debugln("Making new clients")
	id, err := uuid.NewV7()
	if err != nil {
		err = errors.Wrap(err, "Unable to create new UUID for client")
		return
	}
	client = &TransferClient{
		id:      id,
		results: make(chan *TransferResults),
		work:    make(chan *TransferJob),
	}
	client.ctx, client.cancel = context.WithCancel(te.ctx)

	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionCaches{}:
			client.caches = option.Value().([]*url.URL)
		case identTransferOptionCallback{}:
			client.callback = option.Value().(TransferCallbackFunc)
		case identTransferOptionTokenLocation{}:
			client.tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			client.skipAcquire = !option.Value().(bool)
		case identTransferOptionToken{}:
			client.token = option.Value().(string)
		}
	}
	func() {
		te.clientLock.Lock()
		defer te.clientLock.Unlock()
		te.resultsMap[id] = client.results
		te.workMap[id] = client.work
	}()
	log.Debugln("Created new client", id.String())
	select {
	case <-te.ctx.Done():
		log.Debugln("New client unable to start; transfer engine has been canceled")
		err = te.ctx.Err()
	case te.notifyChan <- true:
	}
	return
}

// Initiates a shutdown of the transfer engine.
// Waits until all workers have finished
func (te *TransferEngine) Shutdown() error {
	te.pelicanURLCache.Stop()
	te.Close()
	<-te.closeDoneChan
	te.ewmaTick.Stop()
	te.cancel()

	err := te.egrp.Wait()
	if err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// Closes the TransferEngine.  No new work may
// be submitted.  Any ongoing work will continue
func (te *TransferEngine) Close() {
	select {
	case <-te.ctx.Done():
	case te.closeChan <- true:
	}
}

// Launches a helper goroutine that ensures completed
// transfer results are routed back to their requesting
// channels
func (te *TransferEngine) runMux() error {
	tmpResults := make(map[uuid.UUID][]*TransferResults)
	activeJobs := make(map[uuid.UUID][]*TransferJob)
	closing := false
	closedWorkChan := false
	// The main body of the routine; continuously select on one of the channels,
	// which indicate some event occurs, until an exit condition is met.
	for {
		// The channels we interact with on depend on how many clients and how many results we have.
		// Since this is dynamic, we can't do a fixed-size case statement and instead need to use reflect.Select.
		// This helper function iterates through the TransferEngine's internals with a read-lock held, building up
		// the list of work.
		cases, workMap, workKeys, resultsMap, resultsKeys := func() (cases []reflect.SelectCase, workMap map[uuid.UUID]chan *TransferJob, workKeys []uuid.UUID, resultsMap map[uuid.UUID]chan *TransferResults, resultsKeys []uuid.UUID) {
			te.clientLock.RLock()
			defer te.clientLock.RUnlock()
			workMap = make(map[uuid.UUID]chan *TransferJob, len(te.workMap))
			ctr := 0
			workKeys = make(uuid.UUIDs, 0)
			for key, val := range te.workMap {
				if val != nil {
					workKeys = append(workKeys, key)
				}
			}
			cases = make([]reflect.SelectCase, len(workKeys)+len(tmpResults)+7)
			sortFunc := func(a, b uuid.UUID) int {
				return bytes.Compare(a[:], b[:])
			}
			slices.SortFunc(workKeys, sortFunc)
			for _, key := range workKeys {
				workMap[key] = te.workMap[key]
				cases[ctr].Dir = reflect.SelectRecv
				cases[ctr].Chan = reflect.ValueOf(workMap[key])
				ctr++
			}
			resultsMap = make(map[uuid.UUID]chan *TransferResults, len(tmpResults))
			resultsKeys = make([]uuid.UUID, 0)
			for key := range tmpResults {
				resultsKeys = append(resultsKeys, key)
			}
			slices.SortFunc(resultsKeys, sortFunc)
			for _, key := range resultsKeys {
				resultsMap[key] = te.resultsMap[key]
				cases[ctr].Dir = reflect.SelectSend
				cases[ctr].Chan = reflect.ValueOf(resultsMap[key])
				cases[ctr].Send = reflect.ValueOf(tmpResults[key][0])
				ctr++
			}
			// Notification a new client has been started; recompute the channels
			cases[ctr].Dir = reflect.SelectRecv
			cases[ctr].Chan = reflect.ValueOf(te.notifyChan)
			// Notification that a transfer has finished.
			cases[ctr+1].Dir = reflect.SelectRecv
			cases[ctr+1].Chan = reflect.ValueOf(te.results)
			// Placeholder; never used.
			cases[ctr+2].Dir = reflect.SelectRecv
			cases[ctr+2].Chan = reflect.ValueOf(nil)
			// Notification that the TransferEngine has been cancelled; shutdown immediately
			cases[ctr+3].Dir = reflect.SelectRecv
			cases[ctr+3].Chan = reflect.ValueOf(te.ctx.Done())
			// Notification the translation from job-to-file has been completed.
			cases[ctr+4].Dir = reflect.SelectRecv
			cases[ctr+4].Chan = reflect.ValueOf(te.jobLookupDone)
			// Notification the transfer engine has been "closed".  No more jobs will come in
			// and shutdown can start.
			cases[ctr+5].Dir = reflect.SelectRecv
			cases[ctr+5].Chan = reflect.ValueOf(te.closeChan)
			// The transfer engine keeps statistics on the number of concurrent transfers occur
			// (this is later used to normalize the minimum transfer rate); this ticker periodically
			// will recalculate the average.
			cases[ctr+6].Dir = reflect.SelectRecv
			cases[ctr+6].Chan = reflect.ValueOf(te.ewmaTick.C)
			return
		}()
		if closing && len(workMap) == 0 && !closedWorkChan {
			// If there's no more incoming work, we can safely close the work channel
			// which will cause the job-to-file worker to shutdown.
			close(te.work)
			closedWorkChan = true
		}
		// Statement purposely left commented out; too heavyweight/noisy to leave in at runtime but useful for developer debugging.
		//log.Debugf("runMux running with %d active client channels and sending %d client responses", len(workMap), len(resultsMap))
		chosen, recv, ok := reflect.Select(cases)
		if chosen < len(workMap) {
			// One of the clients has produced work.  Send it to the central queue.
			id := workKeys[chosen]
			if !ok {
				// Client has closed its input channels.  See if we're done.
				func() {
					te.clientLock.Lock()
					defer te.clientLock.Unlock()
					te.workMap[id] = nil
				}()
				if activeJobs[id] == nil {
					close(te.resultsMap[id])
				}
				continue
			}
			job := recv.Interface().(*TransferJob)
			clientJob := &clientTransferJob{job: job, uuid: id}
			clientJobs := activeJobs[id]
			if clientJobs == nil {
				clientJobs = make([]*TransferJob, 0)
			}
			clientJobs = append(clientJobs, job)
			activeJobs[id] = clientJobs
			te.work <- clientJob
		} else if chosen < len(workMap)+len(resultsMap) {
			// One of the "write" channels has been sent some results.
			id := resultsKeys[chosen-len(workMap)]
			clientJob := tmpResults[id][0]
			job := clientJob.job
			job.activeXfer.Add(-1)
			if len(tmpResults[id]) == 1 {
				// The last result back to this client has been sent; delete the
				// slice from the map and check if the overall job is done.
				delete(tmpResults, id)
				// Test to see if the transfer job is done (true if job-to-file translation
				// has completed and there are no remaining active transfers)
				if job.lookupDone.Load() && job.activeXfer.Load() == 0 {
					log.Debugln("Job is done")
					if len(activeJobs[id]) == 1 {
						// Delete the job from the list of active jobs
						delete(activeJobs, id)
						func() {
							te.clientLock.Lock()
							defer te.clientLock.Unlock()
							// If the client is closed and there are no remaining
							// jobs for that client, we can close the results channel
							// for the client -- a clean shutdown of the client.
							if te.workMap[id] == nil {
								close(te.resultsMap[id])
							}
						}()
					} else {
						// Scan through the list of active jobs, removing the recently
						// completed one and saving the updated list.
						newJobList := make([]*TransferJob, 0, len(activeJobs[id]))
						for _, oldJob := range activeJobs[id] {
							if oldJob.uuid != job.uuid {
								newJobList = append(newJobList, oldJob)
							}
						}
						activeJobs[id] = newJobList
					}
				}
			} else {
				tmpResults[id] = tmpResults[id][1:]
			}
		} else if chosen == len(workMap)+len(resultsMap) {
			// The notify channel is meant to let the engine know
			// a new client has joined.  We should restart the for loop,
			// recalculating the channels with the new entry.
			continue
		} else if chosen == len(workMap)+len(resultsMap)+1 {
			// Receive transfer results from one of the engine's workers
			result := recv.Interface().(*clientTransferResults)
			if result == nil {
				te.workersActive--
				if te.workersActive == 0 {
					te.closeDoneChan <- true
					close(te.closeDoneChan)
					return nil
				}
			} else {
				resultBuffer := tmpResults[result.id]
				if resultBuffer == nil {
					resultBuffer = make([]*TransferResults, 0)
				}
				tmpResults[result.id] = append(resultBuffer, &result.results)
			}
		} else if chosen == len(workMap)+len(resultsMap)+3 {
			// Engine's context has been cancelled; immediately exit.
			log.Debugln("Transfer engine has been cancelled")
			close(te.closeDoneChan)
			return te.ctx.Err()
		} else if chosen == len(workMap)+len(resultsMap)+4 {
			// Notification that a job has been processed into files (or failed)
			job := recv.Interface().(*clientTransferJob)
			job.job.lookupDone.Store(true)
			// If no transfers were created and we have an error, the job is no
			// longer active
			if job.job.lookupErr != nil && job.job.totalXfer == 0 {
				// Remove this job from the list of active jobs for the client.
				activeJobs[job.uuid] = slices.DeleteFunc(activeJobs[job.uuid], func(oldJob *TransferJob) bool {
					return oldJob.uuid == job.job.uuid
				})
				if len(activeJobs[job.uuid]) == 0 {
					func() {
						te.clientLock.Lock()
						defer te.clientLock.Unlock()
						// If the client is closed and there are no remaining
						// jobs for that client, we can close the results channel.
						if te.workMap[job.uuid] == nil {
							close(te.resultsMap[job.uuid])
						}
					}()
				}
			}
		} else if chosen == len(workMap)+len(resultsMap)+5 {
			// Notification that the engine should shut down
			closing = true
			log.Debugln("Shutting down transfer engine")
			func() {
				te.clientLock.Lock()
				defer te.clientLock.Unlock()
				for _, channel := range te.workMap {
					if channel != nil {
						close(channel)
					}
				}
			}()
		} else {
			// EWMA tick.
			newVals := te.ewmaCtr.Swap(0)
			te.ewma.Add(float64(newVals))
			te.ewmaVal.Store(int64(te.ewma.Value()))
		}
	}
}

// Listen for new jobs on the engine's work queue and
// turn them into transferFile objects.
//
// Meant to be run as a standalone goroutine
func (te *TransferEngine) runJobHandler() error {
	for {
		select {
		case <-te.ctx.Done():
			log.Debugln("Job handler has been cancelled")
			return te.ctx.Err()
		case job, ok := <-te.work:
			if !ok {
				log.Debugln("Job handler has been shutdown")
				close(te.files)
				return nil
			}
			if job.job.ctx.Err() == context.Canceled {
				job.job.lookupErr = job.job.ctx.Err()
			} else {
				err := te.createTransferFiles(job)
				job.job.lookupErr = err
			}
			te.jobLookupDone <- job
		}
	}
}

// Create a new transfer job for the client
//
// The returned object can be further customized as desired.
// This function does not "submit" the job for execution.
func (tc *TransferClient) NewTransferJob(remoteUrl *url.URL, localPath string, engine *TransferEngine, upload bool, recursive bool, project string, options ...TransferOption) (tj *TransferJob, err error) {

	id, err := uuid.NewV7()
	if err != nil {
		return
	}

	pelicanURL, err := engine.NewPelicanURL(remoteUrl)
	if err != nil {
		err = errors.Wrap(err, "error generating metadata for specified url")
		return
	}

	copyUrl := *remoteUrl // Make a copy of the input URL to avoid concurrent issues.
	tj = &TransferJob{
		caches:        tc.caches,
		recursive:     recursive,
		localPath:     localPath,
		remoteURL:     &copyUrl,
		callback:      tc.callback,
		skipAcquire:   tc.skipAcquire,
		tokenLocation: tc.tokenLocation,
		upload:        upload,
		uuid:          id,
		token:         tc.token,
		project:       project,
	}
	tj.ctx, tj.cancel = context.WithCancel(tc.ctx)

	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionCaches{}:
			tj.caches = option.Value().([]*url.URL)
		case identTransferOptionCallback{}:
			tj.callback = option.Value().(TransferCallbackFunc)
		case identTransferOptionTokenLocation{}:
			tj.tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			tj.skipAcquire = !option.Value().(bool)
		case identTransferOptionToken{}:
			tj.token = option.Value().(string)
		}
	}

	tj.useDirector = pelicanURL.DirectorUrl != ""
	ns, err := getNamespaceInfo(remoteUrl.Path, pelicanURL.DirectorUrl, upload)
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
	}
	tj.namespace = ns

	if upload || ns.UseTokenOnRead && tj.token == "" {
		tj.token, err = getToken(remoteUrl, ns, true, "", tc.tokenLocation, !tj.skipAcquire)
		if err != nil {
			return nil, fmt.Errorf("failed to get token for transfer: %v", err)
		}
	}

	log.Debugf("Created new transfer job, ID %s client %s, for URL %s", tj.uuid.String(), tc.id.String(), remoteUrl.String())
	return
}

// Returns the status of the transfer job-to-file(s) lookup
//
// ok is true if the lookup has completed.
func (tj *TransferJob) GetLookupStatus() (ok bool, err error) {
	ok = tj.lookupDone.Load()
	if ok {
		err = tj.lookupErr
	}
	return
}

// Submit the transfer job to the client for processing
func (tc *TransferClient) Submit(tj *TransferJob) error {
	// Ensure that a tj.Wait() immediately after Submit will always block.
	log.Debugln("Submiting transfer job", tj.uuid.String())
	select {
	case <-tc.ctx.Done():
		return tc.ctx.Err()
	case tc.work <- tj:
		return nil
	}
}

// Close the transfer client object
//
// Any subsequent job submissions will cause a panic
func (tc *TransferClient) Close() {
	if !tc.closed {
		close(tc.work)
		tc.closed = true
	}
}

// Shutdown the transfer client
//
// Closes the client and waits for all jobs to exit cleanly.  Returns
// any results that were pending when Shutdown was called
func (tc *TransferClient) Shutdown() (results []TransferResults, err error) {
	tc.Close()
	results = make([]TransferResults, 0)
	resultsChan := tc.Results()
	for {
		select {
		case <-tc.ctx.Done():
			err = tc.ctx.Err()
			return
		case result, ok := <-resultsChan:
			if !ok {
				return
			}
			results = append(results, result)
		}
	}
}

// Return a channel containing the results from the client
func (tc *TransferClient) Results() chan TransferResults {
	tc.setupResults.Do(func() {
		tc.finalResults = make(chan TransferResults)
		go func() {
			for {
				select {
				case <-tc.ctx.Done():
					return
				case result, ok := <-tc.results:
					if !ok {
						close(tc.finalResults)
						return
					}
					newResult := *result
					newResult.job = nil
					tc.finalResults <- newResult
				}
			}
		}()
	})
	return tc.finalResults
}

// Cancel a client
//
// When cancelled, all channels and goroutines associated with
// the client will close/exit immediately.
func (tc *TransferClient) Cancel() {
	tc.cancel()
}

// Cancel the transfer job
func (tj *TransferJob) Cancel() {
	tj.cancel()
}

// Get the transfer's ID
func (tj *TransferJob) ID() string {
	return tj.uuid.String()
}

// newTransferDetails creates the TransferDetails struct with the given cache
func newTransferDetails(cache namespaces.Cache, opts transferDetailsOptions) []transferAttemptDetails {
	details := make([]transferAttemptDetails, 0)
	var cacheEndpoint string
	if opts.NeedsToken {
		cacheEndpoint = cache.AuthEndpoint
	} else {
		cacheEndpoint = cache.Endpoint
	}

	// Form the URL
	cacheURL, err := url.Parse(cacheEndpoint)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Scheme == "unix" && cacheURL.Host != "" {
		cacheURL.Path = path.Clean("/" + cacheURL.Host + "/" + cacheURL.Path)
		cacheURL.Host = ""
	} else if cacheURL.Scheme != "unix" && cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cacheEndpoint
		cacheURL.Path = ""
		cacheURL.Scheme = ""
		cacheURL.Opaque = ""
	}
	log.Debugf("Parsed Cache: %s", cacheURL.String())
	if opts.NeedsToken {
		if cacheURL.Scheme != "unix" {
			cacheURL.Scheme = "https"
			if !hasPort(cacheURL.Host) {
				// Add port 8444 and 8443
				urlCopy := *cacheURL
				urlCopy.Host += ":8444"
				details = append(details, transferAttemptDetails{
					Url:        &urlCopy,
					Proxy:      false,
					PackOption: opts.PackOption,
				})
				// Strip the port off and add 8443
				cacheURL.Host = cacheURL.Host + ":8443"
			}
		}
		det := transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if cacheURL.Scheme == "unix" {
			det.UnixSocket = cacheURL.Path
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, det)
	} else if cacheURL.Scheme == "" || cacheURL.Scheme == "http" {
		cacheURL.Scheme = "http"
		if !hasPort(cacheURL.Host) {
			cacheURL.Host += ":8000"
		}
		isProxyEnabled := isProxyEnabled()
		details = append(details, transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      isProxyEnabled,
			PackOption: opts.PackOption,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, transferAttemptDetails{
				Url:        cacheURL,
				Proxy:      false,
				PackOption: opts.PackOption,
			})
		}
	} else {
		det := transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if cacheURL.Scheme == "unix" {
			det.UnixSocket = cacheURL.Path
		}
		details = append(details, det)
	}

	return details
}

type CacheInterface interface{}

func generateTransferDetailsUsingCache(cache CacheInterface, opts transferDetailsOptions) []transferAttemptDetails {
	if directorCache, ok := cache.(namespaces.DirectorCache); ok {
		return newTransferDetailsUsingDirector(directorCache, opts)
	} else if cache, ok := cache.(namespaces.Cache); ok {
		return newTransferDetails(cache, opts)
	}
	return nil
}

// Take a transfer job and produce one or more transfer file requests.
// The transfer file requests are sent to be processed via the engine
func (te *TransferEngine) createTransferFiles(job *clientTransferJob) (err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in createTransferFiles:", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) occurred in createTransferFiles: %v", r)
			err = errors.New(ret)
		}
	}()

	log.Debugln("Processing transfer job for URL", job.job.remoteURL.String())

	packOption := job.job.remoteURL.Query().Get("pack")
	if packOption != "" {
		log.Debugln("Will use unpack option value", packOption)
	}
	remoteUrl := &url.URL{Path: job.job.remoteURL.Path, Scheme: job.job.remoteURL.Scheme}

	var transfers []transferAttemptDetails
	if job.job.upload { // Uploads use the redirected endpoint directly
		endpoint, err := url.Parse(job.job.namespace.WriteBackHost)
		if err != nil {
			return errors.Wrap(err, "Invalid URL returned by director for PUT")
		}
		transfers = append(transfers, transferAttemptDetails{
			Url:        endpoint,
			PackOption: packOption,
		})
	} else {
		var closestNamespaceCaches []CacheInterface
		closestNamespaceCaches, err = getCachesFromNamespace(job.job.namespace, job.job.useDirector, job.job.caches)
		if err != nil {
			log.Errorln("Failed to get namespaced caches (treated as non-fatal):", err)
		}

		log.Debugln("Matched caches:", closestNamespaceCaches)

		// Make sure we only try as many caches as we have
		cachesToTry := CachesToTry
		if cachesToTry > len(closestNamespaceCaches) {
			cachesToTry = len(closestNamespaceCaches)
		}
		log.Debugln("Trying the caches:", closestNamespaceCaches[:cachesToTry])

		for _, cache := range closestNamespaceCaches[:cachesToTry] {
			// Parse the cache URL
			log.Debugln("Cache:", cache)
			td := transferDetailsOptions{
				NeedsToken: job.job.namespace.ReadHTTPS || job.job.namespace.UseTokenOnRead,
				PackOption: packOption,
			}
			transfers = append(transfers, generateTransferDetailsUsingCache(cache, td)...)
		}

		if len(transfers) > 0 {
			log.Debugln("Transfers:", transfers[0].Url)
		} else {
			log.Debugln("No transfers possible as no caches are found")
			err = errors.New("No transfers possible as no caches are found")
			return
		}
	}

	if job.job.recursive {
		if job.job.upload {
			return te.walkDirUpload(job, transfers, te.files, job.job.localPath)
		} else {
			return te.walkDirDownload(job, transfers, te.files, remoteUrl)
		}
	}

	job.job.totalXfer += 1
	job.job.activeXfer.Add(1)
	te.files <- &clientTransferFile{
		uuid:  job.uuid,
		jobId: job.job.uuid,
		file: &transferFile{
			ctx:        job.job.ctx,
			callback:   job.job.callback,
			job:        job.job,
			engine:     te,
			remoteURL:  remoteUrl,
			packOption: packOption,
			localPath:  job.job.localPath,
			upload:     job.job.upload,
			token:      job.job.token,
			attempts:   transfers,
			project:    job.job.project,
		},
	}

	return
}

// Start a transfer worker in the current goroutine.
// The transfer workers read in transfers to perform on `workChan` and write out
// the results of the transfer attempt on `results`.
func runTransferWorker(ctx context.Context, workChan <-chan *clientTransferFile, results chan<- *clientTransferResults) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case file, ok := <-workChan:
			if !ok {
				// If the transfer engine is cancelled while a shutdown is occurring, the
				// write to the results channel may block.  Hence, we should see if we're
				// cancelled while the write is pending.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case results <- nil:
					return nil
				}
			}
			if file.file.ctx.Err() == context.Canceled {
				results <- &clientTransferResults{
					id: file.uuid,
					results: TransferResults{
						jobId: file.jobId,
						Error: file.file.ctx.Err(),
					},
				}
				break
			}
			if file.file.err != nil {
				results <- &clientTransferResults{
					id: file.uuid,
					results: TransferResults{
						jobId: file.jobId,
						Error: file.file.err,
					},
				}
				break
			}
			var err error
			var transferResults TransferResults
			if file.file.upload {
				transferResults, err = uploadObject(file.file)
			} else {
				transferResults, err = downloadObject(file.file)
			}
			transferResults.jobId = file.jobId
			transferResults.Scheme = file.file.remoteURL.Scheme
			if err != nil {
				log.Errorf("Error when attempting to transfer object %s for client %s: %v", file.file.remoteURL, file.uuid.String(), err)
				transferResults = newTransferResults(file.file.job)
				transferResults.Scheme = file.file.remoteURL.Scheme
				transferResults.Error = err
			} else if transferResults.Error == nil {
				xferErrors := NewTransferErrors()
				lastXferGood := false
				for _, attempt := range transferResults.Attempts {
					if attempt.Error == nil {
						lastXferGood = true
					} else {
						xferErrors.AddError(attempt.Error)
					}
				}
				if !lastXferGood {
					transferResults.Error = xferErrors
				}
			}
			results <- &clientTransferResults{id: file.uuid, results: transferResults}
		}
	}
}

// If there are multiple potential attempts, try to see if we can quickly eliminate some of them
//
// Attempts a HEAD against all the endpoints simultaneously.  Put any that don't respond within
// a second behind those that do respond.
func sortAttempts(ctx context.Context, path string, attempts []transferAttemptDetails) (size int64, results []transferAttemptDetails) {
	size = -1
	if len(attempts) < 2 {
		results = attempts
		return
	}
	transport := config.GetTransport()
	headChan := make(chan struct {
		idx  int
		size uint64
		err  error
	})
	defer close(headChan)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for idx, transferEndpoint := range attempts {
		tUrl := *transferEndpoint.Url
		tUrl.Path = path

		go func(idx int, tUrl string) {
			headClient := &http.Client{Transport: transport}
			headRequest, _ := http.NewRequestWithContext(ctx, "HEAD", tUrl, nil)
			var headResponse *http.Response
			headResponse, err := headClient.Do(headRequest)
			if err != nil {
				headChan <- struct {
					idx  int
					size uint64
					err  error
				}{idx, 0, err}
				return
			}
			headResponse.Body.Close()
			contentLengthStr := headResponse.Header.Get("Content-Length")
			size := int64(0)
			if contentLengthStr != "" {
				size, err = strconv.ParseInt(contentLengthStr, 10, 64)
				if err != nil {
					err = errors.Wrap(err, "problem converting Content-Length in response to an int")
					log.Errorln(err.Error())

				}
			}
			headChan <- struct {
				idx  int
				size uint64
				err  error
			}{idx, uint64(size), err}
		}(idx, tUrl.String())
	}
	// 1 -> success.
	// 0 -> pending.
	// -1 -> error.
	finished := make(map[int]int)
	for ctr := 0; ctr != len(attempts); ctr++ {
		result := <-headChan
		if result.err != nil {
			if result.err != context.Canceled {
				log.Debugf("Failure when doing a HEAD request against %s: %s", attempts[result.idx].Url.String(), result.err.Error())
				finished[result.idx] = -1
			}
		} else {
			finished[result.idx] = 1
			if result.idx == 0 {
				cancel()
				// If the first responds successfully, we want to return immediately instead of giving
				// the other caches time to respond - the result is "good enough".
				// - Any cache with confirmed errors (-1) is sorted to the back.
				// - Any cache which is still pending (0) is kept in place.
				for ctr := 0; ctr < len(attempts); ctr++ {
					finished[ctr] = 1
				}
			}
			if size <= int64(result.size) {
				size = int64(result.size)
			}
		}
	}
	// Sort all the successful attempts first; use stable sort so the original ordering
	// is preserved if the two entries are both successful or both unsuccessful.
	type sorter struct {
		good    int
		attempt transferAttemptDetails
	}
	tmpResults := make([]sorter, len(attempts))
	for idx, attempt := range attempts {
		tmpResults[idx] = sorter{finished[idx], attempt}
	}
	results = make([]transferAttemptDetails, len(attempts))
	slices.SortStableFunc(tmpResults, func(left sorter, right sorter) int {
		if left.good > right.good {
			return -1
		}
		return 0
	})
	for idx, val := range tmpResults {
		results[idx] = val.attempt
	}
	return
}

func downloadObject(transfer *transferFile) (transferResults TransferResults, err error) {
	log.Debugln("Downloading file from", transfer.remoteURL, "to", transfer.localPath)
	// Remove the source from the file path
	directory := path.Dir(transfer.localPath)
	var downloaded int64
	if err = os.MkdirAll(directory, 0700); err != nil {
		return
	}

	size, attempts := sortAttempts(transfer.job.ctx, transfer.remoteURL.Path, transfer.attempts)

	transferResults = newTransferResults(transfer.job)
	success := false
	for idx, transferEndpoint := range attempts { // For each transfer attempt (usually 3), try to download via HTTP
		var attempt TransferResult
		var timeToFirstByte float64
		var serverVersion string
		attempt.Number = idx // Start with 0
		attempt.Endpoint = transferEndpoint.Url.Host
		// Make a copy of the transfer endpoint URL; otherwise, when we mutate the pointer, other parallel
		// workers might download from the wrong path.
		transferEndpointUrl := *transferEndpoint.Url
		transferEndpointUrl.Path = transfer.remoteURL.Path
		transferEndpoint.Url = &transferEndpointUrl
		transferStartTime := time.Now()
		if downloaded, timeToFirstByte, serverVersion, err = downloadHTTP(transfer.ctx, transfer.engine, transfer.callback, transferEndpoint, transfer.localPath, size, transfer.token, transfer.project); err != nil {
			log.Debugln("Failed to download:", err)
			transferEndTime := time.Now()
			transferTime := transferEndTime.Unix() - transferStartTime.Unix()
			attempt.TransferTime = transferTime
			var ope *net.OpError
			var cse *ConnectionSetupError
			errorString := "Failed to download from " + transferEndpoint.Url.Hostname() + ":" +
				transferEndpoint.Url.Port() + " "
			if errors.As(err, &ope) && ope.Op == "proxyconnect" {
				log.Debugln(ope)
				AddrString, _ := os.LookupEnv("http_proxy")
				if ope.Addr != nil {
					AddrString = " " + ope.Addr.String()
				}
				errorString += "due to proxy " + AddrString + " error: " + ope.Unwrap().Error()
			} else if errors.As(err, &cse) {
				errorString += "+ proxy=" + strconv.FormatBool(transferEndpoint.Proxy) + ": "
				if sce, ok := cse.Unwrap().(grab.StatusCodeError); ok {
					errorString += sce.Error()
				} else {
					errorString += err.Error()
				}
			} else {
				errorString += "+ proxy=" + strconv.FormatBool(transferEndpoint.Proxy) +
					": " + err.Error()
			}
			attempt.TransferFileBytes = downloaded
			attempt.TimeToFirstByte = timeToFirstByte
			attempt.Error = errors.New(errorString)
			attempt.TransferEndTime = transferEndTime.Unix()
			attempt.ServerVersion = serverVersion
			transferResults.Attempts = append(transferResults.Attempts, attempt)
		} else { // Success
			transferEndTime := time.Now()
			transferTime := transferEndTime.Unix() - transferStartTime.Unix()
			attempt.TransferEndTime = transferEndTime.Unix()
			attempt.TransferTime = transferTime
			attempt.TimeToFirstByte = timeToFirstByte
			attempt.TransferFileBytes = downloaded
			attempt.ServerVersion = serverVersion
			log.Debugln("Downloaded bytes:", downloaded)
			transferResults.Attempts = append(transferResults.Attempts, attempt)
			success = true
			break
		}
	}
	transferResults.TransferredBytes = downloaded
	if !success {
		log.Debugln("Failed to download with HTTP")
		transferResults.Error = errors.New("failed to download with HTTP")
	}
	return
}

func parseTransferStatus(status string) (int, string) {
	parts := strings.SplitN(status, ": ", 2)
	if len(parts) != 2 {
		return 0, ""
	}

	statusCode, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, ""
	}

	return statusCode, strings.TrimSpace(parts[1])
}

// Perform the actual download of the file
//
// Returns the downloaded size, time to 1st byte downloaded, serverVersion and an error if there is one
func downloadHTTP(ctx context.Context, te *TransferEngine, callback TransferCallbackFunc, transfer transferAttemptDetails, dest string, totalSize int64, token string, project string) (downloaded int64, timeToFirstByte float64, serverVersion string, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in downloadHTTP:", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) occurred in downloadHTTP: %v", r)
			err = errors.New(ret)
		}
	}()

	lastUpdate := time.Now()
	if callback != nil {
		callback(dest, 0, 0, false)
	}
	defer func() {
		if callback != nil {
			finalSize := int64(0)
			if totalSize >= 0 {
				finalSize = totalSize
			}
			callback(dest, downloaded, finalSize, true)
		}
		if te != nil {
			te.ewmaCtr.Add(int64(time.Since(lastUpdate)))
		}
	}()

	// Create the client, request, and context
	client := grab.NewClient()
	client.UserAgent = getUserAgent(project)
	transport := config.GetTransport()
	if !transfer.Proxy {
		transport.Proxy = nil
	}
	transferUrl := *transfer.Url
	if transfer.Url.Scheme == "unix" {
		transport.Proxy = nil // Proxies make no sense when reading via a Unix socket
		transport = transport.Clone()
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", transfer.UnixSocket)
		}
		transferUrl.Scheme = "http"
		// The host is ignored since we override the dial function; however, I find it useful
		// in debug messages to see that this went to the local cache.
		transferUrl.Host = "localhost"
	}
	httpClient, ok := client.HTTPClient.(*http.Client)
	if !ok {
		return 0, 0, "", errors.New("Internal error: implementation is not a http.Client type")
	}
	httpClient.Transport = transport

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.Debugln("Transfer URL String:", transferUrl.String())
	var req *grab.Request
	var unpacker *autoUnpacker
	if transfer.PackOption != "" {
		behavior, err := GetBehavior(transfer.PackOption)
		if err != nil {
			return 0, 0, "", err
		}
		if dest == "." {
			dest, err = os.Getwd()
			if err != nil {
				return 0, 0, "", errors.Wrap(err, "Failed to get current directory for destination")
			}
		}
		unpacker = newAutoUnpacker(dest, behavior)
		if req, err = grab.NewRequestToWriter(unpacker, transferUrl.String()); err != nil {
			return 0, 0, "", errors.Wrap(err, "Failed to create new download request")
		}
	} else if req, err = grab.NewRequest(dest, transferUrl.String()); err != nil {
		return 0, 0, "", errors.Wrap(err, "Failed to create new download request")
	}

	rateLimit := param.Client_MaximumDownloadSpeed.GetInt()
	if rateLimit > 0 {
		req.RateLimiter = rate.NewLimiter(rate.Limit(rateLimit), 64*1024)
	}

	if token != "" {
		req.HTTPRequest.Header.Set("Authorization", "Bearer "+token)
	}
	// Set the headers
	req.HTTPRequest.Header.Set("X-Transfer-Status", "true")
	req.HTTPRequest.Header.Set("X-Pelican-Timeout", param.Transport_ResponseHeaderTimeout.GetDuration().String())
	req.HTTPRequest.Header.Set("TE", "trailers")
	req.HTTPRequest.Header.Set("User-Agent", getUserAgent(project))
	req = req.WithContext(ctx)

	// Test the transfer speed every 5 seconds
	t := time.NewTicker(5000 * time.Millisecond)
	defer t.Stop()

	// Progress ticker
	progressTicker := time.NewTicker(100 * time.Millisecond)
	defer progressTicker.Stop()
	downloadLimit := param.Client_MinimumDownloadSpeed.GetInt()

	// Start the transfer
	log.Debugln("Starting the HTTP transfer...")
	downloadStart := time.Now()
	resp := client.Do(req)
	// Check the error real quick
	if resp.IsComplete() {
		if err = resp.Err(); err != nil {
			if errors.Is(err, grab.ErrBadLength) {
				err = fmt.Errorf("Local copy of file is larger than remote copy %w", grab.ErrBadLength)
			}
			log.Errorln("Failed to download:", err)
			err = &ConnectionSetupError{Err: err}
			return
		}
	}
	serverVersion = resp.HTTPResponse.Header.Get("Server")

	// Size of the download
	totalSize = resp.Size()
	// Do a head request for content length if resp.Size is unknown
	if totalSize <= 0 && !resp.IsComplete() {
		headClient := &http.Client{Transport: transport}
		headRequest, _ := http.NewRequest("HEAD", transferUrl.String(), nil)
		var headResponse *http.Response
		headResponse, err = headClient.Do(headRequest)
		if err != nil {
			log.Errorln("Could not successfully get response for HEAD request")
			err = errors.Wrap(err, "Could not determine the size of the remote object")
			return
		}
		headResponse.Body.Close()
		contentLengthStr := headResponse.Header.Get("Content-Length")
		if contentLengthStr != "" {
			totalSize, err = strconv.ParseInt(contentLengthStr, 10, 64)
			if err != nil {
				log.Errorln("problem converting content-length to an int:", err)
				totalSize = 0
			}
		}
	}
	if callback != nil {
		callback(dest, 0, totalSize, false)
	}

	stoppedTransferTimeout := int64(param.Client_StoppedTransferTimeout.GetInt())
	slowTransferRampupTime := int64(param.Client_SlowTransferRampupTime.GetInt())
	slowTransferWindow := int64(param.Client_SlowTransferWindow.GetInt())
	var startBelowLimit int64 = 0
	var noProgressStartTime time.Time
	var lastBytesComplete int64
	timeToFirstByteRecorded := false
	// Loop of the download
Loop:
	for {
		if !timeToFirstByteRecorded && resp.BytesComplete() > 1 {
			// We get the time since in nanoseconds:
			timeToFirstByteNs := time.Since(downloadStart)
			// Convert to seconds
			timeToFirstByte = float64(timeToFirstByteNs.Round(time.Millisecond).Milliseconds()) / 1000.0
			timeToFirstByteRecorded = true
		}
		select {
		case <-progressTicker.C:
			downloaded = resp.BytesComplete()
			currentTime := time.Now()
			if te != nil {
				te.ewmaCtr.Add(int64(currentTime.Sub(lastUpdate)))
			}
			lastUpdate = currentTime
			if callback != nil {
				callback(dest, downloaded, totalSize, false)
			}

		case <-t.C:
			// Check that progress is being made and that it is not too slow
			downloaded = resp.BytesComplete()
			if downloaded == lastBytesComplete {
				if noProgressStartTime.IsZero() {
					noProgressStartTime = time.Now()
				} else if time.Since(noProgressStartTime) > time.Duration(stoppedTransferTimeout)*time.Second {
					errMsg := "No progress for more than " + time.Since(noProgressStartTime).Truncate(time.Millisecond).String()
					log.Errorln(errMsg)
					err = &StoppedTransferError{
						Err: errMsg,
					}
					return
				}
			} else {
				noProgressStartTime = time.Time{}
			}
			lastBytesComplete = resp.BytesComplete()

			// Check if we are downloading fast enough
			limit := float64(downloadLimit)
			var concurrency float64 = 1
			if te != nil {
				concurrency = float64(te.ewmaVal.Load()) / float64(ewmaInterval)
			}
			if concurrency > 1 {
				limit /= concurrency
			}
			if resp.BytesPerSecond() < limit {
				// Give the download `slowTransferRampupTime` (default 120) seconds to start
				if resp.Duration() < time.Second*time.Duration(slowTransferRampupTime) {
					continue
				} else if startBelowLimit == 0 {
					warning := []byte("Warning! Downloading too slow...\n")
					status, err := getProgressContainer().Write(warning)
					if err != nil {
						log.Errorln("Problem displaying slow message", err, status)
						continue
					}
					startBelowLimit = time.Now().Unix()
					continue
				} else if (time.Now().Unix() - startBelowLimit) < slowTransferWindow {
					// If the download is below the threshold for less than `SlowTransferWindow` (default 30) seconds, continue
					continue
				}
				// The download is below the threshold for more than `SlowTransferWindow` seconds, cancel the download
				cancel()

				log.Errorln("Cancelled: Download speed of ", resp.BytesPerSecond(), "bytes/s", " is below the limit of", downloadLimit, "bytes/s")

				err = &SlowTransferError{
					BytesTransferred: resp.BytesComplete(),
					BytesPerSecond:   int64(resp.BytesPerSecond()),
					Duration:         resp.Duration(),
					BytesTotal:       totalSize,
				}
				return

			} else {
				// The download is fast enough, reset the startBelowLimit
				startBelowLimit = 0
			}

		case <-resp.Done:
			downloaded = resp.BytesComplete()
			break Loop
		}
	}
	err = resp.Err()
	if err != nil {
		// Connection errors
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNABORTED) {
			err = &ConnectionSetupError{URL: resp.Request.URL().String()}
			return
		}
		log.Debugln("Got error from HTTP download", err)
		return
	} else {
		// Check the trailers for any error information
		trailer := resp.HTTPResponse.Trailer
		if errorStatus := trailer.Get("X-Transfer-Status"); errorStatus != "" {
			statusCode, statusText := parseTransferStatus(errorStatus)
			if statusCode != 200 {
				log.Debugln("Got error from file transfer")
				err = errors.New("transfer error: " + statusText)
				return
			}
		}
	}
	// Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
	// prior attempt.
	if resp.HTTPResponse.StatusCode != 200 && resp.HTTPResponse.StatusCode != 206 {
		log.Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return 0, 0, serverVersion, &HttpErrResp{resp.HTTPResponse.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s",
			resp.HTTPResponse.StatusCode, resp.Err().Error())}
	}

	if unpacker != nil {
		unpacker.Close()
		if err = unpacker.Error(); err != nil {
			return
		}
	}

	log.Debugln("HTTP Transfer was successful")
	return
}

type Sizer interface {
	Size() int64
	BytesComplete() int64
}

type ConstantSizer struct {
	size int64
	read atomic.Int64
}

func (cs *ConstantSizer) Size() int64 {
	return cs.size
}

func (cs *ConstantSizer) BytesComplete() int64 {
	return cs.read.Load()
}

// ProgressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type ProgressReader struct {
	reader io.ReadCloser
	sizer  Sizer
	closed chan bool
}

// Read implements the common read function for io.Reader
func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	if cs, ok := pr.sizer.(*ConstantSizer); ok {
		cs.read.Add(int64(n))
	}
	return n, err
}

// Close implments the close function of io.Closer
func (pr *ProgressReader) Close() error {
	err := pr.reader.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

func (pr *ProgressReader) BytesComplete() int64 {
	return pr.sizer.BytesComplete()
}

func (pr *ProgressReader) Size() int64 {
	return pr.sizer.Size()
}

// Upload a single object to the origin
func uploadObject(transfer *transferFile) (transferResult TransferResults, err error) {
	log.Debugln("Uploading file to destination", transfer.remoteURL)
	transferResult.job = transfer.job

	var sizer Sizer = &ConstantSizer{size: 0}
	var downloaded int64 = 0
	if transfer.callback != nil {
		transfer.callback(transfer.localPath, downloaded, sizer.Size(), false)
		defer func() {
			transfer.callback(transfer.localPath, downloaded, sizer.Size(), true)
		}()
	}

	var attempt TransferResult
	// Stat the file to get the size (for progress bar)
	fileInfo, err := os.Stat(transfer.localPath)
	transferResult.Scheme = transfer.remoteURL.Scheme
	if err != nil {
		log.Errorln("Error checking local file ", transfer.localPath, ":", err)
		transferResult.Error = err
		return transferResult, err
	}

	var ioreader io.ReadCloser
	nonZeroSize := true
	pack := transfer.packOption
	if pack != "" {
		if !fileInfo.IsDir() {
			err = errors.Errorf("Upload with pack=%v only works when input (%v) is a directory", pack, transfer.localPath)
			transferResult.Error = err
			return transferResult, err
		}
		behavior, err := GetBehavior(pack)
		if err != nil {
			transferResult.Error = err
			return transferResult, err
		}
		if behavior == autoBehavior {
			behavior = defaultBehavior
		}
		ap := newAutoPacker(transfer.localPath, behavior)
		ioreader = ap
		sizer = ap
	} else {
		// Try opening the file to send
		file, err := os.Open(transfer.localPath)
		if err != nil {
			log.Errorln("Error opening local file:", err)
			transferResult.Error = err
			return transferResult, err
		}
		ioreader = file
		sizer = &ConstantSizer{size: fileInfo.Size()}
		nonZeroSize = fileInfo.Size() > 0
	}
	if transfer.callback != nil {
		transfer.callback(transfer.localPath, downloaded, sizer.Size(), false)
	}

	// Parse the writeback host as a URL
	writebackhostUrl := transfer.attempts[0].Url

	dest := &url.URL{
		Host:   writebackhostUrl.Host,
		Scheme: "https",
		Path:   transfer.remoteURL.Path,
	}
	attempt.Endpoint = dest.Host
	// Create the wrapped reader and send it to the request
	closed := make(chan bool, 1)
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	reader := &ProgressReader{ioreader, sizer, closed}
	putContext, cancel := context.WithCancel(transfer.ctx)
	transferStartTime := time.Now()
	defer cancel()
	log.Debugln("Full destination URL:", dest.String())
	var request *http.Request
	// For files that are 0 length, we need to send a PUT request with an nil body
	if nonZeroSize {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), reader)
	} else {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		transferResult.Error = err
		return transferResult, err
	}
	// Set the authorization header
	request.Header.Set("Authorization", "Bearer "+transfer.token)
	request.Header.Set("User-Agent", getUserAgent(transfer.project))
	var lastKnownWritten int64
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	uploadStart := time.Now()

	go runPut(request, responseChan, errorChan)
	var lastError error = nil

	tickerDuration := 100 * time.Millisecond
	progressTicker := time.NewTicker(tickerDuration)
	firstByteRecorded := false
	defer progressTicker.Stop()

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		if !firstByteRecorded && reader.BytesComplete() > 1 {
			// We get the time since in nanoseconds:
			timeToFirstByteNs := time.Since(uploadStart)
			// Convert to seconds
			attempt.TimeToFirstByte = float64(timeToFirstByteNs.Round(time.Millisecond).Milliseconds()) / 1000.0
			firstByteRecorded = true
		}
		select {
		case <-progressTicker.C:
			if transfer.callback != nil {
				transfer.callback(transfer.localPath, reader.BytesComplete(), sizer.Size(), false)
			}

		case <-t.C:
			// If we are not making any progress, if we haven't written 1MB in the last 5 seconds
			currentRead := reader.BytesComplete()
			log.Debugln("Current read:", currentRead)
			log.Debugln("Last known written:", lastKnownWritten)
			if lastKnownWritten < currentRead {
				// We have made progress!
				lastKnownWritten = currentRead
			} else {
				// No progress has been made in the last 1 second
				log.Errorln("No progress made in last 5 second in upload")
				lastError = errors.New("upload cancelled, no progress in 5 seconds")
				break Loop
			}

		case <-closed:
			// The file has been closed, we're done here
			log.Debugln("File closed")
		case response := <-responseChan:
			attempt.ServerVersion = response.Header.Get("Server")
			if response.StatusCode != 200 {
				log.Errorln("Got failure status code:", response.StatusCode)
				lastError = &HttpErrResp{response.StatusCode, fmt.Sprintf("Request failed (HTTP status %d)",
					response.StatusCode)}
				break Loop
			}
			break Loop

		case err := <-errorChan:
			log.Warningln("Unexpected error when performing upload:", err)
			lastError = err
			break Loop

		}
	}

	if fileInfo.Size() == 0 {
		transferResult.Error = lastError
		transferEndTime := time.Now()
		attempt.TransferEndTime = transferEndTime.Unix()
		attempt.TransferTime = attempt.TransferEndTime - transferStartTime.Unix()

		// Add our attempt fields
		transferResult.Attempts = append(transferResult.Attempts, attempt)
		return transferResult, lastError
	} else {
		log.Debugln("Uploaded bytes:", reader.BytesComplete())
		transferResult.TransferredBytes = reader.BytesComplete()
		transferEndTime := time.Now()
		attempt.TransferEndTime = transferEndTime.Unix()
		attempt.TransferTime = attempt.TransferEndTime - transferStartTime.Unix()

		// Add our attempt fields
		transferResult.Attempts = append(transferResult.Attempts, attempt)
		return transferResult, lastError
	}

}

// Actually perform the HTTP PUT request to the server.
//
// This is executed in a separate goroutine to allow periodic progress callbacks
// to be created within the main goroutine.
func runPut(request *http.Request, responseChan chan<- *http.Response, errorChan chan<- error) {
	var UploadClient = &http.Client{Transport: config.GetTransport()}
	client := UploadClient
	dump, _ := httputil.DumpRequestOut(request, false)
	log.Debugf("Dumping request: %s", dump)
	response, err := client.Do(request)
	if err != nil {
		log.Errorln("Error with PUT:", err)
		errorChan <- err
		return
	}
	dump, _ = httputil.DumpResponse(response, true)
	log.Debugf("Dumping response: %s", dump)
	if response.StatusCode != 200 {
		log.Errorln("Error status code:", response.Status)
		log.Debugln("From the server:")
		textResponse, err := io.ReadAll(response.Body)
		if err != nil {
			log.Errorln("Error reading response from server:", err)
			responseChan <- response
			return
		}
		log.Debugln(string(textResponse))
	}
	responseChan <- response

}

// Walk a remote directory in a WebDAV server, emitting the files discovered
func (te *TransferEngine) walkDirDownload(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, url *url.URL) error {
	// Create the client to walk the filesystem
	rootUrl := *url
	if job.job.namespace.DirListHost != "" {
		// Parse the dir list host
		dirListURL, err := url.Parse(job.job.namespace.DirListHost)
		if err != nil {
			log.Errorln("Failed to parse dirlisthost from namespaces into URL:", err)
			return err
		}
		rootUrl = *dirListURL

	} else {
		log.Errorln("Host for directory listings is unknown")
		return errors.New("Host for directory listings is unknown")
	}
	log.Debugln("Dir list host: ", rootUrl.String())

	auth := &bearerAuth{token: job.job.token}
	client := gowebdav.NewAuthClient(rootUrl.String(), auth)

	// XRootD does not like keep alives and kills things, so turn them off.
	transport := config.GetTransport()
	client.SetTransport(transport)
	return te.walkDirDownloadHelper(job, transfers, files, url.Path, client)
}

// Helper function for the `walkDirDownload`.
//
// Recursively walks through the remote server directory, emitting transfer files
// for the engine to process.
func (te *TransferEngine) walkDirDownloadHelper(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, remotePath string, client *gowebdav.Client) error {
	// Check for cancelation since the client does not respect the context
	if err := job.job.ctx.Err(); err != nil {
		return err
	}
	infos, err := client.ReadDir(remotePath)
	if err != nil {
		return err
	}
	localBase := strings.TrimPrefix(remotePath, job.job.remoteURL.Path)
	for _, info := range infos {
		newPath := remotePath + "/" + info.Name()
		if info.IsDir() {
			err := te.walkDirDownloadHelper(job, transfers, files, newPath, client)
			if err != nil {
				return err
			}
		} else {
			job.job.activeXfer.Add(1)
			select {
			case <-job.job.ctx.Done():
				return job.job.ctx.Err()
			case files <- &clientTransferFile{
				uuid:  job.uuid,
				jobId: job.job.uuid,
				file: &transferFile{
					ctx:        job.job.ctx,
					callback:   job.job.callback,
					job:        job.job,
					engine:     te,
					remoteURL:  &url.URL{Path: newPath},
					packOption: transfers[0].PackOption,
					localPath:  path.Join(job.job.localPath, localBase, info.Name()),
					upload:     job.job.upload,
					token:      job.job.token,
					attempts:   transfers,
				},
			}:
			}
		}
	}
	return nil
}

// Walk a local directory structure, writing all discovered files to the files channel
func (te *TransferEngine) walkDirUpload(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, localPath string) error {
	if job.job.ctx.Err() != nil {
		return job.job.ctx.Err()
	}

	// Get our list of directory entries
	infos, err := os.ReadDir(localPath)
	if err != nil {
		return err
	}

	for _, info := range infos {
		newPath := localPath + "/" + info.Name()
		if info.IsDir() {
			// Recursively call this function to create any nested dir's as well as list their files
			err := te.walkDirUpload(job, transfers, files, newPath)
			if err != nil {
				return err
			}
		} else if info.Type().IsRegular() {
			// It is a normal file; strip off the path prefix and append the destination prefix
			remotePath := path.Join(job.job.remoteURL.Path, strings.TrimPrefix(newPath, job.job.localPath))
			job.job.activeXfer.Add(1)
			select {
			case <-job.job.ctx.Done():
				return job.job.ctx.Err()
			case files <- &clientTransferFile{
				uuid:  job.uuid,
				jobId: job.job.uuid,
				file: &transferFile{
					ctx:        job.job.ctx,
					callback:   job.job.callback,
					job:        job.job,
					engine:     te,
					remoteURL:  &url.URL{Path: remotePath},
					packOption: transfers[0].PackOption,
					localPath:  newPath,
					upload:     job.job.upload,
					token:      job.job.token,
					attempts:   transfers,
				},
			}:
			}
		}
	}
	return err
}

// Invoke HEAD against a remote URL, using the provided namespace information
//
// If a "dirlist host" is given, then that is used for the namespace info.
// Otherwise, the first three caches are queried simultaneously.
// For any of the queries, if the attempt with the proxy fails, a second attempt
// is made without.
func statHttp(ctx context.Context, dest *url.URL, namespace namespaces.Namespace, token string) (size uint64, err error) {
	statHosts := make([]url.URL, 0, 3)
	if namespace.DirListHost != "" {
		var endpoint *url.URL
		endpoint, err = url.Parse(namespace.DirListHost)
		if err != nil {
			return
		}
		statHosts = append(statHosts, *endpoint)
	} else if len(namespace.SortedDirectorCaches) > 0 {
		for idx, cache := range namespace.SortedDirectorCaches {
			if idx > 2 {
				break
			}
			var endpoint *url.URL
			endpoint, err = url.Parse(cache.EndpointUrl)
			if err != nil {
				return
			}
			statHosts = append(statHosts, *endpoint)
		}
	} else if namespace.WriteBackHost != "" {
		var endpoint *url.URL
		endpoint, err = url.Parse(namespace.WriteBackHost)
		if err != nil {
			return
		}
		statHosts = append(statHosts, *endpoint)
	}

	type statResults struct {
		size uint64
		err  error
	}
	resultsChan := make(chan statResults)
	transport := config.GetTransport()
	client := &http.Client{Transport: transport}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for _, statUrl := range statHosts {
		destCopy := *dest
		destCopy.Host = statUrl.Host
		destCopy.Scheme = statUrl.Scheme

		go func(endpoint *url.URL) {
			canDisableProxy := CanDisableProxy()
			disableProxy := !isProxyEnabled()

			var resp *http.Response
			for {
				if disableProxy {
					log.Debugln("Performing HEAD (without proxy)", endpoint.String())
					transport.Proxy = nil
				} else {
					log.Debugln("Performing HEAD", endpoint.String())
				}

				var req *http.Request
				req, err = http.NewRequestWithContext(ctx, "HEAD", endpoint.String(), nil)
				if err != nil {
					log.Errorln("Failed to create HTTP request:", err)
					resultsChan <- statResults{0, err}
					return
				}

				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}

				resp, err = client.Do(req)
				if err == nil {
					break
				}
				if urle, ok := err.(*url.Error); canDisableProxy && !disableProxy && ok && urle.Unwrap() != nil {
					if ope, ok := urle.Unwrap().(*net.OpError); ok && ope.Op == "proxyconnect" {
						log.Warnln("Failed to connect to proxy; will retry without:", ope)
						disableProxy = true
						continue
					}
				}
				log.Errorln("Failed to get HTTP response:", err)
				resultsChan <- statResults{0, err}
				return
			}

			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				contentLengthStr := resp.Header.Get("Content-Length")
				if len(contentLengthStr) == 0 {
					log.Errorln("HEAD response did not include Content-Length header")
					err = errors.New("HEAD response did not include Content-Length header")
					resultsChan <- statResults{0, err}
					return
				}
				var contentLength int64
				contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
				if err != nil {
					log.Errorf("Unable to parse Content-Length header value (%s) as integer: %s", contentLengthStr, err)
					resultsChan <- statResults{0, err}
					return
				}
				resultsChan <- statResults{uint64(contentLength), nil}
			} else {
				var respB []byte
				respB, err = io.ReadAll(resp.Body)
				if err != nil {
					log.Errorln("Failed to read error message:", err)
					return
				}
				err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s", resp.StatusCode, string(respB))}
				resultsChan <- statResults{0, err}
			}
		}(&destCopy)
	}
	success := false
	for ctr := 0; ctr < len(statHosts); ctr++ {
		result := <-resultsChan
		if result.err == nil {
			if !success {
				cancel()
				success = true
				size = result.size
			}
		} else if err == nil && result.err != context.Canceled {
			err = result.err
		}
	}
	if success {
		err = nil
	}
	return
}
