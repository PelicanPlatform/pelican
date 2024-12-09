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
	"io/fs"
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
	"github.com/lestrrat-go/option"
	"github.com/opensaucerer/grab/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
	"github.com/vbauerster/mpb/v8"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	progressCtrOnce sync.Once
	progressCtr     *mpb.Progress

	stoppedTransferDebugLine sync.Once

	PelicanError error_codes.PelicanError
)

type (
	logFields string

	classAd string

	// Error type for when the transfer started to return data then completely stopped
	StoppedTransferError struct {
		BytesTransferred int64
		StoppedTime      time.Duration
		CacheHit         bool
		Upload           bool
	}

	// SlowTransferError is an error that is returned when a transfer takes longer than the configured timeout
	SlowTransferError struct {
		BytesTransferred int64
		BytesPerSecond   int64
		BytesTotal       int64
		Duration         time.Duration
		CacheAge         time.Duration
	}

	// ConnectionSetupError is an error that is returned when a connection to the remote server fails
	ConnectionSetupError struct {
		URL string
		Err error
	}

	HeaderTimeoutError struct{}

	NetworkResetError struct{}

	allocateMemoryError struct {
		Err error
	}

	dirListingNotSupportedError struct {
		Err error
	}

	// Transfer attempt error wraps an error with information about the service/proxy used
	TransferAttemptError struct {
		serviceHost string
		proxyHost   string
		isUpload    bool
		isProxyErr  bool
		err         error
	}

	// StatusCodeError is a wrapper around grab.StatusCodeErorr that indicates the server returned
	// a non-200 code.
	//
	// The wrapper is done to provide a Pelican-based error hierarchy in case we ever decide to have
	// a different underlying download package.
	StatusCodeError grab.StatusCodeError

	// Represents the results of a single object transfer,
	// potentially across multiple attempts / retries.
	TransferResults struct {
		jobId             uuid.UUID // The job ID this result corresponds to
		job               *TransferJob
		Error             error
		TransferredBytes  int64
		TransferStartTime time.Time
		Scheme            string
		Attempts          []TransferResult
	}

	TransferResult struct {
		Number            int           // indicates which attempt this is
		TransferFileBytes int64         // how much each attempt downloaded
		TimeToFirstByte   time.Duration // how long it took to download the first byte
		TransferEndTime   time.Time     // when the transfer ends
		TransferTime      time.Duration // amount of time we were transferring per attempt (in seconds)
		CacheAge          time.Duration // age of the data reported by the cache
		Endpoint          string        // which origin did it use
		ServerVersion     string        // version of the server
		Error             error         // what error the attempt returned (if any)
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

		// Cache age, if known
		CacheAge time.Duration

		// Whether or not the cache has been queried
		CacheQuery bool
	}

	// A structure representing a single file to transfer.
	transferFile struct {
		ctx        context.Context
		engine     *TransferEngine
		job        *TransferJob
		callback   TransferCallbackFunc
		remoteURL  *url.URL
		localPath  string
		token      *tokenGenerator
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
		ctx            context.Context
		cancel         context.CancelFunc
		callback       TransferCallbackFunc
		uuid           uuid.UUID
		remoteURL      *pelican_url.PelicanURL
		lookupDone     atomic.Bool
		lookupErr      error
		activeXfer     atomic.Int64
		totalXfer      int
		localPath      string
		upload         bool
		recursive      bool
		skipAcquire    bool
		syncLevel      SyncLevel  // Policy for handling synchronization when the destination exists
		prefObjServers []*url.URL // holds any client-requested caches/origins
		dirResp        server_structs.DirectorResponse
		directorUrl    string
		token          *tokenGenerator
		project        string
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

	// Different types of synchronization for recursize transfers
	SyncLevel int

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
		pelicanUrlCache *pelican_url.Cache
	}

	TransferCallbackFunc = func(path string, downloaded int64, totalSize int64, completed bool)

	// A client to the transfer engine.
	TransferClient struct {
		id             uuid.UUID
		ctx            context.Context
		cancel         context.CancelFunc
		callback       TransferCallbackFunc
		engine         *TransferEngine
		skipAcquire    bool      // Enable/disable the token acquisition logic.  Defaults to acquiring a token
		syncLevel      SyncLevel // Policy for the client to synchronize data
		tokenLocation  string    // Location of a token file to use for transfers
		token          string    // Token that should be used for transfers
		work           chan *TransferJob
		closed         bool
		prefObjServers []*url.URL // holds any client-requested caches/origins
		results        chan *TransferResults
		finalResults   chan TransferResults
		setupResults   sync.Once
	}

	TransferOption                   = option.Interface
	identTransferOptionCaches        struct{}
	identTransferOptionCallback      struct{}
	identTransferOptionTokenLocation struct{}
	identTransferOptionAcquireToken  struct{}
	identTransferOptionToken         struct{}
	identTransferOptionSynchronize   struct{}

	transferDetailsOptions struct {
		NeedsToken bool
		PackOption string
	}
)

const (
	ewmaInterval = 15 * time.Second

	projectName classAd = "ProjectName"
	jobId       classAd = "GlobalJobId"

	SyncNone  = iota // When synchronizing, always re-transfer, regardless of existence at destination.
	SyncExist        // Skip synchronization transfer if the destination exists
	SyncSize         // Skip synchronization transfer if the destination exists and matches the current source size
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

func (e *HeaderTimeoutError) Error() string {
	return "timeout waiting for HTTP response (TCP connection successful)"
}

func (e *HeaderTimeoutError) Is(target error) bool {
	_, ok := target.(*HeaderTimeoutError)
	return ok
}

func (e *NetworkResetError) Error() string {
	return "the existing TCP connection was broken (potentially caused by server restart or NAT/firewall issue)"

}

func (e *StoppedTransferError) Error() (errMsg string) {
	if e.StoppedTime > 0 {
		errMsg = "no progress for more than " + e.StoppedTime.Truncate(time.Millisecond).String()
	} else {
		errMsg = "no progress"
	}
	errMsg += " after " + ByteCountSI(e.BytesTransferred) + " transferred"
	if !e.Upload {
		if e.CacheHit {
			errMsg += " (cache hit)"
		} else {
			errMsg += " (cache miss)"
		}
	}
	return
}

func (e *StoppedTransferError) Is(target error) bool {
	_, ok := target.(*StoppedTransferError)
	return ok
}

func (e *allocateMemoryError) Error() string {
	return e.Err.Error()
}

func (e *allocateMemoryError) Unwrap() error {
	return e.Err
}

func (e *allocateMemoryError) Is(target error) bool {
	_, ok := target.(*allocateMemoryError)
	return ok
}

func (e *dirListingNotSupportedError) Error() string {
	return e.Err.Error()
}

func (e *dirListingNotSupportedError) Unwrap() error {
	return e.Err
}

func (e *dirListingNotSupportedError) Is(target error) bool {
	_, ok := target.(*dirListingNotSupportedError)
	return ok
}

type HttpErrResp struct {
	Code int
	Err  string
}

func (e *HttpErrResp) Error() string {
	return e.Err
}

func (e *SlowTransferError) Error() (errMsg string) {
	errMsg = "cancelled transfer, too slow; detected speed=" +
		ByteCountSI(e.BytesPerSecond) +
		"/s, total transferred=" +
		ByteCountSI(e.BytesTransferred) +
		", total transfer time=" +
		e.Duration.Round(time.Millisecond).String()
	if e.CacheAge == 0 {
		errMsg += ", cache miss"
	} else if e.CacheAge > 0 {
		errMsg += ", cache hit"
	}
	return
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

func (e *StatusCodeError) Error() string {
	if int(*e) == http.StatusGatewayTimeout {
		return "cache timed out waiting on origin"
	}
	return (*grab.StatusCodeError)(e).Error()
}

func (e *StatusCodeError) Is(target error) bool {
	sce, ok := target.(*StatusCodeError)
	if !ok {
		return false
	}
	return int(*sce) == int(*e)
}

func (tae *TransferAttemptError) Error() (errMsg string) {
	errMsg = "failed download from "
	if tae.isUpload {
		errMsg = "failed upload to "
	}
	if tae.serviceHost == "" {
		errMsg += "unknown host"
	} else {
		errMsg += tae.serviceHost
	}
	if tae.isProxyErr {
		if tae.proxyHost == "" {
			errMsg += " due to unknown proxy"
		} else {
			errMsg += " due to proxy " + tae.proxyHost
		}
	} else if tae.proxyHost != "" {
		errMsg += "+proxy=" + tae.proxyHost
	}
	if tae.err != nil {
		errMsg += ": " + tae.err.Error()
	}
	return
}

func (tae *TransferAttemptError) Unwrap() error {
	return tae.err
}

func (tae *TransferAttemptError) Is(target error) bool {
	other, ok := target.(*TransferAttemptError)
	if !ok {
		return false
	}
	return tae.isUpload == other.isUpload && tae.serviceHost == other.serviceHost && tae.isProxyErr == other.isProxyErr && tae.proxyHost == other.proxyHost
}

func compatToDuration(dur time.Duration, paramName string) (result time.Duration) {
	// Backward compat: some parameters were previously integers, in seconds.
	// If you give viper an integer without a suffix then it interprets it as a
	// number in *nanoseconds*.  We assume that's not the intent and, if under a
	// microsecond, assume that the user really meant seconds.
	if dur < time.Microsecond {
		log.Warningf("%s must be given as a duration, not an integer; try setting it as '%ds'", paramName, dur.Nanoseconds())
		result = time.Duration(dur.Nanoseconds()) * time.Second
	} else {
		result = dur
	}
	return
}

func newTransferAttemptError(service string, proxy string, isProxyErr bool, isUpload bool, err error) (tae *TransferAttemptError) {
	tae = &TransferAttemptError{
		serviceHost: service,
		proxyHost:   proxy,
		isProxyErr:  isProxyErr,
		isUpload:    isUpload,
		err:         err,
	}
	return
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

// Returns a new transfer engine object whose lifetime is tied
// to the provided context.  Will launcher worker goroutines to
// handle the underlying transfers
func NewTransferEngine(ctx context.Context) (te *TransferEngine, err error) {
	// If we did not initClient yet, we should fail to avoid unexpected/undesired behavior
	if !config.IsClientInitialized() {
		return nil, errors.New("client has not been initialized, unable to create transfer engine")
	}

	ctx, cancel := context.WithCancel(ctx)
	egrp, _ := errgroup.WithContext(ctx)
	work := make(chan *clientTransferJob, 5)
	files := make(chan *clientTransferFile)
	results := make(chan *clientTransferResults, 5)

	// Start the URL cache to avoid repeated metadata queries
	pelicanUrlCache := pelican_url.StartCache()

	te = &TransferEngine{
		ctx:             ctx,
		cancel:          cancel,
		egrp:            egrp,
		work:            work,
		files:           files,
		results:         results,
		resultsMap:      make(map[uuid.UUID]chan *TransferResults),
		workMap:         make(map[uuid.UUID]chan *TransferJob),
		jobLookupDone:   make(chan *clientTransferJob, 5),
		notifyChan:      make(chan bool),
		closeChan:       make(chan bool),
		closeDoneChan:   make(chan bool),
		ewmaTick:        time.NewTicker(ewmaInterval),
		ewma:            ewma.NewMovingAverage(),
		pelicanUrlCache: pelicanUrlCache,
	}
	workerCount := param.Client_WorkerCount.GetInt()
	if workerCount <= 0 {
		return nil, errors.New("worker count must be a positive integer")
	}
	for idx := 0; idx < workerCount; idx++ {
		egrp.Go(func() error {
			return runTransferWorker(ctx, te.files, te.results)
		})
	}
	te.workersActive = workerCount
	egrp.Go(te.runMux)
	egrp.Go(te.runJobHandler)
	return
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

// Create an option to specify the object synchronization level
//
// The synchronization level specifies what to do if the destination
// object already exists.
func WithSynchronize(level SyncLevel) TransferOption {
	return option.New(identTransferOptionSynchronize{}, level)
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
		engine:  te,
		id:      id,
		results: make(chan *TransferResults),
		work:    make(chan *TransferJob),
	}
	client.ctx, client.cancel = context.WithCancel(te.ctx)

	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionCaches{}:
			client.prefObjServers = option.Value().([]*url.URL)
		case identTransferOptionCallback{}:
			client.callback = option.Value().(TransferCallbackFunc)
		case identTransferOptionTokenLocation{}:
			client.tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			client.skipAcquire = !option.Value().(bool)
		case identTransferOptionToken{}:
			client.token = option.Value().(string)
		case identTransferOptionSynchronize{}:
			client.syncLevel = option.Value().(SyncLevel)
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
	te.Close()
	<-te.closeDoneChan
	te.ewmaTick.Stop()
	te.pelicanUrlCache.Stop()
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

// If we've detected a job is done, clean up the active job state map
func (te *TransferEngine) finishJob(activeJobs *map[uuid.UUID][]*TransferJob, job *TransferJob, id uuid.UUID) {
	if len((*activeJobs)[id]) == 1 {
		log.Debugln("Job", job.ID(), "is done for client", id.String(), "which has no active jobs remaining")
		// Delete the job from the list of active jobs
		delete(*activeJobs, id)
		func() {
			te.clientLock.Lock()
			defer te.clientLock.Unlock()
			// If the client is closed and there are no remaining
			// jobs for that client, we can close the results channel
			// for the client -- a clean shutdown of the client.
			if te.workMap[id] == nil {
				close(te.resultsMap[id])
				log.Debugln("Client", id.String(), "has no more work and is finished shutting down")
			}
		}()
	} else {
		// Scan through the list of active jobs, removing the recently
		// completed one and saving the updated list.
		newJobList := make([]*TransferJob, 0, len((*activeJobs)[id]))
		for _, oldJob := range (*activeJobs)[id] {
			if oldJob.uuid != job.uuid {
				newJobList = append(newJobList, oldJob)
			}
		}
		(*activeJobs)[id] = newJobList
		log.Debugln("Job", job.ID(), "is done for client", id.String(), " which has", len(newJobList), "jobs remaining")
	}
}

// Launches a helper goroutine that ensures completed
// transfer results are routed back to their requesting
// channels
func (te *TransferEngine) runMux() error {
	tmpResults := make(map[uuid.UUID][]*TransferResults)
	activeJobs := make(map[uuid.UUID][]*TransferJob)
	var clientJob *clientTransferJob
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
			// Only listen for more incoming work if we're not waiting to send a client job to the
			// jobs-to-objects worker
			slices.SortFunc(workKeys, sortFunc)
			for _, key := range workKeys {
				workMap[key] = te.workMap[key]
				cases[ctr].Dir = reflect.SelectRecv
				if clientJob == nil {
					cases[ctr].Chan = reflect.ValueOf(workMap[key])
				} else {
					cases[ctr].Chan = reflect.ValueOf(nil)
				}
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
			// Buffer the jobs to send to the job-to-objects worker.
			if clientJob == nil {
				cases[ctr+2].Dir = reflect.SelectRecv
				cases[ctr+2].Chan = reflect.ValueOf(nil)
			} else {
				cases[ctr+2].Dir = reflect.SelectSend
				cases[ctr+2].Chan = reflect.ValueOf(te.work)
				cases[ctr+2].Send = reflect.ValueOf(clientJob)
			}
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
			clientJob = &clientTransferJob{job: job, uuid: id}
			clientJobs := activeJobs[id]
			if clientJobs == nil {
				clientJobs = make([]*TransferJob, 0)
			}
			clientJobs = append(clientJobs, job)
			activeJobs[id] = clientJobs
		} else if chosen < len(workMap)+len(resultsMap) {
			// One of the "write" channels has been sent some results.
			id := resultsKeys[chosen-len(workMap)]
			clientJob := tmpResults[id][0]
			job := clientJob.job
			job.activeXfer.Add(-1)
			// Test to see if the transfer job is done (true if job-to-file translation
			// has completed and there are no remaining active transfers)
			if job.lookupDone.Load() && job.activeXfer.Load() == 0 {
				te.finishJob(&activeJobs, job, id)
			}
			if len(tmpResults[id]) == 1 {
				// The last result back to this client has been sent; delete the
				// slice from the map and check if the overall job is done.
				delete(tmpResults, id)
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
		} else if chosen == len(workMap)+len(resultsMap)+2 {
			// Sent the buffered job to the job-to-objects worker.  Clear
			// out the buffer so that we can pull in more work.
			clientJob = nil
		} else if chosen == len(workMap)+len(resultsMap)+3 {
			// Engine's context has been cancelled; immediately exit.
			log.Debugln("Transfer engine has been cancelled")
			close(te.closeDoneChan)
			return te.ctx.Err()
		} else if chosen == len(workMap)+len(resultsMap)+4 {
			// Notification that a job has been processed into files (or failed)
			job := recv.Interface().(*clientTransferJob)
			job.job.lookupDone.Store(true)
			// If no transfers were created or we have an error, the job is no
			// longer active
			if job.job.lookupErr != nil || job.job.totalXfer == 0 {
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
			} else if job.job.activeXfer.Load() == 0 {
				// Transfer jobs were created but they all completed before the recursive directory
				// walk finished.
				te.finishJob(&activeJobs, job.job, job.uuid)
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
func (tc *TransferClient) NewTransferJob(ctx context.Context, remoteUrl *url.URL, localPath string, upload bool, recursive bool, options ...TransferOption) (tj *TransferJob, err error) {

	id, err := uuid.NewV7()
	if err != nil {
		return
	}

	pUrl, err := ParseRemoteAsPUrl(ctx, remoteUrl.String())
	if err != nil {
		return
	}

	// See if we have a projectName defined
	project := searchJobAd(projectName)
	copyUrl := *pUrl // Make a copy of the input URL to avoid concurrent issues.
	if _, exists := copyUrl.Query()[pelican_url.QueryRecursive]; exists {
		recursive = true
	}
	tj = &TransferJob{
		prefObjServers: tc.prefObjServers,
		recursive:      recursive,
		localPath:      localPath,
		remoteURL:      &copyUrl,
		callback:       tc.callback,
		skipAcquire:    tc.skipAcquire,
		syncLevel:      tc.syncLevel,
		upload:         upload,
		uuid:           id,
		project:        project,
		token:          newTokenGenerator(&copyUrl, nil, upload, !tc.skipAcquire),
	}
	if tc.token != "" {
		tj.token.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
	}

	mergeCancel := func(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
		newCtx, cancel := context.WithCancel(ctx1)
		stop := context.AfterFunc(ctx2, func() {
			cancel()
		})
		return newCtx, func() {
			stop()
			cancel()
		}
	}

	tj.ctx, tj.cancel = mergeCancel(ctx, tc.ctx)

	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionCaches{}:
			tj.prefObjServers = option.Value().([]*url.URL)
		case identTransferOptionCallback{}:
			tj.callback = option.Value().(TransferCallbackFunc)
		case identTransferOptionTokenLocation{}:
			tj.token.SetTokenLocation(option.Value().(string))
		case identTransferOptionAcquireToken{}:
			tj.token.EnableAcquire = option.Value().(bool)
		case identTransferOptionToken{}:
			tj.token.SetToken(option.Value().(string))
		case identTransferOptionSynchronize{}:
			tj.syncLevel = option.Value().(SyncLevel)
		}
	}

	httpMethod := http.MethodPut
	if upload {
		httpMethod = http.MethodPut
	} else {
		httpMethod = http.MethodGet
	}

	tj.directorUrl = copyUrl.FedInfo.DirectorEndpoint
	dirResp, err := GetDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, "")
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", pUrl.String())
		return
	}
	tj.dirResp = dirResp
	tj.token.DirResp = &dirResp

	if upload || dirResp.XPelNsHdr.RequireToken {
		contents, err := tj.token.get()
		if err != nil || contents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", copyUrl.String())
				return nil, err
			}
			tj.dirResp = dirResp
			tj.token.DirResp = &dirResp
		}
	} else {
		tj.token = nil
	}

	// If we are a recursive download and using the director, we want to attempt to get directory listings from
	// PROPFINDing the director
	if recursive && !upload {
		collUrl := dirResp.XPelNsHdr.CollectionsUrl
		if collUrl == nil {
			return nil, errors.New("no collections URL found in director response")
		}
	}

	log.Debugf("Created new transfer job, ID %s client %s, for URL %s", tj.uuid.String(), tc.id.String(), copyUrl.String())
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
		log.Debugln("Closing transfer client", tc.id.String())
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
			defer close(tc.finalResults)
			for {
				select {
				case <-tc.ctx.Done():
					return
				case result, ok := <-tc.results:
					if !ok {
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

// generateTransferDetails creates the TransferDetails struct with the given remote object server
func generateTransferDetails(remoteOServer string, opts transferDetailsOptions) []transferAttemptDetails {
	details := make([]transferAttemptDetails, 0)

	// Form the URL
	remoteUrl, err := url.Parse(remoteOServer)
	if err != nil {
		log.Errorln("Failed to parse remote object server:", remoteUrl.String(), "error:", err)
		return nil
	}
	if remoteUrl.Scheme == "unix" && remoteUrl.Host != "" {
		remoteUrl.Path = path.Clean("/" + remoteUrl.Host + "/" + remoteUrl.Path)
		remoteUrl.Host = ""
	} else if remoteUrl.Scheme != "unix" && remoteUrl.Host == "" {
		// Assume the cache is just a hostname
		remoteUrl.Host = remoteOServer
		remoteUrl.Path = ""
		remoteUrl.Scheme = ""
		remoteUrl.Opaque = ""
	}
	if opts.NeedsToken {
		if remoteUrl.Scheme != "unix" {
			remoteUrl.Scheme = "https"
		}
		det := transferAttemptDetails{
			Url:        remoteUrl,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if remoteUrl.Scheme == "unix" {
			det.UnixSocket = remoteUrl.Path
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, det)
	} else if remoteUrl.Scheme == "" || remoteUrl.Scheme == "http" {
		remoteUrl.Scheme = "http"
		isProxyEnabled := isProxyEnabled()
		details = append(details, transferAttemptDetails{
			Url:        remoteUrl,
			Proxy:      isProxyEnabled,
			PackOption: opts.PackOption,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, transferAttemptDetails{
				Url:        remoteUrl,
				Proxy:      false,
				PackOption: opts.PackOption,
			})
		}
	} else {
		det := transferAttemptDetails{
			Url:        remoteUrl,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if remoteUrl.Scheme == "unix" {
			det.UnixSocket = remoteUrl.Path
		}
		details = append(details, det)
	}

	return details
}

// Generate the unique list of object servers (caches or origins) that will be attempted for a single transfer job and populate this info
// in the slice of transferAttemptDetails structs
func getObjectServersToTry(sortedObjectServers []string, job *TransferJob, oServersToTry int, packOption string) (transfers []transferAttemptDetails) {
	oServersListed := 0
	oServerList := make(map[string]bool)
	oServers := make([]string, 0)

	for _, oServer := range sortedObjectServers {
		if oServersListed == oServersToTry {
			break
		}
		// Handle deduplication of any object servers
		if oServerList[oServer] {
			continue
		} else {
			oServersListed++
			oServers = append(oServers, oServer)
			oServerList[oServer] = true
			td := transferDetailsOptions{
				NeedsToken: job.dirResp.XPelNsHdr.RequireToken,
				PackOption: packOption,
			}
			transfers = append(transfers, generateTransferDetails(oServer, td)...)
		}
	}
	log.Debugln("Trying the object servers:", oServers)
	return transfers
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
		if len(job.job.dirResp.ObjectServers) == 0 {
			err = errors.New("No origins found for upload")
			return
		}
		transfers = append(transfers, transferAttemptDetails{
			Url:        job.job.dirResp.ObjectServers[0],
			PackOption: packOption,
		})
	} else {
		var sortedServers []*url.URL
		sortedServers, err = generateSortedObjServers(job.job.dirResp, job.job.prefObjServers)
		if err != nil {
			log.Errorln("Failed to get namespaced caches (treated as non-fatal):", err)
		}
		var sortedServerStrings []string
		for _, serverUrl := range sortedServers {
			sortedServerStrings = append(sortedServerStrings, serverUrl.String())
		}

		// Make sure we only try as many object servers as we have
		objectServersToTry := ObjectServersToTry
		if objectServersToTry > len(sortedServers) {
			objectServersToTry = len(sortedServers)
		}
		log.Debugf("Trying the first %d object servers", objectServersToTry)
		transfers = getObjectServersToTry(sortedServerStrings, job.job, objectServersToTry, packOption)

		if len(transfers) > 0 {
			log.Traceln("First transfer in list:", transfers[0].Url)
		} else {
			err = errors.New("No transfers possible as no object servers were found")
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
			}
			results <- &clientTransferResults{id: file.uuid, results: transferResults}
		}
	}
}

// If there are multiple potential attempts, try to see if we can quickly eliminate some of them
//
// Attempts a HEAD against all the endpoints simultaneously.  Put any that don't respond within
// a second behind those that do respond.
func sortAttempts(ctx context.Context, path string, attempts []transferAttemptDetails, token *tokenGenerator) (size int64, results []transferAttemptDetails) {
	size = -1
	if len(attempts) < 2 {
		results = attempts
		return
	}
	transport := config.GetTransport()
	type checkResults struct {
		idx  int
		size uint64
		age  int
		err  error
	}
	headChan := make(chan checkResults)

	if log.IsLevelEnabled(log.DebugLevel) {
		attemptHosts := make([]string, len(attempts))
		for idx, host := range attempts {
			attemptHosts[idx] = host.Url.Host
		}
		log.Debugln("Will query the following endpoints for availability:", strings.Join(attemptHosts, ", "))
	}

	defer close(headChan)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for idx, transferEndpoint := range attempts {
		tUrl := *transferEndpoint.Url
		tUrl.Path = path

		go func(idx int, tUrl *url.URL) {
			// If the scheme is unix://, it is a local cache and therefore, we should always try this cache first and skip the HEAD request (since it will fail)
			if tUrl.Scheme == "unix" {
				headChan <- checkResults{idx, 0, -1, nil}
				return
			}

			headClient := &http.Client{Transport: transport}
			// Note we are not using a HEAD request here but a GET request for one byte;
			// this is because the XRootD server currently (v5.6.9) only returns the Age
			// header for GETs
			headRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, tUrl.String(), nil)
			headRequest.Header.Set("Range", "0-0")
			if token != nil {
				if tokenContents, err := token.get(); err == nil && tokenContents != "" {
					headRequest.Header.Set("Authorization", "Bearer "+tokenContents)
				}
			}
			var headResponse *http.Response
			headResponse, err := headClient.Do(headRequest)
			if err != nil {
				headChan <- checkResults{idx, 0, -1, err}
				return
			}
			// Allow response body to fail to read; we are only interested in the headers
			// of the response, not the contents.
			if _, err := io.ReadAll(headResponse.Body); err != nil {
				log.Warningln("Failure when reading the one-byte-response body:", err)
			}
			headResponse.Body.Close()
			var age int = -1
			var size int64 = 0
			if headResponse.StatusCode <= 300 {
				contentLengthStr := headResponse.Header.Get("Content-Length")
				if contentLengthStr != "" {
					size, err = strconv.ParseInt(contentLengthStr, 10, 64)
					if err != nil {
						err = errors.Wrap(err, "problem converting Content-Length in response to an int")
						log.Errorln(err.Error())

					}
				}
				ageStr := headResponse.Header.Get("Age")
				if ageStr != "" {
					if ageParsed, err := strconv.Atoi(ageStr); err != nil {
						log.Warningf("Ignoring invalid age value (%s) due to parsing error: %s", headRequest.Header.Get("Age"), err.Error())
					} else {
						age = ageParsed
					}
				}
			} else {
				err = &HttpErrResp{
					Code: headResponse.StatusCode,
					Err:  fmt.Sprintf("GET \"%s\" resulted in status code %d", tUrl, headResponse.StatusCode),
				}
			}
			headChan <- checkResults{idx, uint64(size), age, err}
		}(idx, &tUrl)
	}
	// 1 -> success.
	// 0 -> pending.
	// -1 -> error.
	finished := make(map[int]int)
	for ctr := 0; ctr != len(attempts); ctr++ {
		result := <-headChan
		if result.err != nil {
			// If an attempt to contact the remote cache failed, log a message (unless we purposely
			// canceled the attempt).
			if !errors.Is(result.err, context.Canceled) && !errors.Is(result.err, context.DeadlineExceeded) {
				log.Debugf("Failure when doing a GET request to see if %s is functioning: %s", attempts[result.idx].Url.String(), result.err.Error())
				finished[result.idx] = -1
			} else if errors.Is(result.err, context.DeadlineExceeded) {
				log.Debugf("Timed out when querying to see if %s is functioning", attempts[result.idx].Url.String())
			}
		} else {
			finished[result.idx] = 1
			if result.age >= 0 {
				attempts[result.idx].CacheAge = time.Duration(result.age) * time.Second
				attempts[result.idx].CacheQuery = true
			}
			if result.idx == 0 && result.err == nil {
				cancel()
				// If the first responds successfully, we want to return immediately instead of giving
				// the other caches time to respond - the result is "good enough".
				// - Any cache with confirmed errors (-1) is sorted to the back.
				// - Any cache which is still pending (0) is kept in place.
				log.Debugf("First available cache (%s) responded; will ignore remaining attempts", attempts[result.idx].Url.Host)
				for ctr := 0; ctr < len(attempts); ctr++ {
					if finished[ctr] != -1 {
						finished[ctr] = 1
					}
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

// Download the object specified in the transfer to the local filesystem
//
// transferResults contains the summary of the multiple attempts.
// err is set _only_ if the function was unable to attempt a transfer (e.g., unable to
// create the destination directory).
func downloadObject(transfer *transferFile) (transferResults TransferResults, err error) {
	log.Debugln("Downloading object from", transfer.remoteURL, "to", transfer.localPath)
	// Remove the source from the file path
	directory := path.Dir(transfer.localPath)
	var downloaded int64
	if err = os.MkdirAll(directory, 0700); err != nil {
		return
	}

	size, attempts := sortAttempts(transfer.job.ctx, transfer.remoteURL.Path, transfer.attempts, transfer.token)

	transferResults = newTransferResults(transfer.job)
	xferErrors := NewTransferErrors()
	success := false
	// transferStartTime is the start time of the last transfer attempt
	// we create a var here and update it in the loop
	var transferStartTime time.Time
	for idx, transferEndpoint := range attempts { // For each transfer attempt (usually 3), try to download via HTTP
		var attempt TransferResult
		attempt.CacheAge = -1
		attempt.Number = idx // Start with 0
		attempt.Endpoint = transferEndpoint.Url.Host
		if transferEndpoint.CacheQuery {
			attempt.CacheAge = transferEndpoint.CacheAge
		}
		// Make a copy of the transfer endpoint URL; otherwise, when we mutate the pointer, other parallel
		// workers might download from the wrong path.
		transferEndpointUrl := *transferEndpoint.Url
		transferEndpointUrl.Path = transfer.remoteURL.Path
		transferEndpoint.Url = &transferEndpointUrl
		fields := log.Fields{
			"url": transferEndpoint.Url.String(),
			"job": transfer.job.ID(),
		}
		ctx := context.WithValue(transfer.ctx, logFields("fields"), fields)
		transferStartTime = time.Now() // Update start time for this attempt
		tokenContents := ""
		if transfer.token != nil {
			tokenContents, _ = transfer.token.get()
		}
		attemptDownloaded, timeToFirstByte, cacheAge, serverVersion, err := downloadHTTP(
			ctx, transfer.engine, transfer.callback, transferEndpoint, transfer.localPath, size, tokenContents, transfer.project,
		)
		endTime := time.Now()
		if cacheAge >= 0 {
			attempt.CacheAge = cacheAge
		}
		attempt.TransferEndTime = endTime
		attempt.TransferTime = endTime.Sub(transferStartTime)
		attempt.ServerVersion = serverVersion
		attempt.TransferFileBytes = attemptDownloaded
		attempt.TimeToFirstByte = timeToFirstByte
		downloaded += attemptDownloaded

		if err != nil {
			log.WithFields(fields).Debugln("Failed to download from", transferEndpoint.Url, ":", err)
			var ope *net.OpError
			var cse *ConnectionSetupError
			proxyStr, _ := os.LookupEnv("http_proxy")
			if !transferEndpoint.Proxy {
				proxyStr = ""
			}
			serviceStr := attempt.Endpoint
			if transferEndpointUrl.Scheme == "unix" {
				serviceStr = "local-cache"
			}
			if errors.As(err, &ope) && ope.Op == "proxyconnect" {
				if ope.Addr != nil {
					proxyStr += "(" + ope.Addr.String() + ")"
				}
				attempt.Error = newTransferAttemptError(serviceStr, proxyStr, true, false, err)
			} else if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
				attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, &NetworkResetError{})
			} else if errors.As(err, &cse) {
				if sce, ok := cse.Unwrap().(*StatusCodeError); ok {
					attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, sce)
				} else if ue, ok := cse.Unwrap().(*url.Error); ok {
					httpErr := ue.Unwrap()
					if httpErr.Error() == "net/http: timeout awaiting response headers" {
						attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, &HeaderTimeoutError{})
					} else {
						attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, httpErr)
					}
				} else {
					attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, err)
				}
			} else {
				attempt.Error = newTransferAttemptError(serviceStr, proxyStr, false, false, err)
			}
			xferErrors.AddPastError(attempt.Error, endTime)
		}
		transferResults.Attempts = append(transferResults.Attempts, attempt)

		if err == nil { // Success
			log.WithFields(fields).Debugln("Downloaded bytes:", downloaded)
			success = true
			break
		}
	}
	transferResults.TransferStartTime = transferStartTime
	transferResults.TransferredBytes = downloaded
	if !success {
		transferResults.Error = xferErrors
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
func downloadHTTP(ctx context.Context, te *TransferEngine, callback TransferCallbackFunc, transfer transferAttemptDetails, dest string, totalSize int64, token string, project string) (downloaded int64, timeToFirstByte time.Duration, cacheAge time.Duration, serverVersion string, err error) {
	fields, ok := ctx.Value(logFields("fields")).(log.Fields)
	if !ok {
		fields = log.Fields{}
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(fields).Errorln("Panic occurred in downloadHTTP:", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) occurred in downloadHTTP: %v", r)
			err = errors.New(ret)
		}
	}()

	// Negative cache age indicates no Age response header was received
	cacheAge = -1

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
		return 0, 0, -1, "", errors.New("Internal error: implementation is not a http.Client type")
	}
	httpClient.Transport = transport
	headerTimeout := transport.ResponseHeaderTimeout
	if headerTimeout > time.Second {
		headerTimeout -= 500 * time.Millisecond
	} else {
		headerTimeout /= 2
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.WithFields(fields).Debugln("Attempting to download from:", transferUrl.Host)
	log.WithFields(fields).Debugln("Transfer URL String:", transferUrl.String())
	var req *grab.Request
	var unpacker *autoUnpacker
	if transfer.PackOption != "" {
		behavior, err := GetBehavior(transfer.PackOption)
		if err != nil {
			return 0, 0, -1, "", err
		}
		if dest == "." {
			dest, err = os.Getwd()
			if err != nil {
				return 0, 0, -1, "", errors.Wrap(err, "Failed to get current directory for destination")
			}
		}
		unpacker = newAutoUnpacker(dest, behavior)
		if req, err = grab.NewRequestToWriter(unpacker, transferUrl.String()); err != nil {
			return 0, 0, -1, "", errors.Wrap(err, "Failed to create new download request")
		}
	} else if req, err = grab.NewRequest(dest, transferUrl.String()); err != nil {
		return 0, 0, -1, "", errors.Wrap(err, "Failed to create new download request")
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
	req.HTTPRequest.Header.Set("X-Pelican-Timeout", headerTimeout.Round(time.Millisecond).String())
	if searchJobAd(jobId) != "" {
		req.HTTPRequest.Header.Set("X-Pelican-JobId", searchJobAd(jobId))
	}
	req.HTTPRequest.Header.Set("TE", "trailers")
	req.HTTPRequest.Header.Set("User-Agent", getUserAgent(project))

	req.NoResume = true
	req = req.WithContext(ctx)

	// Test the transfer speed every 0.5 seconds
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	// Progress ticker
	progressTicker := time.NewTicker(100 * time.Millisecond)
	defer progressTicker.Stop()
	downloadLimit := param.Client_MinimumDownloadSpeed.GetInt()

	// Start the transfer
	log.WithFields(fields).Debugln("Starting the HTTP transfer...")
	downloadStart := time.Now()
	resp := client.Do(req)
	// Check the error real quick
	if resp.IsComplete() {
		if err = resp.Err(); err != nil {
			var sce grab.StatusCodeError
			var cam syscall.Errno
			if errors.Is(err, grab.ErrBadLength) {
				err = fmt.Errorf("local copy of file is larger than remote copy %w", grab.ErrBadLength)
			} else if errors.As(err, &sce) {
				log.WithFields(fields).Debugln("Creating a client status code error")
				sce2 := StatusCodeError(sce)
				err = &sce2
			} else if errors.As(err, &cam) && cam == syscall.ENOMEM {
				// ENOMEM is error from os for unable to allocate memory
				err = &allocateMemoryError{Err: err}
			} else {
				err = &ConnectionSetupError{Err: err}
			}
			log.WithFields(fields).Errorln("Failed to download:", err)
			return
		}
	}
	serverVersion = resp.HTTPResponse.Header.Get("Server")

	if ageStr := resp.HTTPResponse.Header.Get("Age"); ageStr != "" {
		if ageSec, err := strconv.Atoi(ageStr); err == nil {
			cacheAge = time.Duration(ageSec) * time.Second
		} else {
			log.WithFields(fields).Debugf("Server at %s gave unparseable Age header (%s) in response: %s", transfer.Url.Host, ageStr, err.Error())
		}
	}
	if cacheAge == 0 {
		log.WithFields(fields).Debugln("Server at", transfer.Url.Host, "had a cache miss")
	} else if cacheAge > 0 {
		log.WithFields(fields).Debugln("Server at", transfer.Url.Host, "had a cache hit with data age", cacheAge.String())
	}

	// Size of the download
	totalSize = resp.Size()
	// Do a head request for content length if resp.Size is unknown
	if totalSize <= 0 && !resp.IsComplete() {
		headClient := &http.Client{Transport: transport}
		headRequest, _ := http.NewRequest(http.MethodHead, transferUrl.String(), nil)
		if token != "" {
			headRequest.Header.Set("Authorization", "Bearer "+token)
		}
		var headResponse *http.Response
		headResponse, err = headClient.Do(headRequest)
		if err != nil {
			log.WithFields(fields).Errorln("Could not successfully get response for HEAD request")
			err = errors.Wrap(err, "Could not determine the size of the remote object")
			return
		}
		headResponse.Body.Close()
		contentLengthStr := headResponse.Header.Get("Content-Length")
		if contentLengthStr != "" {
			totalSize, err = strconv.ParseInt(contentLengthStr, 10, 64)
			if err != nil {
				log.WithFields(fields).Errorln("problem converting content-length to an int:", err)
				totalSize = 0
			}
		}
	}
	if callback != nil {
		callback(dest, 0, totalSize, false)
	}

	stoppedTransferTimeout := compatToDuration(param.Client_StoppedTransferTimeout.GetDuration(), "Client.StoppedTranferTimeout")
	slowTransferRampupTime := compatToDuration(param.Client_SlowTransferRampupTime.GetDuration(), "Client.SlowTransferRampupTime")
	slowTransferWindow := compatToDuration(param.Client_SlowTransferWindow.GetDuration(), "Client.SlowTransferWindow")
	stoppedTransferDebugLine.Do(func() {
		log.WithFields(fields).Debugf("Stopped transfer timeout is %s; slow transfer ramp-up is %s; slow transfer look-back window is %s",
			stoppedTransferTimeout.String(), slowTransferRampupTime.String(), slowTransferWindow.String())
	})
	startBelowLimit := time.Time{}
	var noProgressStartTime time.Time
	var lastBytesComplete int64
	timeToFirstByteRecorded := false
	// Loop of the download
Loop:
	for {
		if !timeToFirstByteRecorded && resp.BytesComplete() > 1 {
			// Convert to seconds
			timeToFirstByte = time.Since(downloadStart)
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
				} else if time.Since(noProgressStartTime) > stoppedTransferTimeout {
					err = &StoppedTransferError{
						BytesTransferred: downloaded,
						StoppedTime:      time.Since(noProgressStartTime),
						CacheHit:         cacheAge > 0,
					}
					log.WithFields(fields).Errorln(err.Error())
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
				if resp.Duration() < slowTransferRampupTime {
					continue
				} else if startBelowLimit.IsZero() {
					warning := []byte("Warning! Downloading too slow...\n")
					status, err := getProgressContainer().Write(warning)
					if err != nil {
						log.WithFields(fields).Errorln("Problem displaying slow message", err, status)
						continue
					}
					startBelowLimit = time.Now()
					continue
				} else if time.Since(startBelowLimit) < slowTransferWindow {
					// If the download is below the threshold for less than `SlowTransferWindow` (default 30) seconds, continue
					continue
				}
				// The download is below the threshold for more than `SlowTransferWindow` seconds, cancel the download
				cancel()

				log.WithFields(fields).Errorf("Cancelled: Download speed of %s/s is below the limit of %s/s", ByteCountSI(int64(resp.BytesPerSecond())), ByteCountSI(int64(downloadLimit)))

				err = &SlowTransferError{
					BytesTransferred: resp.BytesComplete(),
					BytesPerSecond:   int64(resp.BytesPerSecond()),
					Duration:         resp.Duration(),
					BytesTotal:       totalSize,
					CacheAge:         cacheAge,
				}
				err = error_codes.NewTransfer_SlowTransferError(err)
				return

			} else {
				// The download is fast enough, reset the startBelowLimit
				startBelowLimit = time.Time{}
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
		log.WithFields(fields).Debugln("Got error from HTTP download", err)
		return
	} else {
		// Check the trailers for any error information
		trailer := resp.HTTPResponse.Trailer
		if errorStatus := trailer.Get("X-Transfer-Status"); errorStatus != "" {
			statusCode, statusText := parseTransferStatus(errorStatus)
			if statusCode != 200 {
				log.WithFields(fields).Debugln("Got error from file transfer")
				err = errors.New("transfer error: " + statusText)
				return
			}
		}
	}
	// Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
	// prior attempt.
	if resp.HTTPResponse.StatusCode != 200 && resp.HTTPResponse.StatusCode != 206 {
		log.WithFields(fields).Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return 0, 0, -1, serverVersion, &HttpErrResp{resp.HTTPResponse.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s",
			resp.HTTPResponse.StatusCode, resp.Err().Error())}
	}

	if unpacker != nil {
		unpacker.Close()
		if err = unpacker.Error(); err != nil {
			return
		}
	}

	log.WithFields(fields).Debugln("HTTP Transfer was successful")
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
	xferErrors := NewTransferErrors()
	transferResult.job = transfer.job

	var sizer Sizer = &ConstantSizer{size: 0}
	var uploaded int64 = 0
	if transfer.callback != nil {
		transfer.callback(transfer.localPath, 0, sizer.Size(), false)
		defer func() {
			transfer.callback(transfer.localPath, uploaded, sizer.Size(), true)
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

		if fileInfo.IsDir() {
			err := errors.New("the provided path '" + transfer.localPath + "' is a directory, but a file is expected")
			transferResult.Error = err
			return transferResult, err
		}

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
		transfer.callback(transfer.localPath, 0, sizer.Size(), false)
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
		request, err = http.NewRequestWithContext(putContext, http.MethodPut, dest.String(), reader)
	} else {
		request, err = http.NewRequestWithContext(putContext, http.MethodPut, dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		transferResult.Error = err
		return transferResult, err
	}
	// Set the authorization header as well as other headers
	if transfer.token != nil {
		if tokenContents, err := transfer.token.get(); tokenContents != "" && err == nil {
			request.Header.Set("Authorization", "Bearer "+tokenContents)
		}
	}
	request.Header.Set("User-Agent", getUserAgent(transfer.project))
	if searchJobAd(jobId) != "" {
		request.Header.Set("X-Pelican-JobId", searchJobAd(jobId))
	}
	var lastKnownWritten int64
	uploadStart := time.Now()

	go runPut(request, responseChan, errorChan)
	var lastError error = nil

	tickerDuration := 100 * time.Millisecond
	stoppedTransferTimeout := compatToDuration(param.Client_StoppedTransferTimeout.GetDuration(), "Client.StoppedTransferTimeout")
	lastProgress := uploadStart
	progressTicker := time.NewTicker(tickerDuration)
	firstByteRecorded := false
	defer progressTicker.Stop()

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		if !firstByteRecorded && reader.BytesComplete() > 1 {
			// Convert to seconds
			attempt.TimeToFirstByte = time.Since(uploadStart)
			firstByteRecorded = true
		}
		select {
		case <-progressTicker.C:
			uploaded = reader.BytesComplete()
			if transfer.callback != nil {
				transfer.callback(transfer.localPath, uploaded, sizer.Size(), false)
			}
			// Check to see if we are making progress

			timeSinceLastProgress := time.Since(lastProgress)
			if lastKnownWritten < uploaded {
				// We have made progress!
				lastKnownWritten = uploaded
				lastProgress = time.Now()
			} else if timeSinceLastProgress > stoppedTransferTimeout {

				log.Errorln("No progress made in last", timeSinceLastProgress.Round(time.Millisecond).String(), "in upload")
				lastError = &StoppedTransferError{
					BytesTransferred: uploaded,
					StoppedTime:      timeSinceLastProgress,
					Upload:           true,
				}
				// No progress has been made in the last 1 second
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
			log.Errorln("Unexpected error when performing upload:", err)
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Unwrap()
				if err.Error() == "net/http: timeout awaiting response headers" {
					err = &HeaderTimeoutError{}
				}
			}
			if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
				err = &NetworkResetError{}
			}
			lastError = err
			break Loop

		}
	}

	transferEndTime := time.Now()
	uploaded = reader.BytesComplete()
	transferResult.TransferredBytes = uploaded
	attempt.TransferFileBytes = uploaded
	if lastError != nil {
		xferErrors.AddPastError(newTransferAttemptError(dest.Host, "", false, true, lastError), transferEndTime)
		transferResult.Error = xferErrors
		attempt.Error = lastError
	} else {
		log.Debugf("Successful upload of %d bytes", uploaded)
	}
	// Add our attempt fields
	attempt.TransferEndTime = transferEndTime
	attempt.TransferTime = transferEndTime.Sub(transferStartTime)
	transferResult.Attempts = append(transferResult.Attempts, attempt)
	// Note: the top-level `err` (second return value) is only for cases where no
	// transfers were attempted.  If we got here, it must be nil.
	return transferResult, nil
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
		if !errors.Is(err, context.Canceled) {
			log.Errorln("Error with PUT:", err)
		}
		errorChan <- err
		close(errorChan)
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

// This helper function creates a web dav client to walkDavDir's. Used for recursive downloads and lists
func createWebDavClient(collectionsUrl *url.URL, token *tokenGenerator, project string) (client *gowebdav.Client) {
	auth := &bearerAuth{token: token}
	client = gowebdav.NewAuthClient(collectionsUrl.String(), auth)
	client.SetHeader("User-Agent", getUserAgent(project))
	transport := config.GetTransport()
	client.SetTransport(transport)
	return
}

// Depending on the synchronization policy, decide if a object download should be skipped
func skipDownload(syncLevel SyncLevel, remoteInfo fs.FileInfo, localPath string) bool {
	if syncLevel == SyncNone {
		return false
	}
	localInfo, err := os.Stat(localPath)
	if err != nil {
		return false
	}
	switch syncLevel {
	case SyncExist:
		return true
	case SyncSize:
		return localInfo.Size() == remoteInfo.Size()
	}
	return false
}

// Depending on the synchronization policy, decide if the upload should be skipped
func skipUpload(job *TransferJob, localPath string, remoteUrl *pelican_url.PelicanURL) bool {
	if job.syncLevel == SyncNone {
		return false
	}

	localInfo, err := os.Stat(localPath)
	if err != nil {
		return false
	}

	remoteInfo, err := statHttp(remoteUrl, job.dirResp, job.token)
	if err != nil {
		return false
	}

	switch job.syncLevel {
	case SyncExist:
		return true
	case SyncSize:
		return localInfo.Size() == remoteInfo.Size
	}
	return false
}

// Walk a remote collection in a WebDAV server, emitting the files discovered
func (te *TransferEngine) walkDirDownload(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, url *url.URL) error {
	// Create the client to walk the filesystem
	collUrl := job.job.dirResp.XPelNsHdr.CollectionsUrl
	if collUrl == nil {
		return errors.New("Collections URL not found in director response")
	}
	log.Debugln("Trying collections URL: ", collUrl.String())

	client := createWebDavClient(collUrl, job.job.token, job.job.project)
	return te.walkDirDownloadHelper(job, transfers, files, url.Path, client)
}

// Helper function for the `walkDirDownload`.
//
// Recursively walks through the remote server collection, emitting transfer files
// for the engine to process.
func (te *TransferEngine) walkDirDownloadHelper(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, remotePath string, client *gowebdav.Client) error {
	// Check for cancelation since the client does not respect the context
	if err := job.job.ctx.Err(); err != nil {
		return err
	}
	infos, err := client.ReadDir(remotePath)
	if err != nil {
		// Check if we got a 404:
		if gowebdav.IsErrNotFound(err) {
			return errors.New("404: object not found")
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			info, err := client.Stat(remotePath)
			if err != nil {
				return errors.Wrap(err, "failed to stat remote path")
			}
			// If the path leads to a file and not a collection, create a job to download the file and return
			if !info.IsDir() {
				if skipDownload(job.job.syncLevel, info, job.job.localPath) {
					log.Infoln("Skipping download of object", remotePath, "as it already exists at", job.job.localPath)
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
							remoteURL:  &url.URL{Path: remotePath},
							packOption: transfers[0].PackOption,
							localPath:  job.job.localPath,
							upload:     job.job.upload,
							token:      job.job.token,
							attempts:   transfers,
						},
					}:
						job.job.totalXfer += 1
					}
				}
			}
			return nil
		}
		// Otherwise, a different error occurred and we should return it
		return errors.Wrap(err, "failed to read remote collection")
	}
	localBase := strings.TrimPrefix(remotePath, job.job.remoteURL.Path)
	for _, info := range infos {
		newPath := remotePath + "/" + info.Name()
		if info.IsDir() {
			err := te.walkDirDownloadHelper(job, transfers, files, newPath, client)
			if err != nil {
				return err
			}
		} else if localPath := path.Join(job.job.localPath, localBase, info.Name()); skipDownload(job.job.syncLevel, info, localPath) {
			log.Infoln("Skipping download of object", newPath, "as it already exists at", localPath)
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
					localPath:  localPath,
					upload:     job.job.upload,
					token:      job.job.token,
					attempts:   transfers,
				},
			}:
				job.job.totalXfer += 1
			}
		}
	}
	return nil
}

// Helper function for walkDirUpload; not to be called directly
func (te *TransferEngine) walkDirUpload(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, localPath string) error {
	if job.job.ctx.Err() != nil {
		return job.job.ctx.Err()
	}

	// Get our list of directory entries
	infos, err := os.ReadDir(localPath)
	if err != nil {
		info, err := os.Stat(localPath)
		if err != nil {
			return errors.Wrap(err, "failed to stat local path")
		}
		// If the path leads to a file and not a directory, create a job to upload the file and return
		if !info.IsDir() {
			if remotePath := path.Join(job.job.remoteURL.Path, strings.TrimPrefix(localPath, job.job.localPath)); skipUpload(job.job, localPath, job.job.remoteURL) {
				log.Infoln("Skipping upload of object", remotePath, "as it already exists at the destination")
			} else if info.Mode().Type().IsRegular() {
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
						localPath:  job.job.localPath,
						upload:     job.job.upload,
						token:      job.job.token,
						attempts:   transfers,
					},
				}:
					job.job.totalXfer += 1
				}
			}
			return nil
		}
		// Otherwise, a different error occurred and we should return it
		return errors.Wrap(err, "failed to upload local collection")
	}

	for _, info := range infos {
		newPath := localPath + "/" + info.Name()
		remoteUrl, err := pelican_url.Parse(job.job.remoteURL.String(), nil, nil)
		if err != nil {
			return err
		}
		remoteUrl.Path = path.Join(remoteUrl.Path, strings.TrimPrefix(newPath, job.job.localPath))

		if info.IsDir() {
			// Recursively call this function to create any nested dir's as well as list their files
			err := te.walkDirUpload(job, transfers, files, newPath)
			if err != nil {
				return err
			}
		} else if skipUpload(job.job, newPath, remoteUrl) {
			log.Infoln("Skipping upload of object", remoteUrl.Path, "as it already exists at the destination")
		} else if info.Type().IsRegular() {
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
					remoteURL:  &url.URL{Path: remoteUrl.Path},
					packOption: transfers[0].PackOption,
					localPath:  newPath,
					upload:     job.job.upload,
					token:      job.job.token,
					attempts:   transfers,
				},
			}:
				job.job.totalXfer += 1
			}
		}
	}
	return err
}

// This function performs the ls command by walking through the specified collections and printing the contents of the files
func listHttp(remoteUrl *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator) (fileInfos []FileInfo, err error) {
	// Get our collection listing host
	if dirResp.XPelNsHdr.CollectionsUrl == nil {
		return nil, errors.Errorf("Collections URL not found in director response. Are you sure there's an origin for prefix %s that supports listings?", dirResp.XPelNsHdr.Namespace)
	}

	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl
	log.Debugln("Collections URL: ", collectionsUrl.String())

	project := searchJobAd(projectName)
	client := createWebDavClient(collectionsUrl, token, project)
	remotePath := remoteUrl.Path

	infos, err := client.ReadDir(remotePath)
	if err != nil {
		// Check if we got a 404:
		if gowebdav.IsErrNotFound(err) {
			return nil, errors.New("404: object not found")
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// If we get an error code 500 (internal server error), we should check if the user is trying to ls on a file
			info, err := client.Stat(remotePath)
			if err != nil {
				return nil, errors.Wrap(err, "failed to stat remote path")
			}
			// If the path leads to a file and not a collection, just add the filename
			if !info.IsDir() {
				// NOTE: we implement our own FileInfo here because the one we get back from stat() does not have a .name field for some reason
				file := FileInfo{
					Name:         remotePath,
					Size:         info.Size(),
					ModTime:      info.ModTime(),
					IsCollection: false,
				}
				fileInfos = append(fileInfos, file)
				return fileInfos, nil
			}
		} else if gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) {
			// We replace the error from gowebdav with our own because gowebdav returns: "ReadDir /prefix/different-path/: 405" which is not very user friendly
			return nil, errors.Errorf("405: object listings are not supported by the discovered origin")
		}
		// Otherwise, a different error occurred and we should return it
		return nil, errors.Wrap(err, "failed to read remote collection")
	}

	for _, info := range infos {
		jPath, _ := url.JoinPath(remotePath, info.Name())
		// Create a FileInfo for the file and append it to the slice
		file := FileInfo{
			Name:         jPath,
			Size:         info.Size(),
			ModTime:      info.ModTime(),
			IsCollection: info.IsDir(),
		}
		fileInfos = append(fileInfos, file)
	}
	return fileInfos, nil
}

func deleteHttp(remoteUrl *pelican_url.PelicanURL, recursive bool, dirResp server_structs.DirectorResponse, token *tokenGenerator) (err error) {
	log.Debugln("Attempting to delete:", remoteUrl.Path)
	if dirResp.XPelNsHdr.CollectionsUrl == nil {
		return errors.Errorf("collections URL not found in director response.")
	}

	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl

	project := searchJobAd(projectName)
	client := createWebDavClient(collectionsUrl, token, project)
	remotePath := remoteUrl.Path

	info, err := client.Stat(remotePath)
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return errors.Wrap(err, "object not found")
		}
		return errors.Wrap(err, "failed to check object existence")
	}

	if info.IsDir() {
		children, err := client.ReadDir(remotePath)
		if err != nil {
			return errors.Wrap(err, "failed to read directory contents")
		}
		if !recursive && len(children) > 0 {
			return errors.New("cannot delete non-empty directory, use recursive flag or recursive query in the url")
		}
		if recursive {
			for _, child := range children {
				childPath := remotePath + "/" + child.Name()
				err = deleteHttp(&pelican_url.PelicanURL{Path: childPath}, recursive, dirResp, token)
				if err != nil {
					return errors.Wrapf(err, "failed to delete child object: %s", childPath)
				}
			}
		}
	}

	err = client.Remove(remotePath)
	if err != nil {
		if gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) || gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			return err
		}
		return errors.Wrap(err, "failed to delete remote object")
	}
	log.Debugln("Successfully deleted:", remoteUrl.Path)
	return nil
}

// Invoke a stat request against a remote URL that accepts WebDAV protocol,
// using the provided namespace information
//
// If a "dirlist host" is given, then that is used for the namespace info.
// Otherwise, the first three caches are queried simultaneously.
// For any of the queries, if the attempt with the proxy fails, a second attempt
// is made without.
func statHttp(dest *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator) (info FileInfo, err error) {
	statHosts := make([]url.URL, 0, 3)
	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl

	if collectionsUrl != nil {
		endpoint := collectionsUrl
		statHosts = append(statHosts, *endpoint)
	} else if len(dirResp.ObjectServers) > 0 {
		for idx, oServer := range dirResp.ObjectServers {
			if idx > 2 {
				break
			}
			oServer.Path = ""
			statHosts = append(statHosts, *oServer)
		}
	}
	type statResults struct {
		info FileInfo
		err  error
	}
	resultsChan := make(chan statResults)
	transport := config.GetTransport()
	auth := &bearerAuth{token: token}

	for _, statUrl := range statHosts {
		client := gowebdav.NewAuthClient(statUrl.String(), auth)
		destCopy := *(dest.GetRawUrl())
		destCopy.Host = statUrl.Host
		destCopy.Scheme = statUrl.Scheme

		go func(endpoint *url.URL) {
			canDisableProxy := CanDisableProxy()
			disableProxy := !isProxyEnabled()

			var info FileInfo
			for {
				if disableProxy {
					log.Debugln("Performing request (without proxy)", endpoint.String())
					transport.Proxy = nil
				} else {
					log.Debugln("Performing request", endpoint.String())
				}
				client.SetTransport(transport)

				fsinfo, err := client.Stat(endpoint.Path)
				if err == nil {
					info = FileInfo{
						Name:         endpoint.Path,
						Size:         fsinfo.Size(),
						IsCollection: fsinfo.IsDir(),
						ModTime:      fsinfo.ModTime(),
					}
					break
				} else if gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) {
					err = errors.Wrapf(err, "Stat request not allowed for object at endpoint %s", endpoint.String())
					resultsChan <- statResults{FileInfo{}, err}
					return
				} else if gowebdav.IsErrNotFound(err) {
					err = errors.Wrapf(err, "object %s not found at the endpoint %s", dest.String(), endpoint.String())
					resultsChan <- statResults{FileInfo{}, err}
					return
				}

				// If we have a proxy error, we can try again without the proxy
				if urle, ok := err.(*url.Error); canDisableProxy && !disableProxy && ok && urle.Unwrap() != nil {
					if ope, ok := urle.Unwrap().(*net.OpError); ok && ope.Op == "proxyconnect" {
						log.Warnln("Failed to connect to proxy; will retry without:", ope)
						disableProxy = true
						continue
					}
				}
				log.Errorln("Failed to get HTTP response:", err)
				resultsChan <- statResults{FileInfo{}, err}
				return
			}

			resultsChan <- statResults{FileInfo{
				Name:         endpoint.Path,
				Size:         info.Size,
				IsCollection: info.IsCollection,
				ModTime:      info.ModTime,
			}, nil}

		}(&destCopy)
	}
	success := false
	for ctr := 0; ctr < len(statHosts); ctr++ {
		result := <-resultsChan
		if result.err == nil {
			if !success {
				success = true
				info = result.info
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

// This function searches the condor job ad for a specific classad and returns the value of that classad
func searchJobAd(classad classAd) string {

	// Look for the condor job ad file
	condorJobAd, isPresent := os.LookupEnv("_CONDOR_JOB_AD")
	var filename string
	if isPresent {
		filename = condorJobAd
	} else if _, err := os.Stat(".job.ad"); err == nil {
		filename = ".job.ad"
	} else {
		return ""
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		log.Warningln("Can not read .job.ad file", err)
	}

	switch classad {
	// The regex sections of the code below come partially from:
	// https://stackoverflow.com/questions/28574609/how-to-apply-regexp-to-content-in-file-go
	case projectName:
		// Get all matches from file
		// Note: This appears to be invalid regex but is the only thing that appears to work. This way it successfully finds our matches
		classadRegex, e := regexp.Compile(`^*\s*(ProjectName)\s=\s"*(.*)"*`)
		if e != nil {
			log.Fatal(e)
		}

		matches := classadRegex.FindAll(b, -1)
		for _, match := range matches {
			matchString := strings.TrimSpace(string(match))
			if strings.HasPrefix(matchString, "ProjectName") {
				matchParts := strings.Split(strings.TrimSpace(matchString), "=")

				if len(matchParts) == 2 { // just confirm we get 2 parts of the string
					matchValue := strings.TrimSpace(matchParts[1])
					matchValue = strings.Trim(matchValue, "\"") //trim any "" around the match if present
					return matchValue
				}
			}
		}
	case jobId:
		// Get all matches from file
		// Note: This appears to be invalid regex but is the only thing that appears to work. This way it successfully finds our matches
		classadRegex, e := regexp.Compile(`^*\s*(GlobalJobId)\s=\s"*(.*)"*`)
		if e != nil {
			log.Fatal(e)
		}

		matches := classadRegex.FindAll(b, -1)
		for _, match := range matches {
			matchString := strings.TrimSpace(string(match))
			if strings.HasPrefix(matchString, "GlobalJobId") {
				matchParts := strings.Split(strings.TrimSpace(matchString), "=")

				if len(matchParts) == 2 { // just confirm we get 2 parts of the string
					matchValue := strings.TrimSpace(matchParts[1])
					matchValue = strings.Trim(matchValue, "\"") //trim any "" around the match if present
					return matchValue
				}
			}
		}
	default:
		log.Errorln("Invalid classad requested")
		return ""
	}

	return ""
}
