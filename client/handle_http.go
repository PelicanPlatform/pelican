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

package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
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

	// Regex to match the class ad lines
	adLineRegex *regexp.Regexp = regexp.MustCompile(`^\s*([A-Za-z0-9]+)\s=\s"(.*)"\n?$`)

	// Indicates the origin responded too slowly after the cache tried to download from it
	CacheTimedOutReadingFromOrigin = errors.New("cache timed out waiting on origin")

	// ErrObjectNotFound is returned when the requested remote object does not exist.
	ErrObjectNotFound = errors.New("remote object not found")

	// maxWebDavRetries is the maximum number of attempts (including the initial attempt)
	// for WebDAV operations that encounter idle connection errors.
	maxWebDavRetries = 2
)

type (
	logFields string

	classAdAttr string

	transferType int

	ChecksumType int

	// Value of one checksum calculation
	ChecksumInfo struct {
		Algorithm ChecksumType
		Value     []byte
	}

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

	// Represents a mismatched checksum
	ChecksumMismatchError struct {
		Info        ChecksumInfo // The checksum that was calculated by the client
		ServerValue []byte       // The checksum value that was calculated by the server
	}

	HeaderTimeoutError struct{}

	InvalidByteInChunkLengthError struct {
		Err error
	}

	NetworkResetError struct{}

	UnexpectedEOFError struct {
		Err error
	}

	allocateMemoryError struct {
		Err error
	}

	dirListingNotSupportedError struct {
		Err error
	}

	// A writer that discards all data written to it at a provided rate limit
	rateLimitWriter struct {
		ctx         context.Context
		rateLimiter *rate.Limiter
		writer      io.Writer
	}

	// Transfer attempt error wraps an error with information about the service/proxy used
	TransferAttemptError struct {
		serviceHost string
		proxyHost   string
		isUpload    bool
		isProxyErr  bool
		err         error
	}

	// StatusCodeError indicates the server returned a non-200 code.
	//
	// The wrapper is done to provide a Pelican-based error hierarchy in case we ever decide to have
	// a different underlying download package.
	StatusCodeError int

	// Represents the results of a single object transfer,
	// potentially across multiple attempts / retries.
	TransferResults struct {
		JobId             uuid.UUID `json:"jobId"` // The job ID this result corresponds to
		job               *TransferJob
		Error             error            `json:"error"`
		TransferredBytes  int64            `json:"transferredBytes"`
		ServerChecksums   []ChecksumInfo   `json:"serverChecksums"` // Checksums returned by the server
		ClientChecksums   []ChecksumInfo   `json:"clientChecksums"` // Checksums calculated by the client
		TransferStartTime time.Time        `json:"transferStartTime"`
		Scheme            string           `json:"scheme"`
		Source            string           `json:"source"`
		Attempts          []TransferResult `json:"attempts"`
	}

	TransferResult struct {
		Number            int           `json:"attemptNumber"`     // indicates which attempt this is
		TransferFileBytes int64         `json:"transferFileBytes"` // how much each attempt downloaded
		TimeToFirstByte   time.Duration `json:"timeToFirstByte"`   // how long it took to download the first byte
		TransferEndTime   time.Time     `json:"transferEndTime"`   // when the transfer ends
		TransferTime      time.Duration `json:"transferTime"`      // amount of time we were transferring per attempt (in seconds)
		CacheAge          time.Duration `json:"cacheAge"`          // age of the data reported by the cache
		Endpoint          string        `json:"endpoint"`          // which origin did it use
		ServerVersion     string        `json:"serverVersion"`     // version of the server
		Error             error         `json:"error"`             // what error the attempt returned (if any)
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
		ctx                context.Context
		engine             *TransferEngine
		job                *TransferJob
		callback           TransferCallbackFunc
		remoteURL          *url.URL
		srcURL             *url.URL        // When a copy job, this is the source URL to use
		srcToken           *tokenGenerator // When a copy job, the source token to use
		localPath          string
		token              *tokenGenerator
		xferType           transferType
		packOption         string
		attempts           []transferAttemptDetails
		project            string
		requireChecksum    bool
		requestedChecksums []ChecksumType
		err                error
		writer             io.WriteCloser // Optional writer for downloads
		reader             io.ReadCloser  // Optional reader for uploads
	}

	// A representation of a "transfer job".  The job
	// can be submitted to the client library, resulting
	// in one or more transfers (if recursive is true).
	// We assume the transfer job is potentially queued for a
	// long time and all the transfers generated by this job will
	// use the same namespace and token.
	TransferJob struct {
		ctx                context.Context
		cancel             context.CancelFunc
		callback           TransferCallbackFunc
		uuid               uuid.UUID
		remoteURL          *pelican_url.PelicanURL
		lookupDone         atomic.Bool
		lookupErr          error
		activeXfer         atomic.Int64
		totalXfer          int
		skipped403         sync.Mutex // Protects skipped403Objs slice
		skipped403Objs     []string   // List of object paths skipped due to 403 during sync
		localPath          string
		xferType           transferType
		requestedChecksums []ChecksumType
		requireChecksum    bool
		recursive          bool
		skipAcquire        bool
		dryRun             bool                            // Enable dry-run mode to display what would be transferred without actually doing it
		srcURL             *url.URL                        // When a copy job, this is the source URL
		srcDirResp         server_structs.DirectorResponse // When a copy job, this represents the source directory information
		srcToken           *tokenGenerator                 // When a copy job, this represents the source token
		syncLevel          SyncLevel                       // Policy for handling synchronization when the destination exists
		prefObjServers     []*url.URL                      // holds any client-requested caches/origins
		dirResp            server_structs.DirectorResponse
		directorUrl        string
		token              *tokenGenerator
		project            string
		writer             io.WriteCloser // Optional writer for downloads - if set, write to this instead of localPath
		reader             io.ReadCloser  // Optional reader for uploads - if set, read from this instead of localPath
		inPlace            bool           // If true, write directly to final destination; if false, use temporary file
		forcePrestageAPI   bool           // If true, force use of prestage API and error if not supported (no fallback)
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
		ctx                context.Context // The context provided upon creation of the engine.
		cancel             context.CancelFunc
		egrp               *errgroup.Group // The errgroup for the worker goroutines
		work               chan *clientTransferJob
		files              chan *clientTransferFile
		results            chan *clientTransferResults
		jobLookupDone      chan *clientTransferJob // Indicates the job lookup handler is done with the job
		workersActive      int
		resultsMap         map[uuid.UUID]chan *TransferResults
		workMap            map[uuid.UUID]chan *TransferJob
		notifyChan         chan bool
		closeChan          chan bool
		closeDoneChan      chan bool
		ewmaTick           *time.Ticker
		ewma               ewma.MovingAverage
		ewmaVal            atomic.Int64
		ewmaCtr            atomic.Int64
		clientLock         sync.RWMutex
		pelicanUrlCache    *pelican_url.Cache
		prestageAPISupport map[string]bool // Lookup table for caches that support the Pelican prestage API (key: host)
		prestageAPIMutex   sync.RWMutex    // Protects the prestageAPISupport map
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
		dryRun         bool      // Enable dry-run mode to display what would be transferred without actually doing it
		work           chan *TransferJob
		closed         bool
		prefObjServers []*url.URL // holds any client-requested caches/origins
		results        chan *TransferResults
		finalResults   chan TransferResults
		setupResults   sync.Once
	}

	TransferOption                         = option.Interface
	identTransferOptionCaches              struct{}
	identTransferOptionCallback            struct{}
	identTransferOptionTokenLocation       struct{}
	identTransferOptionAcquireToken        struct{}
	identTransferOptionToken               struct{}
	identTransferOptionSourceTokenLocation struct{}
	identTransferOptionSourceToken         struct{}
	identTransferOptionSynchronize         struct{}
	identTransferOptionCollectionsUrl      struct{}
	identTransferOptionChecksums           struct{}
	identTransferOptionRequireChecksum     struct{}
	identTransferOptionRecursive           struct{}
	identTransferOptionDepth               struct{}
	identTransferOptionWriter              struct{}
	identTransferOptionReader              struct{}
	identTransferOptionInPlace             struct{}
	identTransferOptionDryRun              struct{}
	identTransferOptionForcePrestageAPI    struct{}

	transferDetailsOptions struct {
		NeedsToken bool
		PackOption string
	}

	// progressWriter is the same idea as ProgressReader but in reverse
	// -- periodically updates the byte count such that it can be used
	// by the main go routine doing the download
	progressWriter struct {
		writer         io.Writer
		bytesWritten   atomic.Int64
		firstByteTime  time.Time
		closed         atomic.Bool
		bytesPerSecond atomic.Int64
		lastRateSample time.Time
	}
)

const (
	// The EWMA library we use assumes there's a single tick per second
	ewmaInterval = time.Second

	attrProjectName classAdAttr = "ProjectName"
	attrJobId       classAdAttr = "GlobalJobId"

	// The checksum algorithms supported by the client
	//
	// Note we have a helper function, KnownChecksumTypes, that returns a list
	// of all the elements enumerated below; do not skip integers in this list
	// or that functionality will break.
	//
	AlgMD5     ChecksumType = iota // Checksum is using the MD5 algorithm
	AlgCRC32C                      // Checksum is using the CRC32C algorithm
	AlgCRC32                       // Checksum is using the CRC32 algorithm
	AlgSHA1                        // Checksum is using the SHA-1 algorithm
	AlgUnknown                     // Unknown checksum algorithm.  Always a "trailer" indicating the last known algorithm.

	AlgDefault = AlgCRC32C // Default checksum algorithm is CRC32C if the client doesn't specify one.
	algFirst   = AlgMD5
	algLast    = AlgUnknown
)

const (
	SyncNone  SyncLevel = iota // When synchronizing, always re-transfer, regardless of existence at destination.
	SyncExist                  // Skip synchronization transfer if the destination exists
	SyncSize                   // Skip synchronization transfer if the destination exists and matches the current source size
)

const (
	transferTypeDownload transferType = iota // Transfer is downloading from the federation
	transferTypeUpload                       // Transfer is uploading to the federation
	transferTypePrestage                     // Transfer is staging at a federation cache
	transferTypeCopy                         // Transfer copies objects between origins
)

var (
	jobAdOnce sync.Once         // Synchronize access to the process's job ad
	jobAd     map[string]string // String version of the key/values of job ad

	// The parameter table for crc32c
	crc32cTable *crc32.Table = crc32.MakeTable(crc32.Castagnoli)

	// Error condition indicating that the progress writer was externally closed
	// before the transfer was completed
	progressWriterClosed error = errors.New("progress writer closed")

	ErrServerChecksumMissing = errors.New("no checksum information was returned by server but checksums were required by the client")
)

func ChecksumFromHttpDigest(httpDigest string) ChecksumType {
	switch httpDigest {
	case "md5":
		return AlgMD5
	case "crc32c":
		return AlgCRC32C
	case "crc32":
		return AlgCRC32
	case "sha":
		return AlgSHA1
	}
	return AlgUnknown
}

// List all the checksum types known to the client
func KnownChecksumTypes() (result []ChecksumType) {
	result = make([]ChecksumType, algLast-algFirst)
	for idx := algFirst; idx < algLast; idx++ {
		result[idx-algFirst] = idx
	}
	return
}

// List all the checksum types known as HTTP digest strings
func KnownChecksumTypesAsHttpDigest() (result []string) {
	known := KnownChecksumTypes()
	result = make([]string, len(known))
	for idx, checksumType := range known {
		result[idx] = HttpDigestFromChecksum(checksumType)
	}
	return
}

func HttpDigestFromChecksum(checksumType ChecksumType) string {
	switch checksumType {
	case AlgCRC32:
		return "crc32"
	case AlgCRC32C:
		return "crc32c"
	case AlgMD5:
		return "md5"
	case AlgSHA1:
		return "sha"
	}
	return ""
}

// Convert a checksum value to a human-readable string matching the encoding
// specified in RFC 3230
func checksumValueToHttpDigest(checksumType ChecksumType, checksumValue []byte) string {
	switch checksumType {
	case AlgCRC32:
		fallthrough
	case AlgCRC32C:
		return hex.EncodeToString(checksumValue)
	case AlgMD5:
		fallthrough
	case AlgSHA1:
		return base64.StdEncoding.EncodeToString(checksumValue)
	}
	return "(unknown checksum type)"
}

// Reset the memory-cached copy of the HTCondor job ad
//
// The client will search through the process's environment to find
// a HTCondor "job ad" and cache its contents in memory; the job ad
// is used to determine the project name and job ID for the transfer
// headers.
//
// This function is used to reset the job ad and is intended for use
// in unit tests that need to reset things from outside the cache package.
func ResetJobAd() {
	jobAdOnce = sync.Once{}
}

// Write data to the rateLimitDiscarder; after applying the built-in
// rate limit, it'll ignore the written data
func (r *rateLimitWriter) Write(p []byte) (n int, err error) {
	bytesSoFar := 0
	if r.rateLimiter == nil {
		return r.writer.Write(p)
	}
	for len(p) > 0 {
		if len(p) > 64*1024 {
			if err = r.rateLimiter.WaitN(r.ctx, 64*1024); err != nil {
				return bytesSoFar, err
			}
			if n, err = r.writer.Write(p[:64*1024]); err != nil {
				return n, err
			}
			p = p[64*1024:]
			bytesSoFar += n
		} else {
			if err = r.rateLimiter.WaitN(r.ctx, len(p)); err != nil {
				return bytesSoFar, err
			}
			n, err = r.writer.Write(p)
			bytesSoFar += n
			return bytesSoFar, err
		}
	}
	return bytesSoFar, nil
}

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

// mergeCancel combines two contexts and returns a new context with a unified cancel function.
func mergeCancel(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	newCtx, cancel := context.WithCancel(ctx1)
	stop := context.AfterFunc(ctx2, func() {
		cancel()
	})
	return newCtx, func() {
		stop()
		cancel()
	}
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

// Create a new transfer results object
func newTransferResults(job *TransferJob) TransferResults {
	return TransferResults{
		job:      job,
		JobId:    job.uuid,
		Attempts: make([]TransferResult, 0),
		Source:   job.remoteURL.String(),
	}
}

func (tr TransferResults) ID() string {
	return tr.JobId.String()
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
	pelicanUrlCache := pelican_url.StartCache(ctx, egrp)

	te = &TransferEngine{
		ctx:                ctx,
		cancel:             cancel,
		egrp:               egrp,
		work:               work,
		files:              files,
		results:            results,
		resultsMap:         make(map[uuid.UUID]chan *TransferResults),
		workMap:            make(map[uuid.UUID]chan *TransferJob),
		jobLookupDone:      make(chan *clientTransferJob, 5),
		notifyChan:         make(chan bool),
		closeChan:          make(chan bool),
		closeDoneChan:      make(chan bool),
		ewmaTick:           time.NewTicker(ewmaInterval),
		ewma:               ewma.NewMovingAverage(20), // By explicitly setting the age to 20s, the first 10 seconds will use an average of historical samples instead of EWMA
		pelicanUrlCache:    pelicanUrlCache,
		prestageAPISupport: make(map[string]bool),
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

// Override collections URL to be used by the TransferClient
func WithCollectionsUrl(url string) TransferOption {
	return option.New(identTransferOptionCollectionsUrl{}, url)
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

// Create an option to provide a source token for a third-party-copy transfer
func WithSourceToken(token string) TransferOption {
	return option.New(identTransferOptionSourceToken{}, token)
}

// Create an option to provide a source token location for a third-party-copy transfer
func WithSourceTokenLocation(location string) TransferOption {
	return option.New(identTransferOptionSourceTokenLocation{}, location)
}

// Create an option to specify the checksums to request for a given
// transfer
func WithRequestChecksums(types []ChecksumType) TransferOption {
	return option.New(identTransferOptionChecksums{}, types)
}

// Indicate that checksum verification is required
func WithRequireChecksum() TransferOption {
	return option.New(identTransferOptionRequireChecksum{}, true)
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

// Create an option to provide an io.WriteCloser for download destination
//
// When provided, downloaded data will be written to this writer instead of localPath.
// The writer will be closed on completion or error.
func WithWriter(writer io.WriteCloser) TransferOption {
	return option.New(identTransferOptionWriter{}, writer)
}

// Create an option to provide an io.ReadCloser for upload source
//
// When provided, upload data will be read from this reader instead of localPath.
// The reader will be closed on completion or error.
func WithReader(reader io.ReadCloser) TransferOption {
	return option.New(identTransferOptionReader{}, reader)
}

// Create an option to enable recursive listing
//
// When enabled, the list operation will recursively traverse all subdirectories
func WithRecursive(recursive bool) TransferOption {
	return option.New(identTransferOptionRecursive{}, recursive)
}

// Create an option to specify the maximum depth for recursive listing
//
// The depth parameter controls how deep the recursive listing will go.
// A depth of 0 means only the specified directory, 1 means one level deep, etc.
// A depth of -1 means unlimited depth.
func WithDepth(depth int) TransferOption {
	return option.New(identTransferOptionDepth{}, depth)
}

// Create an option to specify whether to write files in-place or use temporary files
//
// When inPlace is false (default), files are written to temporary names and atomically
// renamed on success (similar to rsync's default behavior). When true, files are written
// directly to their final destination (similar to rsync's --inplace option).
func WithInPlace(inPlace bool) TransferOption {
	return option.New(identTransferOptionInPlace{}, inPlace)
}

// Create an option to enable dry-run mode
//
// When enabled, the transfer will display what would be copied without actually
// modifying the destination. Useful for verifying paths and sources before
// performing actual transfers.
func WithDryRun(enable bool) TransferOption {
	return option.New(identTransferOptionDryRun{}, enable)
}

// Create an option to force use of the Pelican prestage API
//
// When enabled for prestage transfers, the client will return an error if the cache
// does not support the Pelican prestage API instead of falling back to the traditional
// method. This is useful for testing to ensure the API is actually being used.
func WithForcePrestageAPI(force bool) TransferOption {
	return option.New(identTransferOptionForcePrestageAPI{}, force)
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
		case identTransferOptionDryRun{}:
			client.dryRun = option.Value().(bool)
		case identTransferOptionForcePrestageAPI{}:
			// This option is handled at the job level, not client level
			// Skip it here; it will be processed in NewTransferJob/NewPrestageJob
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
			select {
			case <-te.ctx.Done():
				log.Debugln("Transfer engine has been cancelled, not returning job lookup notification")
			case te.jobLookupDone <- job:
			}
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
	project, _ := searchJobAd(attrProjectName)
	copyUrl := *pUrl // Make a copy of the input URL to avoid concurrent issues.
	if _, exists := copyUrl.Query()[pelican_url.QueryRecursive]; exists {
		recursive = true
	}
	operation := config.TokenSharedRead
	if upload {
		operation = config.TokenSharedWrite
	}
	tj = &TransferJob{
		prefObjServers: tc.prefObjServers,
		recursive:      recursive,
		localPath:      localPath,
		remoteURL:      &copyUrl,
		callback:       tc.callback,
		skipAcquire:    tc.skipAcquire,
		dryRun:         tc.dryRun,
		syncLevel:      tc.syncLevel,
		xferType:       transferTypeDownload,
		uuid:           id,
		project:        project,
		token:          NewTokenGenerator(&copyUrl, nil, operation, !tc.skipAcquire),
		inPlace:        false, // Default to using temporary files (rsync-style)
	}
	if upload {
		tj.xferType = transferTypeUpload
	}
	if tc.token != "" {
		tj.token.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
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
		case identTransferOptionChecksums{}:
			tj.requestedChecksums = option.Value().([]ChecksumType)
		case identTransferOptionRequireChecksum{}:
			tj.requireChecksum = option.Value().(bool)
		case identTransferOptionWriter{}:
			tj.writer = option.Value().(io.WriteCloser)
		case identTransferOptionReader{}:
			tj.reader = option.Value().(io.ReadCloser)
		case identTransferOptionInPlace{}:
			tj.inPlace = option.Value().(bool)
		case identTransferOptionDryRun{}:
			tj.dryRun = option.Value().(bool)
		}
	}

	httpMethod := http.MethodGet
	if upload {
		httpMethod = http.MethodPut
	}

	tj.directorUrl = copyUrl.FedInfo.DirectorEndpoint
	dirResp, err := GetDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, "")
	if err != nil {
		var sce *StatusCodeError
		if errors.As(err, &sce) {
			return
		}
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", pUrl.String())
		return
	}
	tj.dirResp = dirResp
	tj.token.DirResp = &dirResp

	if upload || dirResp.XPelNsHdr.RequireToken {
		contents, err := tj.token.Get()
		if err != nil || contents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, contents)
			if err != nil {
				var sce *StatusCodeError
				if errors.As(err, &sce) {
					return nil, err
				}
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

// Create a new prestage job for the client
//
// The returned object can be further customized as desired.
// This function does not "submit" the job for execution.
func (tc *TransferClient) NewPrestageJob(ctx context.Context, remoteUrl *url.URL, options ...TransferOption) (tj *TransferJob, err error) {

	id, err := uuid.NewV7()
	if err != nil {
		return
	}

	// See if we have a projectName defined
	project, _ := searchJobAd(attrProjectName)

	pelicanURL, err := ParseRemoteAsPUrl(ctx, remoteUrl.String())
	if err != nil {
		err = errors.Wrap(err, "error generating metadata for specified url")
		return
	}

	copyUrl := *pelicanURL // Make a copy of the input URL to avoid concurrent issues.
	tj = &TransferJob{
		prefObjServers: tc.prefObjServers,
		remoteURL:      &copyUrl,
		callback:       tc.callback,
		skipAcquire:    tc.skipAcquire,
		syncLevel:      tc.syncLevel,
		xferType:       transferTypePrestage,
		uuid:           id,
		project:        project,
		token:          NewTokenGenerator(&copyUrl, nil, config.TokenSharedRead, !tc.skipAcquire),
	}
	if tc.token != "" {
		tj.token.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
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
		case identTransferOptionForcePrestageAPI{}:
			tj.forcePrestageAPI = option.Value().(bool)
		}
	}

	tj.directorUrl = pelicanURL.FedInfo.DirectorEndpoint
	dirResp, err := GetDirectorInfoForPath(tj.ctx, pelicanURL, http.MethodGet, "")
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
		return
	}
	tj.dirResp = dirResp
	tj.token.DirResp = &dirResp

	log.Debugln("Dir resp:", dirResp.XPelNsHdr)
	if dirResp.XPelNsHdr.RequireToken {
		contents, err := tj.token.Get()
		if err != nil || contents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(tj.ctx, pelicanURL, http.MethodGet, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
				return nil, err
			}
			tj.dirResp = dirResp
			tj.token.DirResp = &dirResp
		}
	} else {
		tj.token = nil
	}

	log.Debugf("Created new prestage job, ID %s client %s, for URL %s", tj.uuid.String(), tc.id.String(), remoteUrl.String())
	return
}

// Create a new third-party copy job for the client.
//
// This creates a transfer that uses the HTTP COPY verb to instruct the
// destination server to pull data directly from the source, without the
// client acting as an intermediary.
//
// The returned object can be further customized as desired.
// This function does not "submit" the job for execution.
func (tc *TransferClient) NewCopyJob(ctx context.Context, src *url.URL, dest *url.URL, recursive bool, options ...TransferOption) (tj *TransferJob, err error) {

	id, err := uuid.NewV7()
	if err != nil {
		return
	}

	destPUrl, err := ParseRemoteAsPUrl(ctx, dest.String())
	if err != nil {
		return
	}

	srcPUrl, err := ParseRemoteAsPUrl(ctx, src.String())
	if err != nil {
		return
	}

	// Check for recursive query parameter in source or destination URLs
	if _, exists := srcPUrl.Query()[pelican_url.QueryRecursive]; exists {
		recursive = true
	}
	if _, exists := destPUrl.Query()[pelican_url.QueryRecursive]; exists {
		recursive = true
	}

	project, _ := searchJobAd(attrProjectName)
	copyDestUrl := *destPUrl
	copySrcUrl := *srcPUrl
	tj = &TransferJob{
		prefObjServers: tc.prefObjServers,
		recursive:      recursive,
		remoteURL:      &copyDestUrl,
		callback:       tc.callback,
		skipAcquire:    tc.skipAcquire,
		syncLevel:      tc.syncLevel,
		xferType:       transferTypeCopy,
		uuid:           id,
		project:        project,
		token:          NewTokenGenerator(&copyDestUrl, nil, config.TokenSharedWrite, !tc.skipAcquire),
	}
	tj.srcURL = src
	tj.srcToken = NewTokenGenerator(&copySrcUrl, nil, config.TokenSharedRead, !tc.skipAcquire)
	if tc.token != "" {
		tj.token.SetToken(tc.token)
		tj.srcToken.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
		tj.srcToken.SetTokenLocation(tc.tokenLocation)
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
		case identTransferOptionSourceToken{}:
			tj.srcToken.SetToken(option.Value().(string))
		case identTransferOptionSourceTokenLocation{}:
			tj.srcToken.SetTokenLocation(option.Value().(string))
		case identTransferOptionSynchronize{}:
			tj.syncLevel = option.Value().(SyncLevel)
		}
	}

	// Resolve the destination director information
	tj.directorUrl = copyDestUrl.FedInfo.DirectorEndpoint
	dirResp, err := GetDirectorInfoForPath(tj.ctx, &copyDestUrl, http.MethodPut, "")
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for destination URL %s", dest.String())
		return
	}
	tj.dirResp = dirResp
	tj.token.DirResp = &dirResp

	// Acquire token for the destination if needed
	if dirResp.XPelNsHdr.RequireToken {
		contents, tErr := tj.token.Get()
		if tErr != nil || contents == "" {
			err = errors.Wrap(tErr, "failed to get token for copy destination")
			return nil, err
		}
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyDestUrl, http.MethodPut, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for destination URL %s", dest.String())
				return nil, err
			}
			tj.dirResp = dirResp
			tj.token.DirResp = &dirResp
		}
	}

	// Resolve the source director information
	srcDirResp, err := GetDirectorInfoForPath(tj.ctx, &copySrcUrl, http.MethodGet, "")
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for source URL %s", src.String())
		return
	}
	tj.srcDirResp = srcDirResp
	tj.srcToken.DirResp = &srcDirResp

	if srcDirResp.XPelNsHdr.RequireToken {
		contents, tErr := tj.srcToken.Get()
		if tErr != nil || contents == "" {
			err = errors.Wrap(tErr, "failed to get token for copy source")
			return nil, err
		}
		if contents != "" {
			srcDirResp, err = GetDirectorInfoForPath(tj.ctx, &copySrcUrl, http.MethodGet, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for source URL %s", src.String())
				return nil, err
			}
			tj.srcDirResp = srcDirResp
			tj.srcToken.DirResp = &srcDirResp
		}
	} else {
		tj.srcToken = nil
	}

	log.Debugf("Created new copy job, ID %s client %s, from %s to %s", tj.uuid.String(), tc.id.String(), src.String(), dest.String())
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
	log.Debugln("Submitting transfer job", tj.uuid.String())
	select {
	case <-tc.ctx.Done():
		return tc.ctx.Err()
	case tc.work <- tj:
		return nil
	}
}

// cacheInfo retrieves and returns the age and size of the specified object.
func (tc *TransferClient) CacheInfo(ctx context.Context, remoteUrl *url.URL, options ...TransferOption) (age int, size int64, err error) {
	age = -1

	pelicanURL, err := ParseRemoteAsPUrl(ctx, remoteUrl.String())
	if err != nil {
		err = errors.Wrap(err, "error generating metadata for specified URL")
		return
	}

	var prefObjServers []*url.URL
	token := NewTokenGenerator(pelicanURL, nil, config.TokenSharedRead, true)
	if tc.token != "" {
		token.SetToken(tc.token)
	}
	if tc.tokenLocation != "" {
		token.SetTokenLocation(tc.tokenLocation)
	}
	if tc.skipAcquire {
		token.EnableAcquire = !tc.skipAcquire
	}
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionCaches{}:
			prefObjServers = option.Value().([]*url.URL)
		case identTransferOptionTokenLocation{}:
			token.SetTokenLocation(option.Value().(string))
		case identTransferOptionAcquireToken{}:
			token.EnableAcquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token.SetToken(option.Value().(string))
		}
	}

	ctx, cancel := mergeCancel(tc.ctx, ctx)
	defer cancel()

	dirResp, err := GetDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, "")
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
		return
	}
	token.DirResp = &dirResp

	if dirResp.XPelNsHdr.RequireToken {
		var contents string
		contents, err = token.Get()
		if err != nil || contents == "" {
			err = errors.Wrap(err, "failed to get token for cache info query")
			return
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
				return
			}
			token.DirResp = &dirResp
		}
	} else {
		token = nil
	}

	var sortedServers []*url.URL
	sortedServers, err = generateSortedObjServers(dirResp, prefObjServers)
	if err != nil {
		log.Errorln("Failed to get namespace caches (treated as non-fatal):", err)
		return
	}
	if len(sortedServers) == 0 {
		err = errors.New("No available cache servers detected")
		return
	}
	cacheUrl := *sortedServers[0]
	cacheUrl.Path = remoteUrl.Path

	return objectCached(ctx, &cacheUrl, token)
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
	jobsSkipped := make(map[uuid.UUID]bool) // Track which jobs we've already reported skips for
	for {
		select {
		case <-tc.ctx.Done():
			err = tc.ctx.Err()
			return
		case result, ok := <-resultsChan:
			if !ok {
				// Print summary of skipped files for each job before returning
				for _, r := range results {
					if r.job != nil && !jobsSkipped[r.job.uuid] {
						r.job.skipped403.Lock()
						skipCount := len(r.job.skipped403Objs)
						skippedObjs := make([]string, len(r.job.skipped403Objs))
						copy(skippedObjs, r.job.skipped403Objs)
						r.job.skipped403.Unlock()

						if skipCount > 0 {
							jobsSkipped[r.job.uuid] = true
							if skipCount <= 2 {
								log.Warnf("Skipped upload of %d object(s) because of permission denied errors (object most likely already exists at the origin): %v",
									skipCount, skippedObjs)
							} else {
								log.Warnf("Skipped upload of %d objects because of permission denied errors (objects most likely already exist at the origin)",
									skipCount)
							}
						}
					}
				}
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
	remoteUrl := &url.URL{Path: job.job.remoteURL.Path, Scheme: job.job.remoteURL.Scheme, Host: job.job.remoteURL.Host}

	// For copy jobs, also build the source URL
	var srcUrl *url.URL
	if job.job.xferType == transferTypeCopy {
		srcUrl = &url.URL{Path: job.job.srcURL.Path, Scheme: job.job.srcURL.Scheme}
	}

	var transfers []transferAttemptDetails
	if job.job.xferType == transferTypeUpload { // Uploads use the redirected endpoint
		if len(job.job.dirResp.ObjectServers) == 0 {
			err = errors.New("No origins found for upload")
			return
		}
		transfers = append(transfers, transferAttemptDetails{
			Url:        job.job.dirResp.ObjectServers[0],
			PackOption: packOption,
		})
	} else if job.job.xferType == transferTypeCopy {
		// For copy, the "attempts" represent the source servers the destination will pull from
		var sortedSrcServers []*url.URL
		sortedSrcServers, err = generateSortedObjServers(job.job.srcDirResp, nil)
		if err != nil {
			log.Errorln("Failed to get source servers for copy:", err)
			return
		}
		for _, srcServer := range sortedSrcServers {
			srcServerUrl := *srcServer
			srcServerUrl.Path = path.Clean(job.job.srcURL.Path)
			copiedUrl := srcServerUrl
			transfers = append(transfers, transferAttemptDetails{
				Url: &copiedUrl,
			})
		}
		if len(transfers) == 0 {
			err = errors.New("No source servers found for copy")
			return
		}
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

	// Ensure all transfer URLs have the proper path set (except for unix:// URLs)
	for idx := range transfers {
		if transfers[idx].Url.Scheme == "unix" {
			continue
		}
		if transfers[idx].Url.Path == "/" || transfers[idx].Url.Path == "" {
			transfers[idx].Url.Path = path.Clean(job.job.remoteURL.Path)
		}
	}

	if job.job.recursive {
		if job.job.xferType == transferTypeUpload {
			// The URL returned by the director for directory /foo may be
			// something like https://example.com/prefix/foo.  The transfers emitted
			// by walkDirUpload are in the federation namespaces (i.e., /foo/bar.txt) so
			// we need to provide it with a transfer string that is the root of the
			// federation namespace, https://example.com/prefix/ in this case.
			remotePath := transfers[0].Url.Path
			transfers[0].Url.Path = strings.TrimSuffix(path.Clean(remotePath), path.Clean(job.job.remoteURL.Path))
			return te.walkDirUpload(job, transfers, te.files, job.job.localPath)
		} else if job.job.xferType == transferTypeDownload {
			// For downloads, we need to stat the remote path to see if it's a collection
			// If it is not a collection, we just proceed with a single file transfer
			var statInfo FileInfo
			var statErr error
			var pelicanUrl *pelican_url.PelicanURL
			pelicanUrl, err = pelican_url.Parse(remoteUrl.String(), nil, nil)
			if err != nil {
				return errors.Wrap(err, "failed to parse remote URL for recursive download")
			}
			if statInfo, statErr = statHttp(pelicanUrl, job.job.dirResp, job.job.token); statErr != nil {
				log.Infoln("Error is not found:", errors.Is(statErr, ErrObjectNotFound))
				return errors.Wrap(statErr, "failed to stat remote path for recursive download")
			}

			if statInfo.IsCollection {
				return te.walkDirDownload(job, transfers, te.files, remoteUrl)
			}
		} else if job.job.xferType == transferTypeCopy {
			// For copy, stat the SOURCE to see if it's a collection.
			// If it is, walk the source directory listing and emit individual TPC copy jobs.
			srcUrl := &url.URL{Path: job.job.srcURL.Path, Scheme: job.job.srcURL.Scheme, Host: job.job.srcURL.Host}
			var srcPelicanUrl *pelican_url.PelicanURL
			srcPelicanUrl, err = pelican_url.Parse(srcUrl.String(), nil, nil)
			if err != nil {
				return errors.Wrap(err, "failed to parse source URL for recursive copy")
			}
			var statInfo FileInfo
			if statInfo, err = statHttp(srcPelicanUrl, job.job.srcDirResp, job.job.srcToken); err != nil {
				return errors.Wrap(err, "failed to stat source path for recursive copy")
			}

			if statInfo.IsCollection {
				return te.walkDirCopy(job, transfers, te.files, srcUrl)
			}
		}
		log.Debugln("Remote path is not a collection; proceeding with single file transfer")
	} else if job.job.xferType == transferTypePrestage {
		// For prestage, from day one we handle internally whether it's recursive
		// (as opposed to making the user specify explicitly)
		var statInfo FileInfo
		var pelicanUrl *pelican_url.PelicanURL
		pelicanUrl, err = pelican_url.Parse(remoteUrl.String(), nil, nil)
		if err != nil {
			return
		}
		if statInfo, err = statHttp(pelicanUrl, job.job.dirResp, job.job.token); err != nil {
			err = errors.Wrap(err, "failed to stat object to prestage")
			return
		}
		if statInfo.IsCollection {
			return te.walkDirDownload(job, transfers, te.files, remoteUrl)
		}
	}

	log.Debugln("Queuing transfer for object", remoteUrl.String(), "with first transfer URL:", transfers[0].Url.String())
	job.job.totalXfer += 1
	job.job.activeXfer.Add(1)
	select {
	case <-te.ctx.Done():
		log.Debugln("Transfer engine has been cancelled, not queuing new transfer file information")
	case te.files <- &clientTransferFile{
		uuid:  job.uuid,
		jobId: job.job.uuid,
		file: &transferFile{
			ctx:                job.job.ctx,
			callback:           job.job.callback,
			job:                job.job,
			engine:             te,
			remoteURL:          remoteUrl,
			srcURL:             srcUrl,
			srcToken:           job.job.srcToken,
			requestedChecksums: job.job.requestedChecksums,
			requireChecksum:    job.job.requireChecksum,
			packOption:         packOption,
			localPath:          job.job.localPath,
			xferType:           job.job.xferType,
			token:              job.job.token,
			attempts:           transfers,
			project:            job.job.project,
			writer:             job.job.writer,
			reader:             job.job.reader,
		},
	}:
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
				select {
				case <-ctx.Done():
					return ctx.Err()
				case results <- &clientTransferResults{
					id: file.uuid,
					results: TransferResults{
						JobId: file.jobId,
						Error: file.file.ctx.Err(),
					},
				}:
				}
				break
			}
			if file.file.err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()

				case results <- &clientTransferResults{
					id: file.uuid,
					results: TransferResults{
						JobId: file.jobId,
						Error: file.file.err,
					},
				}:
				}
				break
			}
			var err error
			var transferResults TransferResults
			if file.file.xferType == transferTypeUpload {
				transferResults, err = uploadObject(file.file)
			} else if file.file.xferType == transferTypeCopy {
				transferResults, err = copyHTTP(file.file)
			} else {
				transferResults, err = downloadObject(file.file)
			}
			transferResults.JobId = file.jobId
			transferResults.Scheme = file.file.remoteURL.Scheme
			if err != nil {
				log.Errorf("Error when attempting to transfer object %s for client %s: %v", file.file.remoteURL, file.uuid.String(), err)
				transferResults = newTransferResults(file.file.job)
				transferResults.Scheme = file.file.remoteURL.Scheme
				transferResults.Error = err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case results <- &clientTransferResults{id: file.uuid, results: transferResults}:
			}
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

			if age, size, err := objectCached(ctx, tUrl, token); err != nil {
				headChan <- checkResults{idx, 0, -1, err}
				return
			} else {
				headChan <- checkResults{idx, uint64(size), age, err}
			}

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
	var downloaded int64
	localPath := transfer.localPath
	transferResults.job = transfer.job

	// Create a checksum hash instance for each requested checksum; these will all be
	// joined together into a single writer interface with the output file
	hashes := make([]io.Writer, 0, 1)
	for _, requestedChecksum := range transfer.requestedChecksums {
		switch requestedChecksum {
		case AlgCRC32:
			hashes = append(hashes, crc32.NewIEEE())
		case AlgCRC32C:
			hashes = append(hashes, crc32.New(crc32cTable))
		case AlgMD5:
			hashes = append(hashes, md5.New())
		case AlgSHA1:
			hashes = append(hashes, sha1.New())
		}
	}
	if len(hashes) == 0 {
		hashes = append(hashes, crc32.New(crc32cTable))
	}
	hashesWriter := io.MultiWriter(hashes...)

	// Prepare the local path for transfer; create the directory (as necessary) and remove
	// any pre-existing file or failed attempt.
	// By time this block has finished, we have a writer interface representing the transfer
	// destination (could be io.Discard!) that we'll join with the hashesWriter.
	var fileWriter io.Writer
	var writeDestination string // Path to write to (may be temporary file or final destination)
	var fileCloser io.Closer
	var fp *os.File // File pointer for temp file that needs to be closed before rename on Windows

	// Check if we have a custom writer provided (e.g., for io.FS implementation)
	if transfer.writer != nil {
		fileWriter = transfer.writer
		fileCloser = transfer.writer
		localPath = "" // Don't use localPath when using custom writer
	} else if transfer.xferType == transferTypeDownload {
		// In dry-run mode, skip actual file operations and just report what would happen
		if transfer.job != nil && transfer.job.dryRun {
			// Determine the final local path
			finalLocalPath := localPath
			if len(localPath) > 0 && os.IsPathSeparator(localPath[len(localPath)-1]) {
				finalLocalPath = path.Join(localPath, path.Base(transfer.remoteURL.Path))
			}
			// Print to stdout with structured format for easy parsing
			fmt.Printf("DOWNLOAD: %s -> %s\n", transfer.remoteURL.Path, finalLocalPath)
			return transferResults, nil
		}

		var info os.FileInfo
		if info, err = os.Stat(localPath); err != nil {
			if os.IsNotExist(err) {
				// If we're unpacking, the destination must be a directory. Create it directly.
				if transfer.packOption != "" {
					if err = os.MkdirAll(localPath, 0777); err != nil {
						return
					}
					if info, err = os.Stat(localPath); err != nil {
						return
					}
				} else {
					directory := path.Dir(localPath)
					if localPath != "" && os.IsPathSeparator(localPath[len(localPath)-1]) {
						directory = localPath
						localPath = path.Join(directory, path.Base(transfer.job.remoteURL.Path))
					}
					if err = os.MkdirAll(directory, 0777); err != nil {
						return
					}
				}
			} else {
				return
			}
		}
		if transfer.packOption != "" {
			var behavior packerBehavior
			if behavior, err = GetBehavior(transfer.packOption); err != nil {
				return
			}
			if info == nil || !info.IsDir() {
				err = errors.New("destination path is not a directory; must be a directory for unpacking")
				return
			}
			if localPath, err = filepath.Abs(localPath); err != nil {
				err = errors.Wrap(err, "failed to get absolute path for destination directory")
				return
			}
			fileWriter = newAutoUnpacker(localPath, behavior)
			// Pack operations unpack in-place to the destination directory
			writeDestination = localPath
		} else {
			if info != nil && info.IsDir() {
				localPath = path.Join(localPath, path.Base(transfer.job.remoteURL.Path))
			}
			// Determine write destination - use temporary file unless inPlace is true
			// Special case: os.DevNull should always use inPlace mode (no temp files)
			writeDestination = localPath
			if !transfer.job.inPlace && localPath != os.DevNull {
				// Use rsync-style temporary naming: .filename.XXXXXX (random suffix)
				writeDestination = generateTempPath(localPath)
			}
			// Ensure temporary file is cleaned up if we exit early (errors, panics, etc.)
			if !transfer.job.inPlace && writeDestination != localPath {
				defer func() {
					// Only clean up if the temporary file still exists and wasn't renamed
					if _, statErr := os.Stat(writeDestination); statErr == nil {
						if removeErr := os.Remove(writeDestination); removeErr != nil {
							log.Warningln("Failed to remove temporary file:", removeErr)
						}
					}
				}()
			}
			// If the destination is something strange, like a block device, then the OpenFile below
			// will create the appropriate error message
			if fp, err = os.OpenFile(writeDestination, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
				fileWriter = fp
				defer func() {
					if fp != nil {
						fp.Close()
					}
				}()
			} else {
				return
			}
		}
	} else { // Prestage case
		// Check if we should use the Pelican prestage API
		// We'll try the API for the first attempt (if supported), then fall back to the traditional method
		if len(transfer.attempts) > 0 {
			firstAttempt := transfer.attempts[0]
			cacheHost := firstAttempt.Url.Host

			// Check if this cache supports the prestage API
			supportsAPI := false
			if transfer.engine != nil {
				// First check with read lock
				transfer.engine.prestageAPIMutex.RLock()
				supported, checked := transfer.engine.prestageAPISupport[cacheHost]
				transfer.engine.prestageAPIMutex.RUnlock()

				if !checked {
					// Acquire write lock to perform the check
					transfer.engine.prestageAPIMutex.Lock()
					// Double-check in case another thread already did the check while we were waiting
					supported, checked = transfer.engine.prestageAPISupport[cacheHost]
					if !checked {
						// We're the first thread to check, perform the API support test
						supportsAPI = checkPrestageAPISupport(transfer.ctx, firstAttempt.Url, transfer.token)
						transfer.engine.prestageAPISupport[cacheHost] = supportsAPI
					} else {
						supportsAPI = supported
					}
					transfer.engine.prestageAPIMutex.Unlock()
				} else {
					supportsAPI = supported
				}
			}

			if supportsAPI {
				// Use the Pelican prestage API
				log.Debugln("Using Pelican prestage API for", transfer.remoteURL.Path, "at", cacheHost)
				transferResults = newTransferResults(transfer.job)
				transferStartTime := time.Now()

				bytesTransferred, err := invokePrestageAPI(transfer.ctx, firstAttempt.Url, transfer.remoteURL.Path, transfer.token, transfer.callback)

				endTime := time.Now()
				attempt := TransferResult{
					CacheAge:          -1,
					Number:            0,
					Endpoint:          cacheHost,
					TransferEndTime:   endTime,
					TransferTime:      endTime.Sub(transferStartTime),
					TransferFileBytes: bytesTransferred,
				}

				if err != nil {
					log.Debugln("Prestage API failed:", err)
					attempt.Error = newTransferAttemptError(cacheHost, "", false, false, err)
					transferResults.Error = err
				} else {
					transferResults.TransferredBytes = bytesTransferred
				}

				transferResults.Attempts = append(transferResults.Attempts, attempt)
				transferResults.TransferStartTime = transferStartTime

				// If the API succeeded, return early
				if err == nil {
					return transferResults, nil
				}

				// If API failed and we're forcing API usage, return the error
				if transfer.job != nil && transfer.job.forcePrestageAPI {
					return transferResults, errors.Wrap(err, "prestage API required but failed")
				}

				// If API failed, fall through to traditional method
				log.Debugln("Falling back to traditional prestage method")
			} else if transfer.job != nil && transfer.job.forcePrestageAPI {
				// API not supported but forced - return error immediately
				transferResults = newTransferResults(transfer.job)
				transferResults.Error = errors.Errorf("cache %s does not support the Pelican prestage API, but API usage is required", cacheHost)
				return transferResults, transferResults.Error
			}
		}

		// Traditional prestage: download to /dev/null
		localPath = os.DevNull
		writeDestination = os.DevNull
		fileWriter = io.Discard
	}

	// Close the custom writer at the end if provided
	if fileCloser != nil {
		defer func() {
			if closeErr := fileCloser.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}()
	}

	fileWriter = io.MultiWriter(fileWriter, hashesWriter)

	var size int64 = -1
	attempts := transfer.attempts
	if transfer.job != nil && transfer.job.ctx != nil {
		size, attempts = sortAttempts(transfer.job.ctx, transfer.remoteURL.Path, transfer.attempts, transfer.token)
	}

	// Create a new transferResults if we don't already have one
	// (prestage attempt may have created it previously)
	if transferResults.job == nil {
		transferResults = newTransferResults(transfer.job)
	}
	xferErrors := NewTransferErrors()
	success := false
	// transferStartTime is the start time of the last transfer attempt
	// we create a var here and update it in the loop
	var transferStartTime time.Time
	transferUrls := make([]*url.URL, len(attempts))
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
		transferEndpoint.Url = &transferEndpointUrl
		if transferEndpointUrl.Scheme == "unix" {
			transferEndpointUrl.Path = transfer.remoteURL.Path
		}
		transferUrls[idx] = transferEndpoint.Url
		fields := log.Fields{
			"url": transferEndpoint.Url.String(),
			"job": transfer.job.ID(),
		}
		ctx := context.WithValue(transfer.ctx, logFields("fields"), fields)
		transferStartTime = time.Now() // Update start time for this attempt
		tokenContents := ""
		if transfer.token != nil {
			tokenContents, _ = transfer.token.Get()
		}
		attemptDownloaded, timeToFirstByte, cacheAge, serverVersion, err := downloadHTTP(
			ctx, transfer.engine, transfer.callback, transferEndpoint, writeDestination, fileWriter, downloaded, size, tokenContents, transfer.project,
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
			proxyStr, _ := os.LookupEnv("http_proxy")
			if !transferEndpoint.Proxy {
				proxyStr = ""
			}
			serviceStr := attempt.Endpoint
			if transferEndpointUrl.Scheme == "unix" {
				serviceStr = "local-cache"
			}
			wrappedErr, isProxyErr, modifiedProxyStr := wrapDownloadError(err, transferEndpoint.Url.String(), tokenContents)
			if isProxyErr {
				proxyStr += modifiedProxyStr
			}
			attempt.Error = newTransferAttemptError(serviceStr, proxyStr, isProxyErr, false, wrappedErr)
			xferErrors.AddPastError(attempt.Error, endTime)
		}
		transferResults.Attempts = append(transferResults.Attempts, attempt)

		if err == nil { // Success
			log.WithFields(fields).Debugln("Downloaded bytes:", downloaded)
			success = true
			break
		} else if size > 0 && downloaded == size {
			// We have downloaded all the data but we still have an error.  If we retry again,
			// we will read past the end of the file and generate yet another error.  So, break
			// and cause a permanent failure.
			// In the future, we can consider deleting the file and trying again.
			break
		}
	}

	transferResults.TransferStartTime = transferStartTime
	transferResults.TransferredBytes = downloaded
	if success {
		// Clear any previous errors (e.g., from failed prestage attempts)
		transferResults.Error = nil

		// Fetch checksum of the downloaded file, compare it to the calculated.
		transferUrlCnt := len(transferUrls)
		gotChecksum := false
		// Iterate through the various sources to fetch the checksums, starting with the successful one.
		for idx := 0; idx < transferUrlCnt; idx++ {
			url := transferUrls[transferUrlCnt-idx-1]
			if url == nil {
				continue
			}
			fields := log.Fields{
				"url": url.String(),
				"job": transfer.job.ID(),
			}
			ctx := context.WithValue(transfer.ctx, logFields("fields"), fields)
			tokenContents := ""
			if transfer.token != nil {
				tokenContents, _ = transfer.token.Get()
			}
			if checksums, err := fetchChecksum(ctx, transfer.requestedChecksums, url, tokenContents, transfer.project); err == nil {
				transferResults.ServerChecksums = checksums
				gotChecksum = true
			}
		}
		if !gotChecksum && transfer.requireChecksum {
			transferResults.Error = errors.New("checksum is required but no endpoints were able to provide it")
		}

		// Compare the checksum values sent by the server versus the computed local values
		checksumHashes := transfer.requestedChecksums
		if len(checksumHashes) == 0 {
			// Added to make sure the list of checksum types are consistent with the logic
			// when we created the hashes []io.Writer previously.
			checksumHashes = []ChecksumType{AlgDefault}
		}
		fields := log.Fields{
			"url": transfer.remoteURL.String(),
			"job": transfer.job.ID(),
		}
		successCtr := 0
		transferResults.ClientChecksums = make([]ChecksumInfo, 0, len(checksumHashes))
		for idx, checksum := range checksumHashes {
			computedValue := hashes[idx].(hash.Hash).Sum(nil)
			transferResults.ClientChecksums = append(transferResults.ClientChecksums, ChecksumInfo{
				Algorithm: checksum,
				Value:     computedValue,
			})
			found := false
			for _, checksumInfo := range transferResults.ServerChecksums {
				if checksumInfo.Algorithm == checksum {
					found = true
					if !bytes.Equal(checksumInfo.Value, computedValue) {
						mismatchErr := &ChecksumMismatchError{
							Info: ChecksumInfo{
								Algorithm: checksum,
								Value:     computedValue,
							},
							ServerValue: checksumInfo.Value,
						}
						// Wrap ChecksumMismatchError as Transfer.ChecksumMismatch (post-transfer validation failure)
						transferResults.Error = error_codes.NewTransfer_ChecksumMismatchError(mismatchErr)
						log.WithFields(fields).Errorln(transferResults.Error)
						break
					} else {
						successCtr++
						log.WithFields(fields).Debugf("Checksum %s matches: %s",
							HttpDigestFromChecksum(checksumInfo.Algorithm),
							checksumValueToHttpDigest(checksumInfo.Algorithm, checksumInfo.Value),
						)
					}
					break
				}
			}
			if !found {
				log.WithFields(fields).Debugf("Client requested checksum %s but server did not provide it",
					HttpDigestFromChecksum(checksum),
				)
			}
		}
		// Can happen if all the checksum values we received are not known checksum algorithms
		// we computed (the server can ignore our requested checksums and send its preferred ones)
		if successCtr == 0 && transfer.requireChecksum && transferResults.Error == nil {
			if len(transfer.requestedChecksums) == 0 {
				log.WithFields(fields).Errorln(
					"Client requires checksum to succeed and it was not provided by server; client computed crc32c value is",
					hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				)
			} else {
				log.WithFields(fields).Errorln(
					"Client requires checksum to succeed and it was not provided by server; client computed",
					HttpDigestFromChecksum(transfer.requestedChecksums[0]), "value as",
					checksumValueToHttpDigest(transfer.requestedChecksums[0], hashes[0].(hash.Hash).Sum(nil)),
				)
			}
			transferResults.Error = ErrServerChecksumMissing
			// Otherwise, it's not an error so we should log what we did
		} else if successCtr == 0 && len(transferResults.ServerChecksums) == 0 && transferResults.Error == nil {
			log.WithFields(fields).Debugln(
				"Client computed crc32c value is", hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				"(server did not provide any checksum values to compare)",
			)
		} else if successCtr == 0 && transferResults.Error == nil {
			for _, checksumInfo := range transferResults.ServerChecksums {
				log.WithFields(fields).Debugf(
					"Server provided checksum not requested by client (cannot compare to local) %s=%x",
					HttpDigestFromChecksum(checksumInfo.Algorithm),
					checksumValueToHttpDigest(checksumInfo.Algorithm, checksumInfo.Value),
				)
			}
			if len(transfer.requestedChecksums) == 0 {
				log.WithFields(fields).Debugln(
					"Checksum algorithms provided by server were not the requested crc32c; client-computed crc32c value is",
					hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				)
			} else {
				log.WithFields(fields).Debugln(
					"Checksum algorithms provided by server were not the requested ones; client computed",
					HttpDigestFromChecksum(transfer.requestedChecksums[0]), "value as",
					checksumValueToHttpDigest(transfer.requestedChecksums[0], hashes[0].(hash.Hash).Sum(nil)),
				)
			}
		}
	} else {
		transferResults.Error = xferErrors
	}

	// Atomically rename temporary file to final destination on successful download
	if success && !transfer.job.inPlace && writeDestination != "" && writeDestination != localPath && transfer.packOption == "" {
		// On Windows, we must close the file before renaming it
		// On Unix, this is unnecessary but harmless
		if fp != nil {
			if closeErr := fp.Close(); closeErr != nil {
				transferResults.Error = errors.Wrap(closeErr, "failed to close temporary file before rename")
				log.Warningln("Failed to close temporary file:", closeErr)
				return
			}
			fp = nil // Prevent deferred close from closing again
		}
		if renameErr := os.Rename(writeDestination, localPath); renameErr != nil {
			transferResults.Error = errors.Wrap(renameErr, "failed to rename temporary file to final destination")
			log.Warningln("Failed to rename temporary file:", renameErr)
			// Since rename failed, the deferred cleanup will remove the temp file
			return
		}
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

// Fetch the checksum of a remote object
//
// The checksum is fetched via a HEAD request to the remote object server using RFC 3230 with the `Want-Digest` header.
// Note the server is free to ignore the requested checksums and return whatever it wants (including no checksum at all
// or even an error).  Hence, never assume the resulting checksum info is in the same order as the requested checksums
// in `types`.
//
// It is permissible for `types` to be an empty list; in that case, the default checksum type (crc32c) will be requested.
func fetchChecksum(ctx context.Context, types []ChecksumType, url *url.URL, token string, project string) (result []ChecksumInfo, err error) {
	fields, ok := ctx.Value(logFields("fields")).(log.Fields)
	if !ok {
		fields = log.Fields{}
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		checksumTypes := ""
		for _, cksum := range types {
			if checksumTypes != "" {
				checksumTypes += ", "
			}
			checksumTypes += HttpDigestFromChecksum(cksum)
		}
		if checksumTypes == "" {
			log.WithFields(fields).Debugln(
				"Fetching checksum for", url.String(),
				"no checksum types explicitly requested; using default of crc32c",
			)
		} else {
			log.WithFields(fields).Debugln("Fetching checksum for", url.String(), "for checksum types", checksumTypes)
		}
	}
	var request *http.Request
	if request, err = http.NewRequestWithContext(ctx, "HEAD", url.String(), nil); err != nil {
		return
	}
	// Set the authorization header as well as other headers
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("User-Agent", getUserAgent(project))
	if val, found := searchJobAd(attrJobId); found {
		request.Header.Set("X-Pelican-JobId", val)
	}
	if len(types) == 0 {
		request.Header.Set("Want-Digest", HttpDigestFromChecksum(AlgDefault))
	} else {
		multiple := false
		val := ""
		for _, cksum := range types {
			if multiple {
				val += ","
			}
			val += HttpDigestFromChecksum(cksum)
			multiple = true
		}
		request.Header.Set("Want-Digest", val)
	}
	client := config.GetClient()
	response, err := client.Do(request)
	if err != nil {
		return
	}
	// Always ignore any body coming back from a HEAD
	if response.Body != nil {
		response.Body.Close()
	}
	if response.StatusCode != 200 {
		log.Debugf("Failed to fetch checksum from %s: %s", url.String(), response.Status)
		sce := StatusCodeError(response.StatusCode)
		err = &sce
		return
	}
	ctr := 0
	var val string
	for _, val = range response.Header.Values("Digest") {
		for _, entry := range strings.Split(val, ",") {
			ctr++
			info := strings.SplitN(entry, "=", 2)
			if len(info) != 2 {
				continue
			}
			log.WithFields(fields).Debugf("Server reported object has checksum %s=%s", info[0], info[1])
			checksumInfo := ChecksumInfo{}
			if checksumInfo.Algorithm = ChecksumFromHttpDigest(info[0]); checksumInfo.Algorithm == AlgUnknown {
				log.WithFields(fields).Warningln("Unknown checksum algorithm:", info[0])
				continue
			}
			val := make([]byte, 32)
			switch info[0] {
			case "crc32c":
				// XRootD has a bug where crc32c is base64 encoded instead (per the spec)
				// hex encoded.  Accept this case.  We've reported this as a bug so ideally
				// future versions use hex instead.  Note: 0x3d is the = character.
				// See: https://github.com/xrootd/xrootd/issues/2456
				if len(info[1]) == 8 && info[1][6] == 0x3d && info[1][7] == 0x3d {
					decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(info[1])))
					if _, err := decoder.Read(val); err == nil {
						checksumInfo.Value = val[:4]
						break
					} else {
						log.WithFields(fields).Errorf("Failed to parse base64-encoded checksum value (%s): %s", info[1], err)
					}
				}
				fallthrough
			case "crc32":
				// Parse crc32 and crc32c as hexadecimal values.  Per the IANA registry
				// (https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml), these
				// are hex-encoded and should accept leading 0's.  Once parsed, store the
				// corresponding bytes in network order (big-endian) in our byte array.
				if intVal, err := strconv.ParseInt(info[1], 16, 64); err == nil {
					val[0] = byte((intVal >> 24) & 0xff)
					val[1] = byte((intVal >> 16) & 0xff)
					val[2] = byte((intVal >> 8) & 0xff)
					val[3] = byte(intVal & 0xff)
					checksumInfo.Value = val[:4]
				} else {
					log.WithFields(fields).Errorf("Failed to parse %s checksum value (%s): %s", info[0], info[1], err)
					continue
				}
			case "md5":
				fallthrough
			case "sha":
				decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(info[1])))
				if count, err := decoder.Read(val); err != nil {
					log.WithFields(fields).Errorf("Failed to parse %s checksum value (%s): %s", info[0], info[1], err)
					continue
				} else {
					val = val[:count]
				}
				checksumInfo.Value = val
			default:
				log.WithFields(fields).Warningf("Unknown checksum algorithm: %s", info[0])
				continue
			}
			result = append(result, checksumInfo)
		}
	}
	if ctr == 0 {
		log.WithFields(fields).Debugln("Server returned no checksum information")
	}
	return
}

// Verify that a file on disk matches the expected size. We ignore directories
// and generic stat failures unless the file doesn't exist.
func verifyFileSize(dest string, expectedSize int64, fields log.Fields) error {
	if dest == os.DevNull || dest == "" {
		log.WithFields(fields).Debugf("Skipping size check because destination is (%s)", os.DevNull)
		return nil
	}

	fi, err := os.Stat(dest)
	if err != nil { // Don't treat stat failure as fatal unless it indicates the file doesn't exist
		if os.IsNotExist(err) {
			return errors.Errorf("file does not exist: %s", dest)
		}

		log.WithFields(fields).Debugf("Error checking size of %s on disk: %v", dest, err)
		return nil
	}

	if fi.IsDir() {
		log.WithFields(fields).Debugf("Skipping size check for directory: %s", dest)
		return nil
	}

	sizeOnDisk := fi.Size()
	if sizeOnDisk != expectedSize {
		return errors.Errorf("file size on disk %db does not match expected size %db", sizeOnDisk, expectedSize)
	}

	return nil
}

// Download a single object from a single HTTP server with no retries.
//
// The following information is required:
//   - ctx: the context to use for the request and cancellation
//   - te: the transfer engine to use for the request.  downloadHttp provides the transfer engine with information
//     about overall transfer speed which is then used to report engine-wide averages.
//   - callback: periodically invoked with progress information about the transfer.
//   - transfer: contains the URL used for downloading the object.
//   - dest: the destination file to write the object to.
//   - writer: An io.Writer object where the downloaded bytes will be written to.
//   - bytesSoFar: the number of bytes already downloaded prior to invocation.  This is used to set the Range header for the subsequent request.
//   - totalSize: the expected size of the object.  If this is -1, the size is unknown.
//   - token: the token to use for authoriation.
//   - project: the project name to be used in the header identifying the transfer to the server.
//   - hashes: the list of hashes to be used for checksum verification.
//
// Returns the downloaded size, time to 1st byte downloaded, serverVersion and an error if there is one
func downloadHTTP(ctx context.Context, te *TransferEngine, callback TransferCallbackFunc, transfer transferAttemptDetails, dest string, writer io.Writer, bytesSoFar int64, totalSize int64, token string, project string) (downloaded int64, timeToFirstByte time.Duration, cacheAge time.Duration, serverVersion string, err error) {
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

	// Ensure we always invoke the callback at the start and the deferred
	// function will invoke it at the end.
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
			callback(dest, downloaded+bytesSoFar, finalSize, true)
		}
		if te != nil {
			te.ewmaCtr.Add(int64(time.Since(lastUpdate)))
		}
	}()

	// Create the client, request, and context
	var client *http.Client
	if transfer.Proxy {
		client = config.GetClient()
	} else {
		client = config.GetClientNoProxy()
	}
	transferUrl := *transfer.Url
	if transfer.Url.Scheme == "unix" {
		transport := config.GetTransport().Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", transfer.UnixSocket)
		}
		transferUrl.Scheme = "http"
		// The host is ignored since we override the dial function; however, I find it useful
		// in debug messages to see that this went to the local cache.
		transferUrl.Host = "localhost"
		// Note we aren't reusing a common client from the config module; this is because
		// the transport is actually reading from a Unix socket and is rather unique.
		client = &http.Client{Transport: transport}
	}
	headerTimeout := config.GetTransport().ResponseHeaderTimeout
	if headerTimeout > time.Second {
		headerTimeout -= 500 * time.Millisecond
	} else {
		headerTimeout /= 2
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.WithFields(fields).Debugln("Attempting to download from:", transferUrl.Host)
	log.WithFields(fields).Debugln("Transfer URL String:", transferUrl.String())

	// Create the request
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, transferUrl.String(), nil); err != nil {
		return
	}

	var unpacker *autoUnpacker
	defer func() {
		if unpacker != nil {
			unpacker.Close()
			if unpackerErr := unpacker.Error(); unpackerErr != nil {
				log.WithFields(fields).Errorln("Failed to close unpacker:", err)
				return
			}
		}
	}()

	rateLimit := param.Client_MaximumDownloadSpeed.GetInt()
	if rateLimit > 0 {
		writer = &rateLimitWriter{
			writer:      writer,
			rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), 64*1024),
			ctx:         ctx,
		}
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Set the headers
	userAgent := getUserAgent(project)
	jobId, found := searchJobAd(attrJobId)
	if found {
		req.Header.Set("X-Pelican-JobId", jobId)
	}
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("X-Pelican-Timeout", headerTimeout.Round(time.Millisecond).String())
	if bytesSoFar > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", bytesSoFar))
		log.Debugln("Resuming transfer starting at offset", bytesSoFar)
	}
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", userAgent)

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
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		var cam syscall.Errno
		if errors.As(err, &cam) && cam == syscall.ENOMEM {
			// ENOMEM is error from os for unable to allocate memory
			err = &allocateMemoryError{Err: err}
		} else if isTLSCertificateValidationError(err) {
			// TLS certificate validation error - wrap as SpecificationError (configuration issue, not retryable)
			err = error_codes.NewSpecificationError(err)
		} else if isContextDeadlineError(err) || isDNSError(err) || (isTLSError(err) && !isTLSCertificateValidationError(err)) || isDialError(err) {
			// Connection setup errors (timeout, DNS, TLS handshake, dial) - wrap as ConnectionSetupError (retryable)
			err = &ConnectionSetupError{Err: err}
		}
		// Note: Any other errors from client.Do that don't match the above conditions will remain unwrapped for now.
		// In practice, client.Do primarily returns connection-related errors, so most should be caught above.
		// TODO: Wrap any other errors from client.Do with appropriate PelicanError types.
		log.WithFields(fields).Errorln("Failed to download:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		log.WithFields(fields).Debugln("Got failure status code:", resp.StatusCode)
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.WithFields(fields).Debugln("Failed to read response body for error:", readErr)
		}
		bodyStr := string(bodyBytes)
		log.WithFields(fields).Debugln("Error response body:", bodyStr)
		serverVersion = resp.Header.Get("Server")
		if resp.StatusCode == http.StatusForbidden {
			// We will update the error message in the caller
			return 0, 0, -1, serverVersion, error_codes.NewAuthorizationError(&PermissionDeniedError{})
		}
		sce := StatusCodeError(resp.StatusCode)
		// Wrap StatusCodeError with appropriate PelicanError based on status code
		wrappedErr := wrapStatusCodeError(&sce)
		httpErr := &HttpErrResp{resp.StatusCode, fmt.Sprintf("request failed (HTTP status %d): %s",
			resp.StatusCode, strings.TrimSpace(bodyStr)), wrappedErr}
		return 0, 0, -1, serverVersion, httpErr
	}

	serverVersion = resp.Header.Get("Server")

	if ageStr := resp.Header.Get("Age"); ageStr != "" {
		if ageSec, err := strconv.Atoi(ageStr); err == nil {
			cacheAge = time.Duration(ageSec) * time.Second
		} else {
			log.WithFields(fields).Debugf("Server at %s gave unparsable Age header (%s) in response: %s", transfer.Url.Host, ageStr, err.Error())
		}
	}
	if cacheAge == 0 {
		log.WithFields(fields).Debugln("Server at", transfer.Url.Host, "had a cache miss")
	} else if cacheAge > 0 {
		log.WithFields(fields).Debugln("Server at", transfer.Url.Host, "had a cache hit with data age", cacheAge.String())
	}

	// Size of the download
	totalSize = resp.ContentLength
	if bytesSoFar > 0 && resp.StatusCode == http.StatusPartialContent {
		// In this case, totalSize is the size of the response, not the object
		if totalSize < 0 {
			rangeStr := resp.Header.Get("Content-Range")
			if rangeStr != "" {
				parts := strings.SplitN(rangeStr, "/", 2)
				if len(parts) == 2 {
					if size, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						totalSize = size
					}
				} else {
					log.WithFields(fields).Debugln("Error parsing Content-Range header:", rangeStr)
				}
			} else {
				log.WithFields(fields).Debugln("Content-Range header is missing; unable to determine size of object")
			}
		} else {
			totalSize += bytesSoFar
		}
	}
	// Worst case: do a separate HEAD request to get the size
	if totalSize <= 0 && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent) {
		// If the size is unknown, we can try to get it via a HEAD request
		headRequest, _ := http.NewRequest(http.MethodHead, transferUrl.String(), nil)
		if token != "" {
			headRequest.Header.Set("Authorization", "Bearer "+token)
		}
		headRequest.Header.Set("User-Agent", userAgent)
		if jobId != "" {
			headRequest.Header.Set("X-Pelican-JobId", jobId)
		}
		var headResponse *http.Response
		headResponse, err = client.Do(headRequest)
		if err != nil {
			log.WithFields(fields).Errorln("Could not successfully get response for HEAD request")
			err = errors.Wrap(err, "Could not determine the size of the remote object")
			return
		}
		if _, err := io.Copy(io.Discard, headResponse.Body); err != nil {
			log.Warningln("Failed to read out response body:", err)
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
		callback(dest, bytesSoFar, totalSize, false)
	}

	stoppedTransferTimeout := compatToDuration(param.Client_StoppedTransferTimeout.GetDuration(), "Client.StoppedTransferTimeout")
	slowTransferRampupTime := compatToDuration(param.Client_SlowTransferRampupTime.GetDuration(), "Client.SlowTransferRampupTime")
	slowTransferWindow := compatToDuration(param.Client_SlowTransferWindow.GetDuration(), "Client.SlowTransferWindow")
	progressInterval := param.Logging_Client_ProgressInterval.GetDuration()
	stoppedTransferDebugLine.Do(func() {
		log.WithFields(fields).Debugf("Configuration values for stopped transfer timeout: %s; slow transfer ramp-up: %s; slow transfer look-back window: %s",
			stoppedTransferTimeout.String(), slowTransferRampupTime.String(), slowTransferWindow.String())
	})
	startBelowLimit := time.Time{}
	var noProgressStartTime time.Time
	var lastBytesComplete int64

	// Run the GET request, reading from the response body, in a separate goroutine.
	// The main go routine will wait for the download to finish and send out progress
	// updates.

	// This channel is used to signal the main goroutine that the download is done
	// In a deferred function, we wait on the done channel to get the signal that the download is done
	done := make(chan error, 1)
	pw := &progressWriter{
		writer: writer,
	}

	go func() {
		// Copy the response body to the progress writer
		// When we are done, we will send an error (could be nil) to the done channel
		// and then close the done channel
		_, err := io.Copy(pw, resp.Body)
		done <- err // send the error
		close(done) // signal that the download is done
	}()
	defer pw.Close()

	// This defer is used to clean up the goroutine that is copying the response body to the progress writer
	defer func() {
		// Ensure the context is cancelled to stop the io.Copy if it's still running
		cancel()
		// Wait for the copy goroutine to finish
		// We can ignore the error from the done channel as the final check on `downloaded`
		// bytes vs totalSize will catch any read errors
		<-done

		// Now that the goroutine is done, get the final byte count
		finalDownloaded := pw.BytesComplete()
		downloaded = finalDownloaded

		// If the function is returning an error that contains byte counts, update it
		var ste *SlowTransferError
		var stpe *StoppedTransferError
		if errors.As(err, &ste) {
			ste.BytesTransferred = finalDownloaded
		} else if errors.As(err, &stpe) {
			stpe.BytesTransferred = finalDownloaded
		}
	}()

	// Loop of the download
	lastProgressUpdate := time.Now()
Loop:
	for {
		select {
		case <-progressTicker.C:
			downloaded = pw.BytesComplete()
			currentTime := time.Now()
			if te != nil {
				te.ewmaCtr.Add(int64(currentTime.Sub(lastUpdate)))
			}
			lastUpdate = currentTime
			if callback != nil {
				callback(dest, downloaded+bytesSoFar, totalSize, false)
			}

		case <-t.C:
			// Check that progress is being made and that it is not too slow
			currentDownloaded := pw.BytesComplete()
			if currentDownloaded == lastBytesComplete {
				if noProgressStartTime.IsZero() {
					noProgressStartTime = time.Now()
				} else if time.Since(noProgressStartTime) > stoppedTransferTimeout {
					downloaded = currentDownloaded
					err = &StoppedTransferError{
						BytesTransferred: downloaded,
						StoppedTime:      time.Since(noProgressStartTime),
						CacheHit:         cacheAge > 0,
					}
					err = error_codes.NewTransfer_StoppedTransferError(err)
					log.WithFields(fields).Errorln(err.Error())
					return
				}
			} else {
				noProgressStartTime = time.Time{}
			}
			lastBytesComplete = currentDownloaded

			// Check if we are downloading fast enough
			limit := int64(downloadLimit)
			var concurrency float64 = 1
			if te != nil {
				concurrency = float64(te.ewmaVal.Load()) / float64(ewmaInterval)
			}
			if concurrency > 1 {
				limit = int64(float64(limit) / concurrency)
			}
			transferRate := pw.BytesPerSecond()
			if progressInterval > 0 && time.Since(lastProgressUpdate) > progressInterval {
				lastProgressUpdate = time.Now()
				log.Infof("Download of %s has %d bytes complete out of %d; recent transfer rate is %s/s", transferUrl.String(), downloaded, totalSize, ByteCountSI(transferRate))
			}

			if transferRate < limit {
				// Give the download `slowTransferRampupTime` (default 120) seconds to start
				if time.Since(downloadStart) < slowTransferRampupTime {
					continue
				} else if startBelowLimit.IsZero() {
					warning := []byte("Warning! Downloading too slow...\n")
					status, err := getProgressContainer().Write(warning)
					if err != nil {
						log.WithFields(fields).Errorln("Problem displaying slow message", err, status)
						continue
					}
					log.Warningln("Transfer of", transferUrl.String(), "is below threshold; attempt will error out if it remains below threshold for", slowTransferWindow)
					startBelowLimit = time.Now()
					continue
				} else if time.Since(startBelowLimit) < slowTransferWindow {
					// If the download is below the threshold for less than `SlowTransferWindow` (default 30) seconds, continue
					continue
				}

				if concurrency > 1 {
					log.WithFields(fields).Errorf("Cancelling download attempt of %s: Download speed of %s/s is below the computed limit of %s/s (configured limit of %s/s divided by estimated %.1f concurrent transfers on average)", transferUrl.String(), ByteCountSI(transferRate), ByteCountSI(int64(limit)), ByteCountSI(int64(downloadLimit)), concurrency)
				} else {
					log.WithFields(fields).Errorf("Cancelling download attempt of %s: Download speed of %s/s is below the limit of %s/s", transferUrl.String(), ByteCountSI(transferRate), ByteCountSI(int64(downloadLimit)))
				}

				err = &SlowTransferError{
					BytesTransferred: pw.BytesComplete(),
					BytesPerSecond:   transferRate,
					Duration:         time.Since(downloadStart),
					BytesTotal:       totalSize,
					CacheAge:         cacheAge,
				}
				err = error_codes.NewTransfer_SlowTransferError(err)
				return

			} else {
				// The download is fast enough, reset the startBelowLimit
				startBelowLimit = time.Time{}
			}

		case err = <-done:
			downloaded = pw.BytesComplete()
			break Loop

		case <-ctx.Done():
			err = ctx.Err()
			break Loop
		}
	}
	if err != nil {
		// Connection errors
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNABORTED) {
			err = &ConnectionSetupError{URL: req.URL.String(), Err: err}
			return
		}
		// Add a check for InvalidByteInChunkLengthError
		if strings.Contains(err.Error(), "invalid byte in chunk length") {
			err = &InvalidByteInChunkLengthError{Err: err}
		}
		log.WithFields(fields).Debugln("Got error from HTTP download", err)
		return
	} else {
		// Check the trailers for any error information
		trailer := resp.Trailer
		if errorStatus := trailer.Get("X-Transfer-Status"); errorStatus != "" {
			statusCode, statusText := parseTransferStatus(errorStatus)
			if statusCode != http.StatusOK {
				log.WithFields(fields).Debugln("Got error from file transfer:", statusText)
				if strings.Contains(statusText, "sTREAM ioctl timeout") {
					err = CacheTimedOutReadingFromOrigin
					err = error_codes.NewTransfer_TimedOutError(err)
				} else {
					baseErr := errors.New(statusText)
					if strings.Contains(statusText, "unexpected EOF") {
						baseErr = &UnexpectedEOFError{Err: baseErr}
					}
					err = error_codes.NewTransferError(fmt.Errorf("download error after server response started: %w", baseErr))
					return
				}
				return
			}
		}
	}
	// Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
	// prior attempt.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		log.WithFields(fields).Debugln("Got failure status code:", resp.StatusCode)
		if resp.StatusCode == 403 {
			// We will update the error message in the caller
			return 0, 0, -1, serverVersion, error_codes.NewAuthorizationError(&PermissionDeniedError{})
		}
		var wrappedErr error
		if err == nil {
			sce := StatusCodeError(resp.StatusCode)
			// Wrap StatusCodeError with appropriate PelicanError based on status code
			wrappedErr = wrapStatusCodeError(&sce)
		} else {
			// If err is already set, use it as-is (might be from trailer status)
			wrappedErr = err
		}
		httpErr := &HttpErrResp{resp.StatusCode, fmt.Sprintf("request failed (HTTP status %d)",
			resp.StatusCode), wrappedErr}
		return 0, 0, -1, serverVersion, httpErr
	}

	// By now, we think the download succeeded. If we know how large the file was supposed to
	// be based on the Content-Length header, we can check that a) the HTTP client witnessed
	// the correct number of bytes and b) the file on disk is the correct size. If totalSize is
	// <= 0, it indicates we don't know how large the transfer was supposed to be in the first
	// place.
	if totalSize > 0 {
		if bytesSoFar+downloaded != totalSize {
			log.WithFields(fields).Debugf("Download completed but received size %db does not match expected size %db", bytesSoFar+downloaded, totalSize)
			err = errors.Errorf("download completed but received size %db does not match expected size %db", bytesSoFar+downloaded, totalSize)
			return
		}

		// Second sanity check to verify the file size as it appears on disk.
		if err = verifyFileSize(dest, totalSize, fields); err != nil {
			err = errors.Wrapf(err, "failed to verify size of downloaded file (%s) on disk", dest)
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

// progressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type progressReader struct {
	reader io.ReadCloser
	sizer  Sizer
	closed chan bool
}

// Read implements the common read function for io.Reader
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	if cs, ok := pr.sizer.(*ConstantSizer); ok {
		cs.read.Add(int64(n))
	}
	return n, err
}

// Close implements the close function of io.Closer
func (pr *progressReader) Close() error {
	err := pr.reader.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

func (pr *progressReader) BytesComplete() int64 {
	return pr.sizer.BytesComplete()
}

func (pr *progressReader) Size() int64 {
	return pr.sizer.Size()
}

// Write to the underlying writer object, updating the progress
func (pw *progressWriter) Write(p []byte) (n int, err error) {
	if pw.closed.Load() {
		return 0, progressWriterClosed
	}
	if pw.firstByteTime.IsZero() && len(p) > 0 {
		pw.firstByteTime = time.Now()
	}
	now := time.Now()
	startupTime := now.Sub(pw.firstByteTime)
	startupTimeUS := startupTime.Microseconds()
	// Transfer is ramping up, less than 5 seconds total.  Take the average rate since start.
	if startupTime < 5*time.Second && startupTimeUS > 0 {
		pw.bytesPerSecond.Store(1000000 * pw.bytesWritten.Load() / startupTimeUS)
		pw.lastRateSample = now
	} else {
		elapsed := now.Sub(pw.lastRateSample)
		pw.lastRateSample = now
		elapsedUS := elapsed.Microseconds()
		if elapsedUS > 0 {
			oldBytesPerSecond := pw.bytesPerSecond.Load()
			alpha := math.Exp(-1 * float64(elapsed) / float64(10*time.Second))
			recentRate := 1000000 * int64(len(p)) / elapsedUS
			pw.bytesPerSecond.Store(int64(float64(oldBytesPerSecond)*alpha + float64(recentRate)*(1-alpha)))
		}
	}
	n, err = pw.writer.Write(p)
	pw.bytesWritten.Add(int64(n))
	return n, err
}

func (pw *progressWriter) BytesComplete() int64 {
	return pw.bytesWritten.Load()
}

func (pw *progressWriter) FirstByteTime() time.Time {
	return pw.firstByteTime
}

func (pw *progressWriter) Close() {
	pw.closed.Store(true)
}

func (pw *progressWriter) BytesPerSecond() int64 {
	return pw.bytesPerSecond.Load()
}

// Upload a single object to the origin
func uploadObject(transfer *transferFile) (transferResult TransferResults, err error) {
	log.Debugln("Uploading file to destination", transfer.remoteURL)
	xferErrors := NewTransferErrors()
	transferResult.job = transfer.job

	// In dry-run mode, log what would be uploaded and return success
	if transfer.job != nil && transfer.job.dryRun {
		// Print to stdout with structured format for easy parsing
		fmt.Printf("UPLOAD: %s -> %s\n", transfer.localPath, transfer.remoteURL.Path)
		// Return success for dry-run without performing any file operations
		return transferResult, nil
	}

	// Check if the remote object already exists using statHttp
	// If the job is recursive, we skip this check as the check is already performed in walkDirUpload
	// If the job is not recursive, we check if the object exists at the origin
	// Skip this check if Client.EnableOverwrites is enabled
	if transfer.remoteURL != nil && transfer.job != nil && transfer.job.syncLevel == SyncNone && !transfer.job.recursive && !param.Client_EnableOverwrites.GetBool() {
		remoteUrl, dirResp, token := transfer.job.remoteURL, transfer.job.dirResp, transfer.job.token
		_, statErr := statHttp(remoteUrl, dirResp, token)
		if statErr == nil {
			// Object exists, abort upload
			transferResult.Error = error_codes.NewSpecification_FileAlreadyExistsError(
				errors.New("remote object already exists, upload aborted"),
			)
			return transferResult, transferResult.Error
		} else if !errors.Is(statErr, ErrObjectNotFound) {
			// We encountered an unexpected error while checking for object existence.
			// Log a warning but proceed with the upload; the upload itself may still succeed.
			log.Warningln("Failed to check if object exists at the origin, proceeding with upload:", statErr)
		}
		// If statErr indicates the object was not found, proceed with upload
	}

	var sizer Sizer = &ConstantSizer{size: 0}
	var uploaded int64 = 0
	if transfer.callback != nil {
		transfer.callback(transfer.localPath, 0, sizer.Size(), false)
		defer func() {
			transfer.callback(transfer.localPath, uploaded, sizer.Size(), true)
		}()
	}

	// Create a checksum hash instance for each requested checksum.
	// Will all be joined into a single writer
	hashes := make([]io.Writer, 0, 1)
	for _, checksum := range transfer.requestedChecksums {
		switch checksum {
		case AlgCRC32:
			hashes = append(hashes, crc32.NewIEEE())
		case AlgCRC32C:
			hashes = append(hashes, crc32.New(crc32cTable))
		case AlgMD5:
			hashes = append(hashes, md5.New())
		case AlgSHA1:
			hashes = append(hashes, sha1.New())
		}
	}
	// If no checksums are requested, use crc32c by default
	if len(hashes) == 0 {
		hashes = append(hashes, crc32.New(crc32cTable))
	}
	hashesWriter := io.MultiWriter(hashes...)

	var attempt TransferResult
	var ioreader io.ReadCloser
	nonZeroSize := true
	pack := transfer.packOption
	fileSizeHint := int64(0)
	hasFileSize := false
	transferResult.Scheme = transfer.remoteURL.Scheme

	// If a reader was provided (used by PelicanFS writes), bypass filesystem stat/open.
	if transfer.reader != nil {
		ioreader = transfer.reader
		// Size is unknown; track bytes as they are read unless the reader self-reports.
		if sizedReader, ok := ioreader.(Sizer); ok {
			sizer = sizedReader
		} else {
			sizer = &ConstantSizer{size: 0}
		}
	} else {
		// Stat the file to get the size (for progress bar)
		fileInfo, statErr := os.Stat(transfer.localPath)
		if statErr != nil {
			log.Errorln("Error checking local file ", transfer.localPath, ":", statErr)
			if os.IsNotExist(statErr) {
				transferResult.Error = error_codes.NewParameter_FileNotFoundError(errors.Wrapf(statErr, "local file %q does not exist", transfer.localPath))
			} else if os.IsPermission(statErr) {
				transferResult.Error = error_codes.NewAuthorizationError(errors.Wrapf(statErr, "permission denied accessing local file %q", transfer.localPath))
			} else {
				transferResult.Error = error_codes.NewParameterError(errors.Wrapf(statErr, "failed to stat local file %q", transfer.localPath))
			}
			return transferResult, transferResult.Error
		}

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
				err := error_codes.NewParameterError(errors.New("the provided path '" + transfer.localPath + "' is a directory, but a file is expected"))
				transferResult.Error = err
				return transferResult, err
			}

			// Try opening the file to send
			file, openErr := os.Open(transfer.localPath)
			if openErr != nil {
				log.Errorln("Error opening local file:", openErr)
				if os.IsNotExist(openErr) {
					transferResult.Error = error_codes.NewParameter_FileNotFoundError(errors.Wrapf(openErr, "local file %q does not exist", transfer.localPath))
				} else if os.IsPermission(openErr) {
					transferResult.Error = error_codes.NewAuthorizationError(errors.Wrapf(openErr, "permission denied opening local file %q", transfer.localPath))
				} else {
					transferResult.Error = error_codes.NewParameterError(errors.Wrapf(openErr, "failed to open local file %q", transfer.localPath))
				}
				return transferResult, transferResult.Error
			}
			ioreader = file
			sizer = &ConstantSizer{size: fileInfo.Size()}
			fileSizeHint = fileInfo.Size()
			hasFileSize = true
			nonZeroSize = fileInfo.Size() > 0
		}
	}
	if transfer.callback != nil {
		transfer.callback(transfer.localPath, 0, sizer.Size(), false)
	}

	// Parse the writeback host as a URL
	writebackhostUrl := transfer.attempts[0].Url

	// Start from the director-provided URL but override the path/query with the
	// per-file destination so recursive uploads target each object, not just the
	// collection root. For POSIXv2 origins that include a base path, preserve the
	// prefix when constructing the final destination.
	destCopy := *writebackhostUrl
	if transfer.remoteURL != nil {
		destCopy.Path = computeUploadDestPath(transfer.remoteURL.Path, destCopy.Path)
		// Preserve query parameters from the director (for example, authz tokens) unless the
		// per-file URL explicitly provides its own query.
		destCopy.RawQuery = writebackhostUrl.RawQuery
		if transfer.remoteURL.RawQuery != "" {
			destCopy.RawQuery = transfer.remoteURL.RawQuery
		}
	}
	if destCopy.Scheme == "" {
		destCopy.Scheme = "https"
	}
	dest := &destCopy
	// Add the oss.asize query parameter for PUT requests
	query := dest.Query()
	query.Set("oss.asize", fmt.Sprintf("%d", sizer.Size()))
	dest.RawQuery = query.Encode()
	attempt.Endpoint = dest.Host
	// Create the wrapped reader and send it to the request
	closed := make(chan bool, 1)
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	reader := &progressReader{ioreader, sizer, closed}
	// This will write to the checksum hashes as we read from the file
	tee := io.TeeReader(reader, hashesWriter)
	putContext, cancel := context.WithCancel(transfer.ctx)
	transferStartTime := time.Now()
	defer cancel()
	log.Debugln("Full destination URL:", dest.String())
	var request *http.Request
	// For files that are 0 length, we need to send a PUT request with an nil body
	if nonZeroSize {
		request, err = http.NewRequestWithContext(putContext, http.MethodPut, dest.String(), tee)
	} else {
		request, err = http.NewRequestWithContext(putContext, http.MethodPut, dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		transferResult.Error = err
		return transferResult, err
	}

	// Hint upload size
	// Only do this for non-zero size files and not for pack uploads
	// Because with compressed files, we don't know the decompressed size
	if nonZeroSize && pack == "" && hasFileSize {
		query := request.URL.Query()
		query.Add("oss.asize", strconv.FormatInt(fileSizeHint, 10))
		request.URL.RawQuery = query.Encode()
	}

	// Set the authorization header as well as other headers
	var tokenContents string
	if transfer.token != nil {
		if tokenContents, err = transfer.token.Get(); tokenContents != "" && err == nil {
			request.Header.Set("Authorization", "Bearer "+tokenContents)
		}
	}
	request.Header.Set("User-Agent", getUserAgent(transfer.project))
	if result, found := searchJobAd(attrJobId); found {
		request.Header.Set("X-Pelican-JobId", result)
	}
	var lastKnownWritten int64
	uploadStart := time.Now()

	useProxy := transfer.attempts[0].Proxy

	go runPut(request, responseChan, errorChan, useProxy)
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
				lastError = error_codes.NewTransfer_StoppedTransferError(lastError)
				// No progress has been made in the last 1 second
				break Loop
			}

		case <-closed:
			// The file has been closed, we're done here
			log.Debugln("File closed")
		case response := <-responseChan:
			attempt.ServerVersion = response.Header.Get("Server")

			// Handle 403 specially when sync is enabled
			if response.StatusCode == http.StatusForbidden && transfer.job.syncLevel != SyncNone {
				// When syncing, a 403 on PUT typically means the file already exists
				// and the origin doesn't allow overwrites. This is expected behavior.
				// Track this for summary reporting
				transfer.job.skipped403.Lock()
				transfer.job.skipped403Objs = append(transfer.job.skipped403Objs, transfer.remoteURL.Path)
				transfer.job.skipped403.Unlock()

				log.Debugln("Skipping upload of", transfer.remoteURL.Path, "(403 Forbidden, object likely already exists)")
				// Don't set lastError - treat this as successful skip
				break Loop
			}

			// Note: Accept both 200 and 201 as success codes; the latter is the correct one, but
			// older versions of XRootD incorrectly use 200.
			if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
				log.Errorln("Got failure status code:", response.StatusCode)
				sce := StatusCodeError(response.StatusCode)
				// Wrap StatusCodeError with appropriate PelicanError based on status code
				wrappedErr := wrapStatusCodeError(&sce)
				lastError = &HttpErrResp{response.StatusCode, fmt.Sprintf("request failed (HTTP status %d)",
					response.StatusCode), wrappedErr}
				break Loop
			}
			break Loop

		case err := <-errorChan:
			log.Errorln("Unexpected error when performing upload:", err)
			var ope *net.OpError
			var ue *url.Error
			var cse *ConnectionSetupError
			// Check for proxy connection errors first (may be wrapped in url.Error)
			if errors.As(err, &ue) {
				innerErr := ue.Unwrap()
				if ope, ok := innerErr.(*net.OpError); ok && ope.Op == "proxyconnect" {
					// Wrap proxy connection error as Contact.ConnectionSetupError (code 3006, retryable)
					proxyErr := &ConnectionSetupError{URL: request.URL.String(), Err: err}
					err = error_codes.NewContact_ConnectionSetupError(proxyErr)
				} else if innerErr.Error() == "net/http: timeout awaiting response headers" {
					err = error_codes.NewTransfer_HeaderTimeoutError(&HeaderTimeoutError{})
				} else {
					// Restore original url.Error for further processing
					err = ue
				}
			} else if errors.As(err, &ope) && ope.Op == "proxyconnect" {
				// Direct proxy connection error (not wrapped in url.Error)
				proxyErr := &ConnectionSetupError{URL: request.URL.String(), Err: err}
				err = error_codes.NewContact_ConnectionSetupError(proxyErr)
			} else if errors.As(err, &cse) {
				// ConnectionSetupError already created in runPut - only check for special cases
				innerErr := cse.Unwrap()
				if isTLSCertificateValidationError(innerErr) {
					// TLS certificate validation error - wrap as SpecificationError (configuration issue, not retryable)
					err = error_codes.NewSpecificationError(err)
				} else if ue, ok := innerErr.(*url.Error); ok {
					httpErr := ue.Unwrap()
					if httpErr.Error() == "net/http: timeout awaiting response headers" {
						err = error_codes.NewTransfer_HeaderTimeoutError(&HeaderTimeoutError{})
					} else {
						// Wrap ConnectionSetupError even if it contains a url.Error (it's still a connection setup error)
						err = error_codes.NewContact_ConnectionSetupError(cse)
					}
				} else {
					// All other ConnectionSetupError cases - wrap as ConnectionSetupError (already identified as connection setup error)
					err = error_codes.NewContact_ConnectionSetupError(cse)
				}
			} else if isContextDeadlineError(err) || isDNSError(err) || (isTLSError(err) && !isTLSCertificateValidationError(err)) || isDialError(err) {
				// Connection setup errors (timeout, DNS, TLS handshake, dial) - wrap as ConnectionSetupError (retryable)
				cse := &ConnectionSetupError{URL: request.URL.String(), Err: err}
				err = error_codes.NewContact_ConnectionSetupError(cse)
			}
			if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
				// Wrap NetworkResetError as Contact.ConnectionReset (code 3005, retryable)
				err = error_codes.NewContact_ConnectionResetError(&NetworkResetError{})
			}
			lastError = err
			break Loop

		}
	}

	transferResult.TransferStartTime = transferStartTime
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
		// At this point, we have a successful upload.
		// We now need to fetch the checksums from the server and then test them against the ones we calculated.
		// If they match, we're good. If they don't, we need to return an error.

		// Fetch the checksums from the server
		result, err := fetchChecksum(putContext, transfer.requestedChecksums, dest, tokenContents, transfer.job.project)
		if err != nil {
			if transfer.requireChecksum {
				log.Errorln("Error fetching checksum:", err)
				transferResult.Error = errors.New("checksum is required but endpoint was not able to provide it")
				attempt.Error = err
			} else {
				log.Warnln("Checksum is not required, but endpoint was not able to provide it. Continuing without verification.")
			}
		} else {
			transferResult.ServerChecksums = result
		}

		checksumHashes := transfer.requestedChecksums
		if len(checksumHashes) == 0 {
			checksumHashes = []ChecksumType{AlgDefault}
		}
		fields := log.Fields{
			"url": transfer.remoteURL.String(),
			"job": transfer.job.ID(),
		}
		successCtr := 0
		transferResult.ClientChecksums = make([]ChecksumInfo, 0, len(checksumHashes))
		for idx, checksum := range checksumHashes {
			computedValue := hashes[idx].(hash.Hash).Sum(nil)
			transferResult.ClientChecksums = append(transferResult.ClientChecksums, ChecksumInfo{
				Algorithm: checksum,
				Value:     computedValue,
			})
			found := false
			for _, checksumInfo := range transferResult.ServerChecksums {
				if checksumInfo.Algorithm == checksum {
					found = true
					if !bytes.Equal(checksumInfo.Value, computedValue) {
						mismatchErr := &ChecksumMismatchError{
							Info: ChecksumInfo{
								Algorithm: checksum,
								Value:     computedValue,
							},
							ServerValue: checksumInfo.Value,
						}
						// Wrap ChecksumMismatchError as Transfer.ChecksumMismatch (post-transfer validation failure)
						transferResult.Error = error_codes.NewTransfer_ChecksumMismatchError(mismatchErr)
						log.WithFields(fields).Errorln(transferResult.Error)
						break
					} else {
						successCtr++
						log.WithFields(fields).Debugf("Checksum %s matches: %s",
							HttpDigestFromChecksum(checksumInfo.Algorithm),
							checksumValueToHttpDigest(checksumInfo.Algorithm, checksumInfo.Value),
						)
					}
					break
				}
			}
			if !found {
				log.WithFields(fields).Debugf("Client requested checksum %s but server did not provide it",
					HttpDigestFromChecksum(checksum))
			}
		}
		if successCtr == 0 && transfer.requireChecksum && transferResult.Error == nil {
			if len(transfer.requestedChecksums) == 0 {
				log.WithFields(fields).Errorln(
					"Client requires checksum to succeed and it was not provided by server; client computed crc32c value is",
					hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				)
			} else {
				log.WithFields(fields).Errorln(
					"Client requires checksum to succeed and it was not provided by server; client computed",
					HttpDigestFromChecksum(transfer.requestedChecksums[0]), "value as",
					checksumValueToHttpDigest(transfer.requestedChecksums[0], hashes[0].(hash.Hash).Sum(nil)),
				)
			}
			transferResult.Error = ErrServerChecksumMissing
		} else if successCtr == 0 && len(transferResult.ServerChecksums) == 0 && transferResult.Error == nil {
			log.WithFields(fields).Debugln(
				"Client computed crc32c value is", hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				"(server did not provide any checksum values to compare)",
			)
		} else if successCtr == 0 && transferResult.Error == nil {
			for _, checksumInfo := range transferResult.ServerChecksums {
				log.WithFields(fields).Debugf(
					"Server provided checksum not requested by client (cannot compare to local) %s=%x",
					HttpDigestFromChecksum(checksumInfo.Algorithm),
					checksumValueToHttpDigest(checksumInfo.Algorithm, checksumInfo.Value),
				)
			}
			if len(transfer.requestedChecksums) == 0 {
				log.WithFields(fields).Debugln(
					"Checksum algorithms provided by server were not the requested crc32c; client-computed crc32c value is",
					hex.EncodeToString(hashes[0].(hash.Hash).Sum(nil)),
				)
			} else {
				log.WithFields(fields).Debugln(
					"Checksum algorithms provided by server were not the requested ones; client computed",
					HttpDigestFromChecksum(transfer.requestedChecksums[0]), "value as",
					checksumValueToHttpDigest(transfer.requestedChecksums[0], hashes[0].(hash.Hash).Sum(nil)),
				)
			}
		}
	}
	// Add our attempt fields
	attempt.TransferEndTime = transferEndTime
	attempt.TransferTime = transferEndTime.Sub(transferStartTime)
	transferResult.Attempts = append(transferResult.Attempts, attempt)
	// Note: the top-level `err` (second return value) is only for cases where no
	// transfers were attempted.  If we got here, it must be nil.
	return transferResult, nil
}

// tpcStatus represents a status update from a third-party-copy transfer
type tpcStatus struct {
	err     error
	done    bool
	xferred uint64
}

// copyHTTP uses the WebDAV COPY verb to perform a third-party-copy transfer.
// Only implements the "push" mode where the destination side is the active
// side performing the transfer.
func copyHTTP(xfer *transferFile) (transferResults TransferResults, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in HTTP copy code:", r)
			err = errors.Errorf("Unrecoverable error (panic) occurred in copyHTTP: %v", r)
		}
	}()
	if len(xfer.attempts) == 0 {
		log.Errorln("No source URLs specified; cannot copy")
		err = errors.New("No source URLs specified")
		return
	}
	if len(xfer.job.dirResp.ObjectServers) == 0 {
		log.Errorln("No destination servers specified; cannot copy")
		err = errors.New("No destination servers specified")
		return
	}
	resolvedDestUrl := *xfer.job.dirResp.ObjectServers[0]
	resolvedDestUrl.Path = path.Clean(xfer.remoteURL.Path)
	resolvedDestUrl.RawQuery = xfer.remoteURL.RawQuery

	log.Debugln("Copying object from", xfer.attempts[0].Url.String(), "to", resolvedDestUrl.String())
	transferResults = newTransferResults(xfer.job)

	lastUpdate := time.Now()
	if xfer.callback != nil {
		xfer.callback(xfer.remoteURL.String(), 0, 0, false)
	}
	downloaded := int64(-1)
	totalSize := int64(-1)
	transferStartTime := time.Now()
	transferResults.TransferStartTime = transferStartTime
	attempt := TransferResult{
		CacheAge: -1,
		Number:   0,
		Endpoint: xfer.remoteURL.String(),
	}

	defer func() {
		endTime := time.Now()
		attempt.TransferEndTime = endTime
		attempt.TransferTime = endTime.Sub(transferStartTime)
		attempt.TransferFileBytes = totalSize
		transferResults.Attempts = []TransferResult{attempt}

		if xfer.callback != nil {
			finalSize := int64(0)
			if totalSize >= 0 {
				finalSize = totalSize
			}
			xfer.callback(xfer.remoteURL.String(), downloaded, finalSize, true)
		}
		if xfer.engine != nil {
			xfer.engine.ewmaCtr.Add(int64(time.Since(lastUpdate)))
		}
	}()

	client := http.Client{
		Transport: config.GetTransport(),
	}

	ctx, cancel := context.WithCancel(xfer.ctx)
	defer cancel()

	// HEAD request to get source size
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, xfer.attempts[0].Url.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "Failed to get size of the source object %s", xfer.attempts[0].Url.String())
		return
	}

	if xfer.srcToken != nil {
		srcTkn, tErr := xfer.srcToken.Get()
		if tErr == nil && srcTkn != "" {
			req.Header.Set("Authorization", "Bearer "+srcTkn)
		}
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	log.Debugln("Starting the HEAD request to the HTTP Third Party Copy source...")
	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "failed to execute the HEAD request to third-party-copy source %s", xfer.attempts[0].Url.String())
		log.Errorln(err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("HEAD request to source failed (HTTP status %d)", resp.StatusCode), nil}
		return
	}
	totalSize = resp.ContentLength
	if resp.ContentLength < 0 {
		log.Warningln("Third-party-copy source", xfer.attempts[0].Url.String(), "is of unknown size; download statistics may be incorrect")
	}
	attempt.ServerVersion = resp.Header.Get("Server")

	// COPY request to the destination
	req, err = http.NewRequestWithContext(ctx, "COPY", resolvedDestUrl.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "Unable to create request for third-party-copy to %s", xfer.remoteURL.String())
		return
	}

	if tkn, tErr := xfer.token.Get(); tErr == nil && tkn != "" {
		req.Header.Set("Authorization", "Bearer "+tkn)
	}
	if xfer.srcToken != nil {
		if srcTkn, tErr := xfer.srcToken.Get(); tErr == nil && srcTkn != "" {
			req.Header.Set("TransferHeaderAuthorization", "Bearer "+srcTkn)
		}
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	req.Header.Set("Source", xfer.attempts[0].Url.String())

	log.Debugln("Starting the HTTP Third Party Copy transfer...")
	resp, err = client.Do(req)

	if err != nil {
		log.Errorf("Failed to execute the third-party-copy to %s: %s", xfer.remoteURL.String(), err.Error())
		err = errors.Wrapf(err, "Failed to execute the third-party-copy to %s", xfer.remoteURL.String())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var respBytes []byte
		respBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("TPC COPY to %s failed (HTTP status %d); additionally, reading the response body failed: %s", resolvedDestUrl.String(), resp.StatusCode, err.Error())
		} else {
			if resp.StatusCode == http.StatusOK {
				log.Errorf("TPC COPY to %s returned HTTP 200 instead of 201 Created; the destination server does not have the TPC module loaded: %s",
					resolvedDestUrl.String(), string(respBytes))
				err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("TPC COPY to %s failed: the destination server does not have the TPC module loaded",
					resolvedDestUrl.String()), nil}
			} else if resp.StatusCode > 200 && resp.StatusCode < 300 {
				log.Errorf("TPC COPY to %s returned HTTP %d instead of 201 Created; the destination server may not support HTTP third-party-copy (ensure the TPC module is loaded): %s",
					resolvedDestUrl.String(), resp.StatusCode, string(respBytes))
				err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("TPC COPY failed (HTTP status %d)",
					resp.StatusCode), nil}
			} else {
				log.Errorf("TPC COPY to %s failed (HTTP status %d): %s", resolvedDestUrl.String(), resp.StatusCode, string(respBytes))
				err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("TPC COPY failed (HTTP status %d)",
					resp.StatusCode), nil}
			}
		}
		return
	}

	serverMessages := make(chan tpcStatus, 1)

	xfer.engine.egrp.Go(func() error { return monitorTPC(serverMessages, resp.Body) })

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	gotFirstByte := false
MessageHandler:
	for {
		select {
		case msg, ok := <-serverMessages:
			if !ok {
				break MessageHandler
			}
			if msg.err != nil || msg.done {
				err = msg.err
				break MessageHandler
			}
			downloaded = int64(msg.xferred)
			if !gotFirstByte && downloaded > 0 {
				gotFirstByte = true
				attempt.TimeToFirstByte = time.Since(transferStartTime)
			}
		case <-ticker.C:
			if totalSize < downloaded {
				totalSize = downloaded
				attempt.TransferFileBytes = totalSize
			}
			if xfer.callback != nil {
				log.Infof("Transfer %s->%s has downloaded %d bytes", xfer.attempts[0].Url.String(), xfer.remoteURL.String(), downloaded)
				xfer.callback(xfer.remoteURL.String(), downloaded, totalSize, false)
			}
		case <-ctx.Done():
			err = ctx.Err()
			break MessageHandler
		}
	}

	if err == nil && totalSize >= 0 {
		transferResults.TransferredBytes = totalSize
	}

	return
}

// monitorTPC reads periodic updates from the HTTP TPC response body,
// parses performance markers, and writes them to the channel.
//
// This is guaranteed to close the channel before exiting.
func monitorTPC(messages chan tpcStatus, body io.Reader) error {
	defer close(messages)
	scanner := bufio.NewScanner(body)
	perfMarker := false
	stripes := make(map[int]uint64)
	xferred := uint64(0)
	curStripe := 0
	curStripeBytes := uint64(0)
	var err error
Listener:
	for scanner.Scan() {
		text := scanner.Text()
		if text == "Perf Marker" {
			perfMarker = true
		} else if text == "End" {
			if !perfMarker {
				log.Warning("Client received an end-of-performance marker but no beginning")
			}
			stripes[curStripe] = curStripeBytes
			perfMarker = false
			sum := uint64(0)
			for _, val := range stripes {
				sum += val
			}
			messages <- tpcStatus{
				xferred: sum,
			}
			xferred = sum
		} else { // All other messages have the format "key: value"
			info := strings.SplitN(text, ":", 2)
			if len(info) != 2 {
				log.Warningln("Invalid line in the TPC update:", text)
				continue
			}
			key := strings.TrimSpace(info[0])
			value := strings.TrimSpace(info[1])
			switch key {
			case "failure":
				err = errors.Errorf("TPC copy failed: %s", value)
				break Listener
			case "success":
				break Listener
			case "Stripe Index":
				idx, pErr := strconv.Atoi(value)
				if pErr == nil {
					curStripe = idx
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Index': %s (%s)", pErr.Error(), value)
				}
			case "Stripe Bytes Transferred":
				bytes, pErr := strconv.Atoi(value)
				if pErr == nil {
					curStripeBytes = uint64(bytes)
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Bytes Transferred': %s (%s)", pErr.Error(), value)
				}
			case "Total Stripe Count":
				// Ignored
			case "RemoteConnections":
				// Ignored
			default:
				log.Debugln("Received performance marker with unknown key:", key)
			}
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	messages <- tpcStatus{
		err:     err,
		done:    true,
		xferred: xferred,
	}
	return nil
}

// Actually perform the HTTP PUT request to the server.
//
// This is executed in a separate goroutine to allow periodic progress callbacks
// to be created within the main goroutine.
func runPut(request *http.Request, responseChan chan<- *http.Response, errorChan chan<- error, proxy bool) {
	client := config.GetClientNoProxy()
	dump, _ := httputil.DumpRequestOut(request, false)
	log.Debugf("Dumping request: %s", dump)
	response, err := client.Do(request)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Errorln("Error with PUT:", err)
			// Wrap connection setup errors (timeout, DNS, TLS handshake, dial) in ConnectionSetupError
			// Note: TLS certificate validation errors are handled separately (not retryable)
			if isTLSCertificateValidationError(err) {
				// TLS certificate validation error - leave unwrapped, will be wrapped as SpecificationError in upload error handler
			} else if isContextDeadlineError(err) || isDNSError(err) || (isTLSError(err) && !isTLSCertificateValidationError(err)) || isDialError(err) {
				err = &ConnectionSetupError{URL: request.URL.String(), Err: err}
			}
		}
		errorChan <- err
		close(errorChan)
		return
	}
	dump, _ = httputil.DumpResponse(response, true)
	log.Debugf("Dumping response: %s", dump)
	// Note: XRootD used to always return 200 (OK) on upload, even when it was supposed to turn
	// HTTP 201 (Created).  Check for both here; in the future we may want to remove the 200 check
	// if we decide to drop support for the older versions of XRootD.
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
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

// Determine whether to skip a prestage based on whether an object is at a cache
func skipPrestage(object string, job *TransferJob) bool {
	var cache url.URL
	if len(job.dirResp.ObjectServers) > 0 {
		cache = *job.dirResp.ObjectServers[0]
	} else if len(job.prefObjServers) > 0 {
		cache = *job.prefObjServers[0]
	} else {
		log.Errorln("Cannot skip prestage if no cache is specified!")
	}

	cache.Path = object
	if age, _, err := objectCached(job.ctx, &cache, job.token); err == nil {
		return age >= 0
	} else {
		log.Warningln("Failed to check cache status of object", cache.String(), "so assuming it needs prestaging:", err)
		return false
	}
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
	// Skip the synchronization check if overwrites are enabled
	if param.Client_EnableOverwrites.GetBool() {
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

// Depending on the synchronization policy, decide if a TPC copy should be skipped.
// This stats the destination remote path using the destination's collections URL
// to check if the object already exists.
// sourceInfo is the fs.FileInfo from the source WebDAV listing.
// destCollClient is a WebDAV client pointed at the destination's collections URL.
func skipCopy(syncLevel SyncLevel, sourceInfo fs.FileInfo, destPath string, destCollClient *gowebdav.Client) bool {
	if syncLevel == SyncNone {
		return false
	}

	// Stat the destination to see if it already exists
	var destInfo fs.FileInfo
	err := retryWebDavOperation("Stat", func() error {
		var statErr error
		destInfo, statErr = destCollClient.Stat(destPath)
		return statErr
	})
	if err != nil {
		// If stat fails (e.g., 404), the destination doesn't exist; don't skip
		return false
	}

	switch syncLevel {
	case SyncExist:
		return true
	case SyncSize:
		return sourceInfo.Size() == destInfo.Size()
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
	var infos []fs.FileInfo
	err := retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = client.ReadDir(remotePath)
		return err
	})
	if err != nil {
		// Check if we got a 404:
		if gowebdav.IsErrNotFound(err) {
			return error_codes.NewSpecification_FileNotFoundError(errors.New("404: object not found"))
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// XRootD workaround!
			// If you attempt a directory listing on a path that is actually a file,
			// XRootD returns a 500 error.  In this case, we need to stat the path
			// to see if it's a file, and if so, create a download job for it.
			var info fs.FileInfo
			err := retryWebDavOperation("Stat", func() error {
				var err error
				info, err = client.Stat(remotePath)
				return err
			})
			if err != nil {
				return errors.Wrap(err, "failed to stat remote path")
			}
			// If the path leads to a file and not a collection, create a job to download the file and return
			if !info.IsDir() {
				if skipDownload(job.job.syncLevel, info, job.job.localPath) {
					log.Infoln("Skipping download of object", remotePath, "as it already exists at", job.job.localPath)
				} else {
					// Construct URL using the transfer URL's base, _not the collections URL base_
					// The transfer URL base may differ: "/" for downloads from XRootD or
					// "/api/v1.0/origin/data" for uploads to a POSIXv2 origin in some configurations.
					// The collections URL base may be different for POSIXv2 versus POSIX origins.  Hence,
					// we should never assume they are comparable.
					//
					// Calculate the base by stripping the federation namespace path from the transfer URL
					transferAttempts := make([]transferAttemptDetails, len(transfers))
					for i, attempt := range transfers {
						transferAttempts[i] = attempt
						attemptPath := attempt.Url.Path
						if attemptPath != "" && !strings.HasSuffix(attemptPath, "/") {
							attemptPath += "/"
						}
						federationPath := job.job.remoteURL.Path
						if federationPath != "" && !strings.HasSuffix(federationPath, "/") {
							federationPath += "/"
						}
						log.Debugln("Attempt path:", attemptPath, "federation path:", federationPath)
						transferBase := strings.TrimSuffix(attemptPath, federationPath)
						fileURL := &url.URL{
							Scheme:   attempt.Url.Scheme,
							Host:     attempt.Url.Host,
							Path:     path.Join(transferBase, remotePath),
							RawQuery: attempt.Url.RawQuery,
						}
						transferAttempts[i].Url = fileURL
						log.Debugln("Constructed attempt URL for download:", fileURL.String(), "remote path:", remotePath)
					}
					job.job.activeXfer.Add(1)
					select {
					case <-job.job.ctx.Done():
						return job.job.ctx.Err()
					case files <- &clientTransferFile{
						uuid:  job.uuid,
						jobId: job.job.uuid,
						file: &transferFile{
							ctx:                job.job.ctx,
							callback:           job.job.callback,
							job:                job.job,
							engine:             te,
							remoteURL:          &url.URL{Path: remotePath},
							requestedChecksums: job.job.requestedChecksums,
							requireChecksum:    job.job.requireChecksum,
							packOption:         transfers[0].PackOption,
							localPath:          job.job.localPath,
							xferType:           job.job.xferType,
							token:              job.job.token,
							attempts:           transferAttempts,
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
		newPath := path.Join(remotePath, info.Name())
		if info.IsDir() {
			err := te.walkDirDownloadHelper(job, transfers, files, newPath, client)
			if err != nil {
				return err
			}
		} else if job.job.xferType == transferTypePrestage && skipPrestage(newPath, job.job) {
			log.Infoln("Skipping prestage of object", newPath, "as it already is at the cache")
		} else {
			// Determine the correct local path.  If the user requested that the
			// transfer be directed to the null device, then we always use
			// os.DevNull as the target path; otherwise, construct the standard
			// destination inside the requested directory.
			targetPath := job.job.localPath
			if targetPath != os.DevNull {
				targetPath = path.Join(job.job.localPath, localBase, info.Name())
			}

			if job.job.xferType == transferTypeDownload && skipDownload(job.job.syncLevel, info, targetPath) {
				log.Infoln("Skipping download of object", newPath, "as it already exists at", targetPath)
				continue
			}

			// Construct URL using the transfer URL's base, not the collections URL base.
			// The two bases may differ in arbitrary ways; see notes above for explanation.
			transferAttempts := make([]transferAttemptDetails, len(transfers))
			for i, attempt := range transfers {
				transferAttempts[i] = attempt
				attemptPath := attempt.Url.Path
				if attemptPath != "" && !strings.HasSuffix(attemptPath, "/") {
					attemptPath += "/"
				}
				federationPath := job.job.remoteURL.Path
				if federationPath != "" && !strings.HasSuffix(federationPath, "/") {
					federationPath += "/"
				}
				log.Debugln("Attempt path:", attemptPath, "federation path:", federationPath)
				transferBase := strings.TrimSuffix(attemptPath, federationPath)
				fileURL := &url.URL{
					Scheme:   attempt.Url.Scheme,
					Host:     attempt.Url.Host,
					Path:     path.Join(transferBase, newPath),
					RawQuery: attempt.Url.RawQuery,
				}
				transferAttempts[i].Url = fileURL
				log.Debugln("Constructed attempt URL for download:", fileURL.String(), "remote path:", remotePath)
			}
			job.job.activeXfer.Add(1)
			select {
			case <-job.job.ctx.Done():
				return job.job.ctx.Err()
			case files <- &clientTransferFile{
				uuid:  job.uuid,
				jobId: job.job.uuid,
				file: &transferFile{
					ctx:                job.job.ctx,
					callback:           job.job.callback,
					job:                job.job,
					engine:             te,
					remoteURL:          &url.URL{Path: newPath},
					requestedChecksums: job.job.requestedChecksums,
					requireChecksum:    job.job.requireChecksum,
					packOption:         transfers[0].PackOption,
					localPath:          targetPath,
					xferType:           job.job.xferType,
					token:              job.job.token,
					attempts:           transferAttempts,
				},
			}:
				job.job.totalXfer += 1
			}
		}
	}
	return nil
}

// walkDirCopy walks the remote source directory and emits individual TPC copy jobs
// for each file found. This is used for recursive third-party-copy operations.
func (te *TransferEngine) walkDirCopy(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, srcUrl *url.URL) error {
	// Use the source director response to get the collections URL for listing
	collUrl := job.job.srcDirResp.XPelNsHdr.CollectionsUrl
	if collUrl == nil {
		return errors.New("Collections URL not found in source director response for recursive copy")
	}
	log.Debugln("Trying source collections URL for TPC walk: ", collUrl.String())

	srcClient := createWebDavClient(collUrl, job.job.srcToken, job.job.project)

	// Create a destination WebDAV client for sync skip checks (stat destination)
	var destClient *gowebdav.Client
	if job.job.syncLevel != SyncNone {
		destCollUrl := job.job.dirResp.XPelNsHdr.CollectionsUrl
		if destCollUrl == nil {
			log.Warnln("Destination collections URL not found; sync skip checks will be disabled for TPC copy")
		} else {
			log.Debugln("Trying destination collections URL for TPC sync skip: ", destCollUrl.String())
			destClient = createWebDavClient(destCollUrl, job.job.token, job.job.project)
		}
	}

	return te.walkDirCopyHelper(job, transfers, files, srcUrl.Path, srcClient, destClient)
}

// walkDirCopyHelper recursively walks the remote source directory and emits individual
// TPC copy transfer files. For each file found, it creates a copy job where the source
// server URLs point to the individual file and the destination (via dirResp.ObjectServers)
// is also adjusted to the corresponding destination path.
// destWebDavClient may be nil if sync skip is disabled; used to stat destination files.
func (te *TransferEngine) walkDirCopyHelper(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, remotePath string, webdavClient *gowebdav.Client, destWebDavClient *gowebdav.Client) error {
	// Check for cancellation
	if err := job.job.ctx.Err(); err != nil {
		return err
	}

	var infos []fs.FileInfo
	err := retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = webdavClient.ReadDir(remotePath)
		return err
	})
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return error_codes.NewSpecification_FileNotFoundError(errors.New("404: source object not found"))
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// XRootD workaround: a directory listing on a file path returns 500.
			// Stat the path; if it is a file, emit a single copy job.
			var info fs.FileInfo
			err := retryWebDavOperation("Stat", func() error {
				var err error
				info, err = webdavClient.Stat(remotePath)
				return err
			})
			if err != nil {
				return errors.Wrap(err, "failed to stat source path for copy")
			}
			if !info.IsDir() {
				return te.emitCopyJob(job, transfers, files, remotePath, info, destWebDavClient)
			}
			return nil
		}
		return errors.Wrap(err, "failed to read source collection for copy")
	}

	for _, info := range infos {
		newPath := path.Join(remotePath, info.Name())
		if info.IsDir() {
			err := te.walkDirCopyHelper(job, transfers, files, newPath, webdavClient, destWebDavClient)
			if err != nil {
				return err
			}
		} else {
			if err := te.emitCopyJob(job, transfers, files, newPath, info, destWebDavClient); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitCopyJob creates and emits a single TPC copy job for a file at the given source path.
// It adjusts the source server URLs (in transfers/attempts) and the destination remote URL
// to point at the individual file, computing the relative path within the source directory.
// sourceInfo is the fs.FileInfo for the source file, used for sync skip checks.
// destCollClient may be nil if sync skip is disabled; used to stat the destination file.
func (te *TransferEngine) emitCopyJob(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, srcFilePath string, sourceInfo fs.FileInfo, destCollClient *gowebdav.Client) error {
	// Compute relative path of this file within the source directory
	relPath := strings.TrimPrefix(srcFilePath, job.job.srcURL.Path)
	relPath = strings.TrimPrefix(relPath, "/")

	// Build the destination path: the base destination + the relative path from source
	destPath := path.Join(job.job.remoteURL.Path, relPath)

	// Check if this copy should be skipped based on sync policy
	if destCollClient != nil && skipCopy(job.job.syncLevel, sourceInfo, destPath, destCollClient) {
		log.Infoln("Skipping copy of object", srcFilePath, "as it already exists at destination", destPath)
		return nil
	}

	// Build source server attempts for this individual file.
	// Each attempt in `transfers` has the source server URL with the source directory path;
	// we need to replace that path with the individual file path.
	srcAttempts := make([]transferAttemptDetails, len(transfers))
	for i, attempt := range transfers {
		srcAttempts[i] = attempt
		// The attempt URL path is currently set to the source directory path.
		// Compute the base by stripping the original source path, then append the file path.
		attemptPath := attempt.Url.Path
		if attemptPath != "" && !strings.HasSuffix(attemptPath, "/") {
			attemptPath += "/"
		}
		srcBasePath := job.job.srcURL.Path
		if srcBasePath != "" && !strings.HasSuffix(srcBasePath, "/") {
			srcBasePath += "/"
		}
		transferBase := strings.TrimSuffix(attemptPath, srcBasePath)
		fileURL := &url.URL{
			Scheme:   attempt.Url.Scheme,
			Host:     attempt.Url.Host,
			Path:     path.Join(transferBase, srcFilePath),
			RawQuery: attempt.Url.RawQuery,
		}
		srcAttempts[i].Url = fileURL
		log.Debugln("Constructed source attempt URL for TPC copy:", fileURL.String(), "file:", srcFilePath)
	}

	job.job.activeXfer.Add(1)
	select {
	case <-job.job.ctx.Done():
		return job.job.ctx.Err()
	case files <- &clientTransferFile{
		uuid:  job.uuid,
		jobId: job.job.uuid,
		file: &transferFile{
			ctx:       job.job.ctx,
			callback:  job.job.callback,
			job:       job.job,
			engine:    te,
			remoteURL: &url.URL{Path: destPath},
			xferType:  job.job.xferType,
			token:     job.job.token,
			srcToken:  job.job.srcToken,
			attempts:  srcAttempts,
		},
	}:
		job.job.totalXfer += 1
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
			if os.IsNotExist(err) {
				return error_codes.NewParameter_FileNotFoundError(errors.Wrapf(err, "local path %q does not exist", localPath))
			} else if os.IsPermission(err) {
				return error_codes.NewAuthorizationError(errors.Wrapf(err, "permission denied accessing local path %q", localPath))
			}
			return error_codes.NewParameterError(errors.Wrap(err, "failed to stat local path"))
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
						xferType:   job.job.xferType,
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
		return error_codes.NewParameterError(errors.Wrap(err, "failed to upload local collection"))
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
					xferType:   job.job.xferType,
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
func listHttp(remoteUrl *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator, recursive bool, depth int) (fileInfos []FileInfo, err error) {
	// Get our collection listing host
	if dirResp.XPelNsHdr.CollectionsUrl == nil {
		return nil, errors.Errorf("Collections URL not found in director response. Are you sure there's an origin for prefix %s that supports listings?", dirResp.XPelNsHdr.Namespace)
	}

	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl
	if collectionsUrl == nil {
		err = errors.New("namespace does not provide a collections URL for listing")
		return
	}
	log.Debugln("Collections URL: ", collectionsUrl.String())

	project, found := searchJobAd(attrProjectName)
	if !found {
		project = ""
	}
	client := createWebDavClient(collectionsUrl, token, project)
	remotePath := remoteUrl.Path

	// If recursive listing is requested, use the helper function
	if recursive {
		return listHttpRecursive(client, remotePath, depth)
	}

	// Non-recursive listing (original behavior)
	var infos []fs.FileInfo
	err = retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = client.ReadDir(remotePath)
		return err
	})
	if err != nil {
		// Check if we got a 404:
		if gowebdav.IsErrNotFound(err) {
			return nil, error_codes.NewSpecification_FileNotFoundError(errors.New("404: object not found"))
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// If we get an error code 500 (internal server error), we should check if the user is trying to ls on a file
			var info fs.FileInfo
			err := retryWebDavOperation("Stat", func() error {
				var err error
				info, err = client.Stat(remotePath)
				return err
			})
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
			listingErr := &dirListingNotSupportedError{
				Err: errors.New("405: object listings are not supported by the discovered origin"),
			}
			return nil, error_codes.NewSpecificationError(listingErr)
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

// listHttpRecursive recursively lists all objects in a collection with optional depth limiting
func listHttpRecursive(client *gowebdav.Client, remotePath string, maxDepth int) (fileInfos []FileInfo, err error) {
	return listHttpRecursiveHelper(client, remotePath, 0, maxDepth)
}

// listHttpRecursiveHelper is the recursive helper function that tracks the current depth
func listHttpRecursiveHelper(client *gowebdav.Client, remotePath string, currentDepth int, maxDepth int) (fileInfos []FileInfo, err error) {
	// Check if we've reached the maximum depth (if maxDepth is >= 0)
	if maxDepth >= 0 && currentDepth > maxDepth {
		return fileInfos, nil
	}

	var infos []fs.FileInfo
	err = retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = client.ReadDir(remotePath)
		return err
	})
	if err != nil {
		// Check if we got a 404:
		if gowebdav.IsErrNotFound(err) {
			return nil, error_codes.NewSpecification_FileNotFoundError(errors.New("404: object not found"))
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// If we get an error code 500 (internal server error), we should check if the user is trying to ls on a file
			var info fs.FileInfo
			err := retryWebDavOperation("Stat", func() error {
				var err error
				info, err = client.Stat(remotePath)
				return err
			})
			if err != nil {
				return nil, errors.Wrap(err, "failed to stat remote path")
			}
			// If the path leads to a file and not a collection, just add the filename
			if !info.IsDir() {
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
			listingErr := &dirListingNotSupportedError{
				Err: errors.New("405: object listings are not supported by the discovered origin"),
			}
			return nil, error_codes.NewSpecificationError(listingErr)
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

		// If this is a collection and we haven't reached max depth, recurse into it
		// We check currentDepth + 1 < maxDepth because currentDepth represents how deep we are,
		// and we want to recurse only if going one level deeper wouldn't exceed maxDepth
		if info.IsDir() && (maxDepth < 0 || currentDepth+1 < maxDepth) {
			subFileInfos, err := listHttpRecursiveHelper(client, jPath, currentDepth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			fileInfos = append(fileInfos, subFileInfos...)
		}
	}

	return fileInfos, nil
}

// retryWebDavOperation executes a WebDAV operation with retry logic for idle connection errors.
// The operation is retried up to maxWebDavRetries times if an idle connection error is encountered.
func retryWebDavOperation(operationName string, operation func() error) error {
	var err error
	for attempt := 0; attempt < maxWebDavRetries; attempt++ {
		err = operation()
		if err == nil {
			return nil
		}
		// Retry if it's a retriable error (idle connection, timeout, etc.) and we have attempts remaining
		if isRetryableWebDavError(err) && attempt < maxWebDavRetries-1 {
			log.Debugf("Retrying %s after retriable error (attempt %d/%d): %v", operationName, attempt+1, maxWebDavRetries, err)
			continue
		}
		// For all other errors or final attempt, return the error
		break
	}
	return err
}

// deleteHttp takes the collection URL from the director response to perform the delete operation.
// If the recursive flag is set, it recursively deletes a collection by iterating over the collection tree
// and deleting each leaf object one by one.
//
// Note: The current implementation of recursive collection deletion is inefficient and does not use concurrency.
// This limitation exists because the object delete command is not openly supported and is intended to remain hidden.
// Adding concurrency would require integrating the delete command into the transfer engine logic,
// which would involve significant and complex changes. As the command is not fully supported, concurrency is deferred.
func deleteHttp(ctx context.Context, remoteUrl *pelican_url.PelicanURL, recursive bool, dirResp server_structs.DirectorResponse, token *tokenGenerator) (err error) {
	log.Debugln("Attempting to delete:", remoteUrl.Path)
	project, found := searchJobAd(attrProjectName)
	if !found {
		project = ""
	}

	if dirResp.XPelNsHdr.CollectionsUrl == nil || dirResp.XPelNsHdr.CollectionsUrl.String() == "" {
		log.Info("Collections URL not received in director response, attempting to delete directly using HTTP DELETE.")
		if len(dirResp.ObjectServers) == 0 {
			return errors.New("no object servers found in director response; cannot delete object")
		}

		client := config.GetClient()

		// Object deletion command only works for a single origin in a prefix setup.
		serverUrl := dirResp.ObjectServers[0].String()
		req, err := http.NewRequestWithContext(ctx, "DELETE", serverUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create HTTP DELETE request: %w", err)
		}
		tokenContents, err := token.Get()
		if err != nil || tokenContents == "" {
			return errors.Wrap(err, "failed to get token for transfer")
		}
		req.Header.Set("User-Agent", getUserAgent(project))
		if jobId, found := searchJobAd(attrJobId); found {
			req.Header.Set("X-Pelican-JobId", jobId)
		}
		req.Header.Set("Authorization", "Bearer "+tokenContents)
		req.Header.Set("X-Transfer-Status", "true")

		var resp *http.Response
		if resp, err = client.Do(req); err != nil {
			return errors.Wrap(err, "HTTP DELETE request failed")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			sce := StatusCodeError(resp.StatusCode)
			return errors.Wrap(&sce, "HTTP DELETE request returned unexpected status")
		}

		log.Debugln("Successfully deleted:", remoteUrl.Path)
		return nil

	}

	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl
	client := createWebDavClient(collectionsUrl, token, project)
	remotePath := remoteUrl.Path

	// Use retry logic for Stat() to handle idle connection errors
	var info fs.FileInfo
	err = retryWebDavOperation("Stat", func() error {
		var err error
		info, err = client.Stat(remotePath)
		if err != nil {
			if gowebdav.IsErrNotFound(err) {
				return error_codes.NewSpecification_FileNotFoundError(errors.Wrapf(ErrObjectNotFound, "cannot remove remote path %s: no such object or collection", remotePath))
			}
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "failed to check object existence")
	}

	if info.IsDir() {
		var children []fs.FileInfo
		// Use retry logic for ReadDir() to handle idle connection errors
		err = retryWebDavOperation("ReadDir", func() error {
			var err error
			children, err = client.ReadDir(remotePath)
			return err
		})
		if err != nil {
			return errors.Wrapf(err, "failed to read contents of collection %s", remotePath)
		}
		if !recursive && len(children) > 0 {
			return errors.Errorf("%s is a non-empty collection, use recursive flag or recursive query in the url to delete it", remotePath)
		}
		if recursive {
			for _, child := range children {
				childPath := remotePath + "/" + child.Name()
				err = deleteHttp(ctx, &pelican_url.PelicanURL{Path: childPath}, recursive, dirResp, token)
				if err != nil {
					return errors.Wrapf(err, "failed to delete child object %s", childPath)
				}
			}
		}
	}

	// Retry logic for Remove operation to handle spurious HTTP 400 errors
	err = func() error {
		var lastErr error
		for attempt := range 2 {
			lastErr = client.Remove(remotePath)
			if lastErr == nil {
				return nil
			}
			// Retry once if we get an HTTP 400 error (spurious server errors)
			if attempt == 0 && gowebdav.IsErrCode(lastErr, http.StatusBadRequest) {
				log.Debugln("Received HTTP 400 on delete attempt, retrying once:", remotePath)
				continue
			}
			// For all other errors or final attempt, return the error
			return lastErr
		}
		return lastErr
	}()

	if err != nil {
		if gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) {
			return errors.Wrap(err, "method not allowed on the remote object, deletion is not permitted")
		}
		if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			return errors.Wrap(err, "internal server error occurred while attempting to delete the remote object")
		}
		return errors.Wrap(err, "failed to delete remote object")
	}
	log.Debugln("Origin reported successful deletion of:", remoteUrl.Path)
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
		if destCopy.Path != "" {
			destCopy.Path = path.Clean(destCopy.Path)
		}

		go func(endpoint *url.URL) {
			canDisableProxy := CanDisableProxy()
			disableProxy := !isProxyEnabled()
			idleConnRetries := 0

			var info FileInfo
			for {
				if disableProxy {
					log.Debugln("Performing request (without proxy)", endpoint.String())
					transport = config.GetTransportNoProxy()
				} else {
					log.Debugln("Performing request", endpoint.String())
				}
				client.SetTransport(transport)

				fsinfo, err := client.Stat(endpoint.Path)
				if err == nil {
					info = FileInfo{
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
					err = errors.Wrapf(ErrObjectNotFound, "object %s not found at the endpoint %s", dest.String(), endpoint.String())
					err = error_codes.NewSpecification_FileNotFoundError(err)
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
				// If we have a retryable error (idle connection, timeout, etc.), retry
				if isRetryableWebDavError(err) && idleConnRetries < maxWebDavRetries-1 {
					log.Debugf("Retrying Stat after retryable error (attempt %d/%d): %v", idleConnRetries+1, maxWebDavRetries, err)
					idleConnRetries++
					continue
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

// Check if a given URL is present at the first cache in the director response
//
// Note that xrootd returns an `Age` header for GETs but only a `Content-Length`
// header for HEADs.  If `Content-Range` is found, we will use that header; if not,
// we will issue two commands.
func objectCached(ctx context.Context, objectUrl *url.URL, token *tokenGenerator) (age int, size int64, err error) {

	age = -1

	headClient := config.GetClient()
	headRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, objectUrl.String(), nil)
	if err != nil {
		return
	}
	headRequest.Header.Set("Range", "0-0")
	if token != nil {
		if tokenContents, err := token.Get(); err == nil && tokenContents != "" {
			headRequest.Header.Set("Authorization", "Bearer "+tokenContents)
		}
	}
	var headResponse *http.Response
	headResponse, err = headClient.Do(headRequest)
	if err != nil {
		return
	}
	// Allow response body to fail to read; we are only interested in the headers
	// of the response, not the contents.
	if _, err := io.Copy(io.Discard, headResponse.Body); err != nil {
		log.Debugln("Failure when reading the one-byte-response body - expected because the body is discarded:", err)
	}
	headResponse.Body.Close()
	gotContentRange := false
	if headResponse.StatusCode <= 300 {
		if contentRangeStr := headResponse.Header.Get("Content-Range"); contentRangeStr != "" {
			if after, found := strings.CutPrefix(contentRangeStr, "bytes 0-0/"); found {
				if afterParsed, err := strconv.Atoi(after); err == nil {
					size = int64(afterParsed)
					gotContentRange = true
				} else {
					log.Warningf("Ignoring invalid content range value (%s) due to parsing error: %s", after, err.Error())
				}
			} else {
				log.Debugln("Unexpected value found in Content-Range header:", contentRangeStr)
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
		sce := StatusCodeError(headResponse.StatusCode)
		err = &HttpErrResp{
			Code: headResponse.StatusCode,
			Str:  fmt.Sprintf("request failed (%d)", headResponse.StatusCode),
			Err:  &sce,
		}
	}
	// Early return -- all the info we wanted was in the GET response.
	if gotContentRange {
		return
	}

	headRequest, err = http.NewRequestWithContext(ctx, http.MethodHead, objectUrl.String(), nil)
	if err != nil {
		return
	}
	if token != nil {
		if tokenContents, err := token.Get(); err == nil && tokenContents != "" {
			headRequest.Header.Set("Authorization", "Bearer "+tokenContents)
		}
	}

	headResponse, err = headClient.Do(headRequest)
	if err != nil {
		return
	}
	if _, err := io.Copy(io.Discard, headResponse.Body); err != nil {
		log.Warningln("Failure when reading the HEAD response body:", err)
	}
	defer headResponse.Body.Close()
	if headResponse.StatusCode <= 300 {
		contentLengthStr := headResponse.Header.Get("Content-Length")
		if contentLengthStr != "" {
			size, err = strconv.ParseInt(contentLengthStr, 10, 64)
			if err != nil {
				err = errors.Wrap(err, "problem converting Content-Length in response to an int")
				log.Errorln(err.Error())

			}
		}
	} else {
		sce := StatusCodeError(headResponse.StatusCode)
		err = &HttpErrResp{
			Code: headResponse.StatusCode,
			Str:  fmt.Sprintf("request failed (HTTP status %d)", headResponse.StatusCode),
			Err:  &sce,
		}
	}
	return
}

// This function searches the condor job ad for a specific classad attribute
// and returns the value.
func searchJobAd(attribute classAdAttr) (value string, found bool) {
	jobAdOnce.Do(func() {
		jobAd = make(map[string]string)
		// Look for the condor job ad file
		condorJobAd, isPresent := os.LookupEnv("_CONDOR_JOB_AD")
		var filename string
		if isPresent {
			filename = condorJobAd
		} else if _, err := os.Stat(".job.ad"); err == nil {
			filename = ".job.ad"
		} else {
			return
		}

		b, err := os.ReadFile(filename)
		if err != nil {
			log.Warningln("Can not read .job.ad file", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			matches := adLineRegex.FindStringSubmatch(line)
			if len(matches) != 3 {
				continue
			}
			jobAd[matches[1]] = matches[2]
		}
	})

	switch attribute {
	case attrProjectName:
		value, found = jobAd[string(attrProjectName)]
		return
	case attrJobId:
		value, found = jobAd[string(attrJobId)]
	}
	return
}
