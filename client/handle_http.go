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
	"net/http/httptrace"
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
	"golang.org/x/sync/singleflight"
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

	// errStatOnCollectionAtCache is an internal sentinel for the case where a
	// stat host (typically an XRootD cache) returns 409 for a PROPFIND on what
	// is actually a directory. Caches do not serve directory listings; statHttp
	// uses this to decide whether to fall back to the collections URL (origin
	// WebDAV endpoint), which does serve them.
	errStatOnCollectionAtCache = errors.New("stat host returned 409 (likely a collection at a cache)")

	// maxWebDavRetries is the maximum number of attempts (including the initial attempt)
	// for WebDAV operations that encounter idle connection errors.
	maxWebDavRetries = 2
)

type (
	logFields string

	classAdAttr string

	// requestIdCtxKey is the context key for propagating a caller-supplied
	// request ID (X-Pelican-JobId) through the transfer pipeline.
	requestIdCtxKey struct{}

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
		Error             error                        `json:"error"`
		TransferredBytes  int64                        `json:"transferredBytes"`
		ETag              string                       `json:"etag,omitempty"`  // ETag from the server response (GET or PUT)
		ServerChecksums   []ChecksumInfo               `json:"serverChecksums"` // Checksums returned by the server
		ClientChecksums   []ChecksumInfo               `json:"clientChecksums"` // Checksums calculated by the client
		TransferStartTime time.Time                    `json:"transferStartTime"`
		Scheme            string                       `json:"scheme"`
		Source            string                       `json:"source"`
		Attempts          []TransferResult             `json:"attempts"`
		DirectorDecision  *server_structs.RedirectInfo `json:"directorDecision,omitempty"`
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

		// Preferred indicates this server came from the user's PreferredCaches
		// configuration rather than being discovered via the Director.  When true,
		// the server must not be sorted after any non-preferred (director-provided)
		// server, even if the origin/cache service responds more quickly.
		Preferred bool
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
		fedToken           TokenProvider // Federation token; added as access_token query param on origin URLs
		xferType           transferType
		packOption         string
		attempts           []transferAttemptDetails
		project            string
		requireChecksum    bool
		requestedChecksums []ChecksumType
		err                error
		writer             io.WriteCloser          // Optional writer for downloads
		reader             io.ReadCloser           // Optional reader for uploads
		byteRange          *ByteRange              // Optional byte range for partial downloads
		metadataChan       chan<- TransferMetadata // Optional channel to receive early transfer metadata

		// TagScheduler hooks: nil unless the engine was constructed with a
		// scheduler. schedFirstByte fires once (idempotent) as soon as the
		// remote end proves responsive: for downloads, the first non-empty
		// body byte written to the local sink; for uploads, the earliest of
		// a negotiated 100-continue, the first byte of the PUT response, or
		// uploadNonStarvingSentBytes of body consumed by the transport (the
		// far end must be draining it); for third-party copies, the first
		// byte of the COPY response or the first performance marker,
		// whichever arrives first. schedDone fires exactly once when the
		// worker is done with this file.
		schedFirstByte func()
		schedDone      func()
		// objectMetadata is the optional uploader-supplied custom-
		// fields map. When non-empty, the upload PUT is decorated
		// with an X-Pelican-Object-Metadata header carrying the SFV
		// rendering of these fields.
		objectMetadata map[string]any
		// objectMetadataBlob carries the optional opaque-blob
		// metadata supplied via WithObjectMetadataBlob /
		// WithObjectMetadataBlobFile. When non-nil, the upload PUT
		// is sent as multipart/form-data: "metadata" part with
		// the blob, "object" part with the file body.
		objectMetadataBlob *objectMetadataBlob
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
		skipped403         sync.Mutex // Protects skipped403Objs slice
		skipped403Objs     []string   // List of object paths skipped due to 403 during sync
		localPath          string
		xferType           transferType
		requestedChecksums []ChecksumType
		requireChecksum    bool
		recursive          bool
		rejectCollections  bool // If true, error when the remote path is a collection
		skipAcquire        bool
		dryRun             bool                            // Enable dry-run mode to display what would be transferred without actually doing it
		srcURL             *url.URL                        // When a copy job, this is the source URL
		srcDirResp         server_structs.DirectorResponse // When a copy job, this represents the source directory information
		srcToken           *tokenGenerator                 // When a copy job, this represents the source token
		syncLevel          SyncLevel                       // Policy for handling synchronization when the destination exists
		prefObjServers     []*url.URL                      // holds any client-requested caches/origins
		dirResp            server_structs.DirectorResponse // Director response for non-copy transfers (download, upload, prestage)
		destDirResp        server_structs.DirectorResponse // Director response for the copy destination
		directorUrl        string
		token              *tokenGenerator
		fedToken           TokenProvider // Federation token; sent as access_token query param to origins (not to the director)
		cacheMode          bool          // When true, the client queries the director's origin endpoint (/api/v1.0/director/origin/) instead of the default endpoint
		project            string
		writer             io.WriteCloser          // Optional writer for downloads - if set, write to this instead of localPath
		reader             io.ReadCloser           // Optional reader for uploads - if set, read from this instead of localPath
		inPlace            bool                    // If true, write directly to final destination; if false, use temporary file
		forcePrestageAPI   bool                    // If true, force use of prestage API and error if not supported (no fallback)
		byteRange          *ByteRange              // Optional byte range for partial downloads
		metadataChan       chan<- TransferMetadata // Optional channel to receive early transfer metadata
		requestId          string                  // Caller-supplied request ID for end-to-end tracing (X-Pelican-JobId)
		// objectMetadata is the optional client-supplied
		// X-Pelican-Object-Metadata field-set propagated to all
		// child transferFiles for upload jobs.
		objectMetadata map[string]any
		// objectMetadataBlob is the optional opaque-blob metadata
		// (set by WithObjectMetadataBlob / WithObjectMetadataBlobFile).
		// When non-nil and the blob body is non-empty, every child
		// transferFile uploads via multipart/form-data instead of
		// the historic raw PUT.
		objectMetadataBlob *objectMetadataBlob
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
		dirRespCache       *DirRespCache   // Prefix-matching cache for director responses
		prestageAPISupport map[string]bool // Lookup table for caches that support the Pelican prestage API (key: host)
		prestageAPIMutex   sync.RWMutex    // Protects the prestageAPISupport map
		scheduler          *TagScheduler   // Optional fair-scheduler; when set, admits before te.files
	}

	TransferCallbackFunc = func(path string, downloaded int64, totalSize int64, completed bool)

	// A client to the transfer engine.
	TransferClient struct {
		id                uuid.UUID
		ctx               context.Context
		cancel            context.CancelFunc
		callback          TransferCallbackFunc
		engine            *TransferEngine
		skipAcquire       bool          // Enable/disable the token acquisition logic.  Defaults to acquiring a token
		syncLevel         SyncLevel     // Policy for the client to synchronize data
		tokenLocation     string        // Location of a token file to use for transfers
		token             string        // Token that should be used for transfers
		fedToken          TokenProvider // Federation token; sent as access_token query param to origins (not to the director)
		cacheMode         bool          // When true, the client queries the director's origin endpoint (/api/v1.0/director/origin/)
		dryRun            bool          // Enable dry-run mode to display what would be transferred without actually doing it
		rejectCollections bool          // Reject downloads of collections when not in recursive mode
		work              chan *TransferJob
		closed            bool
		closeOnce         sync.Once
		prefObjServers    []*url.URL // holds any client-requested caches/origins
		results           chan *TransferResults
		finalResults      chan TransferResults
		setupResults      sync.Once
	}

	TransferOption                              = option.Interface
	identTransferOptionCaches                   struct{}
	identTransferOptionCallback                 struct{}
	identTransferOptionTokenLocation            struct{}
	identTransferOptionAcquireToken             struct{}
	identTransferOptionSourceAcquireToken       struct{}
	identTransferOptionDestinationAcquireToken  struct{}
	identTransferOptionToken                    struct{}
	identTransferOptionSourceTokenLocation      struct{}
	identTransferOptionSourceToken              struct{}
	identTransferOptionDestinationTokenLocation struct{}
	identTransferOptionDestinationToken         struct{}
	identTransferOptionSynchronize              struct{}
	identTransferOptionCollectionsUrl           struct{}
	identTransferOptionChecksums                struct{}
	identTransferOptionRequireChecksum          struct{}
	identTransferOptionRecursive                struct{}
	identTransferOptionDepth                    struct{}
	identTransferOptionWriter                   struct{}
	identTransferOptionReader                   struct{}
	identTransferOptionInPlace                  struct{}
	identTransferOptionDryRun                   struct{}
	identTransferOptionForcePrestageAPI         struct{}
	identTransferOptionByteRange                struct{}
	identTransferOptionMetadataChannel          struct{}
	identTransferOptionFedToken                 struct{}
	identTransferOptionCacheEmbeddedClientMode  struct{}
	identTransferOptionRequestId                struct{}
	identTransferOptionTokenProvider            struct{}
	identTransferOptionSourceTokenProvider      struct{}
	identTransferOptionNonInteractive           struct{}
	identTransferOptionStatUploadDestination    struct{}
	identTransferOptionRejectCollections        struct{}
	identTransferOptionObjectMetadata           struct{}
	identTransferOptionObjectMetadataFile       struct{}
	identTransferOptionObjectMetadataBlob       struct{}
	identTransferOptionObjectMetadataBlobFile   struct{}
	identTransferOptionObjectMetadataBlobType   struct{}

	// ByteRange specifies a byte range for partial object transfers
	// Start and End are inclusive byte offsets (0-indexed)
	// End of -1 means "to end of file"
	ByteRange struct {
		Start int64
		End   int64 // -1 means "to end of file"
	}

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
		// onFirstByte, if non-nil, fires exactly once when the first
		// non-empty write lands. Used by TagScheduler to promote a
		// transfer from the starving bucket to the active bucket.
		onFirstByte func()
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

// wantDigestValue builds the value for a Want-Digest header from a list
// of checksum types.  If the list is empty, the default algorithm is used.
func wantDigestValue(types []ChecksumType) string {
	if len(types) == 0 {
		return HttpDigestFromChecksum(AlgDefault)
	}
	val := ""
	for i, cksum := range types {
		if i > 0 {
			val += ","
		}
		val += HttpDigestFromChecksum(cksum)
	}
	return val
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

// createAllChecksumHashes creates hash writers for all known checksum types.
// Computing all algorithms during transfer allows the client to verify against
// whatever algorithm the server actually supports, even if it differs from
// what was originally requested.
func createAllChecksumHashes() (writers []io.Writer, types []ChecksumType) {
	known := KnownChecksumTypes()
	writers = make([]io.Writer, 0, len(known))
	types = make([]ChecksumType, 0, len(known))
	for _, t := range known {
		var w io.Writer
		switch t {
		case AlgCRC32:
			w = crc32.NewIEEE()
		case AlgCRC32C:
			w = crc32.New(crc32cTable)
		case AlgMD5:
			w = md5.New()
		case AlgSHA1:
			w = sha1.New()
		default:
			continue
		}
		writers = append(writers, w)
		types = append(types, t)
	}
	return
}

// checksumFallbacksSeen tracks which fallback checksum algorithms have
// already produced a warning this process, so repeated fallbacks (one per
// transfer in bulk workloads) log at debug level instead.
var checksumFallbacksSeen sync.Map

// serviceDigests remembers, per object-server host, which digest algorithms
// the service most recently reported. When the caller requests no specific
// checksum types, verification defaults to what this service is known to
// provide; first contact still asks for the platform default (crc32c).
var serviceDigests sync.Map // string (host) -> []ChecksumType

// rememberServiceDigests records the digest algorithms a service reported so
// later transfers to it can default their verification accordingly.
func rememberServiceDigests(host string, infos []ChecksumInfo) {
	if host == "" || len(infos) == 0 {
		return
	}
	types := make([]ChecksumType, 0, len(infos))
	for _, info := range infos {
		types = append(types, info.Algorithm)
	}
	serviceDigests.Store(host, types)
}

// defaultChecksumTypesForService returns the checksum types to verify against
// when the caller requested none: the set this service last reported, falling
// back to the global default for services we have not heard from yet.
func defaultChecksumTypesForService(host string) []ChecksumType {
	if v, ok := serviceDigests.Load(host); ok {
		if types, ok := v.([]ChecksumType); ok && len(types) > 0 {
			return types
		}
	}
	return []ChecksumType{AlgDefault}
}

// verifyTransferChecksums compares server-provided checksums against locally-computed ones.
//
// It tries to match any server-provided checksum against the computed values. If the match
// is for a type the client didn't explicitly request (e.g., the server returned MD5 when
// CRC32C was requested), a warning is logged about the fallback. Returns whether verification
// succeeded and any error (e.g., checksum mismatch or missing required checksum).
// quietFallbacks names algorithms whose use in place of the requested ones
// should not be reported as a surprise: the caller expressed no preference
// and this service is already known to provide these digests. It affects
// logging only -- verification itself is unchanged, as is the set of
// algorithms reported back to the caller in ClientChecksums.
func verifyTransferChecksums(
	allComputed map[ChecksumType][]byte,
	requestedTypes []ChecksumType,
	quietFallbacks []ChecksumType,
	serverChecksums []ChecksumInfo,
	requireChecksum bool,
	fields log.Fields,
) (verified bool, err error) {
	if len(serverChecksums) == 0 {
		if requireChecksum {
			log.WithFields(fields).Errorln(
				"Client requires checksum verification but server provided no checksums")
			return false, error_codes.NewTransfer_ChecksumMissingError(ErrServerChecksumMissing)
		}
		log.WithFields(fields).Debugln("Server did not provide any checksum values to compare")
		return false, nil
	}

	requestedSet := make(map[ChecksumType]bool, len(requestedTypes))
	for _, t := range requestedTypes {
		requestedSet[t] = true
	}
	quietSet := make(map[ChecksumType]bool, len(quietFallbacks))
	for _, t := range quietFallbacks {
		quietSet[t] = true
	}

	for _, serverCk := range serverChecksums {
		clientVal, ok := allComputed[serverCk.Algorithm]
		if !ok {
			continue
		}
		if !bytes.Equal(serverCk.Value, clientVal) {
			mismatchErr := &ChecksumMismatchError{
				Info: ChecksumInfo{
					Algorithm: serverCk.Algorithm,
					Value:     clientVal,
				},
				ServerValue: serverCk.Value,
			}
			return false, error_codes.NewTransfer_ChecksumMismatchError(mismatchErr)
		}
		if !requestedSet[serverCk.Algorithm] {
			if quietSet[serverCk.Algorithm] {
				// Not what we asked for, but what this service is known to
				// provide, and the caller expressed no preference.
				log.WithFields(fields).Debugf("Checksum %s matches: %s",
					HttpDigestFromChecksum(serverCk.Algorithm),
					checksumValueToHttpDigest(serverCk.Algorithm, serverCk.Value))
				return true, nil
			}
			// This fires for every transfer against a server that lacks the
			// requested digest (e.g. an origin that only computes MD5 when
			// CRC32C was requested) -- warn once per process per algorithm,
			// then drop to debug so bulk workloads aren't flooded.
			if _, seen := checksumFallbacksSeen.LoadOrStore(serverCk.Algorithm, struct{}{}); !seen {
				log.WithFields(fields).Warnf(
					"Requested checksum type(s) not provided by server; verified transfer using %s instead"+
						" (subsequent fallbacks will be logged at debug level)",
					HttpDigestFromChecksum(serverCk.Algorithm))
			} else {
				log.WithFields(fields).Debugf(
					"Requested checksum type(s) not provided by server; verified transfer using %s instead",
					HttpDigestFromChecksum(serverCk.Algorithm))
			}
		} else {
			log.WithFields(fields).Debugf("Checksum %s matches: %s",
				HttpDigestFromChecksum(serverCk.Algorithm),
				checksumValueToHttpDigest(serverCk.Algorithm, serverCk.Value))
		}
		return true, nil
	}

	// No server checksum matched any computed algorithm
	if requireChecksum {
		log.WithFields(fields).Errorln(
			"Client requires checksum verification but server returned only unsupported algorithms")
		return false, error_codes.NewTransfer_ChecksumMissingError(ErrServerChecksumMissing)
	}
	for _, checksumInfo := range serverChecksums {
		log.WithFields(fields).Debugf(
			"Server provided checksum %s=%s but algorithm not computable by client",
			HttpDigestFromChecksum(checksumInfo.Algorithm),
			checksumValueToHttpDigest(checksumInfo.Algorithm, checksumInfo.Value))
	}
	return false, nil
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
	if param.Client_DisableHttpProxy.GetBool() {
		return false
	}
	for _, envVar := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"} {
		if val, isSet := os.LookupEnv(envVar); isSet && val != "" {
			return true
		}
	}
	return false
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

// transferEngineConfig collects the settings assembled from the
// TransferEngineOption arguments handed to NewTransferEngine.
type transferEngineConfig struct {
	workerCount int
	scheduler   *TagScheduler
}

// TransferEngineOption customizes the engine returned by NewTransferEngine.
//
// Unlike TransferOption (an alias for the option package's untyped
// interface), engine options are a distinct function type; the two sets are
// therefore not interchangeable, so a per-transfer option such as
// WithCallback cannot be handed to the constructor and silently dropped.
type TransferEngineOption func(*transferEngineConfig)

// WithWorkerCount sets the number of transfer workers the engine launches,
// overriding the Client.WorkerCount default.  This lets embedded consumers
// (e.g. the cache) run with more concurrency than a command-line client
// would.  A workerCount <= 0 is an error at construction.
func WithWorkerCount(workerCount int) TransferEngineOption {
	return func(cfg *transferEngineConfig) {
		cfg.workerCount = workerCount
	}
}

// WithScheduler wires the engine to a TagScheduler that admits transfers
// into per-tag FIFOs and dispatches them to workers with a weighted random
// draw.  Callers that don't want per-tag fairness (e.g., single-user CLI
// transfers) should omit this option.
//
// The scheduler must have been created with NewTagScheduler; it is started
// by NewTransferEngine and stopped when the engine shuts down.  A nil
// scheduler is ignored.
func WithScheduler(scheduler *TagScheduler) TransferEngineOption {
	return func(cfg *transferEngineConfig) {
		cfg.scheduler = scheduler
	}
}

// NewTransferEngineWithWorkers creates a transfer engine with an explicit
// number of transfer workers.
//
// Deprecated: use NewTransferEngine with WithWorkerCount.
func NewTransferEngineWithWorkers(ctx context.Context, workerCount int) (te *TransferEngine, err error) {
	return NewTransferEngine(ctx, WithWorkerCount(workerCount))
}

// Returns a new transfer engine object whose lifetime is tied
// to the provided context.  Will launcher worker goroutines to
// handle the underlying transfers
//
// With no options the engine runs the client's configured number of workers
// (Client.WorkerCount) and hands transfers straight to them; see
// WithWorkerCount and WithScheduler to change either behavior.
func NewTransferEngine(ctx context.Context, opts ...TransferEngineOption) (te *TransferEngine, err error) {
	// If we did not initClient yet, we should fail to avoid unexpected/undesired behavior
	if !config.IsClientInitialized() {
		return nil, errors.New("client has not been initialized, unable to create transfer engine")
	}

	cfg := transferEngineConfig{workerCount: param.Client_WorkerCount.GetInt()}
	for _, opt := range opts {
		opt(&cfg)
	}
	// Validate before anything is allocated so a bad worker count cannot leak
	// the derived context or the URL cache's goroutine.
	if cfg.workerCount <= 0 {
		return nil, errors.New("worker count must be a positive integer")
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
		dirRespCache:       NewDirRespCache(5 * time.Minute),
		prestageAPISupport: make(map[string]bool),
	}
	for idx := 0; idx < cfg.workerCount; idx++ {
		egrp.Go(func() error {
			return runTransferWorker(ctx, te.files, te.results)
		})
	}
	te.workersActive = cfg.workerCount
	egrp.Go(te.runMux)
	egrp.Go(te.runJobHandler)

	if cfg.scheduler != nil {
		scheduler := cfg.scheduler
		te.scheduler = scheduler
		// Transfers still queued in the scheduler when it stops would
		// otherwise vanish without a result, leaving their jobs' active
		// counts permanently non-zero (and result waiters blocked until ctx
		// cancellation). Synthesize a failure result for each, exactly as
		// submitFile does for an admission rejection.
		scheduler.onDrop = func(file *clientTransferFile) {
			res := synthesizeRejectionResult(file, errors.New("transfer engine shut down before the transfer could be dispatched"))
			select {
			case te.results <- res:
			case <-te.ctx.Done():
			}
		}
		// The scheduler goroutine joins the engine's errgroup. It cannot make
		// Shutdown's egrp.Wait() hang: runJobHandler — also in that group —
		// calls scheduler.Stop() before closing te.files, so run() has already
		// returned by the time the group drains.
		scheduler.Start(te.ctx, te.egrp, te.files)
	}
	return
}

// submitFile hands a clientTransferFile off to the worker pool. When a
// scheduler is configured, the file goes through per-tag admission
// (which may return ErrTooManyRequests); otherwise it goes straight to
// the workers via te.files.
//
// On a scheduler rejection the function pushes a synthetic
// clientTransferResults to te.results so the job-completion machinery
// observes the failure exactly as it would for any other transfer
// error, then returns the rejection error to the caller.
func (te *TransferEngine) submitFile(ctx context.Context, file *clientTransferFile) error {
	if te.scheduler != nil {
		tag := deriveSchedulerTag(file)
		err := te.scheduler.Submit(ctx, tag, file)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrTooManyRequests) {
			select {
			case te.results <- synthesizeRejectionResult(file, err):
			case <-te.ctx.Done():
				return te.ctx.Err()
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return err
	}
	select {
	case te.files <- file:
		return nil
	case <-te.ctx.Done():
		return te.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// workerFailureResult builds the result a transfer worker reports for a file it
// declines to run.
//
// The job pointer matters: runMux dereferences it on every result it routes, to
// decrement the job's active-transfer count and decide whether the job is
// finished. A result without it is a nil dereference on the runMux goroutine,
// which takes the process down -- and does so *after* the result has already
// been handed to the client, so the crash does not even look related to the
// transfer that caused it.
func workerFailureResult(file *clientTransferFile, err error) TransferResults {
	if file.file == nil || file.file.job == nil {
		return TransferResults{JobId: file.jobId, Error: err}
	}
	res := newTransferResults(file.file.job)
	res.JobId = file.jobId
	res.Error = err
	return res
}

// uncountSubmission undoes the activeXfer increment a caller made just before
// a submission that then failed for a reason other than a scheduler shed.
//
// The count has to be taken before submitting: a shed produces a synthetic
// result immediately, and runMux both decrements on every result and retires
// the job when the count reaches zero, so counting afterwards would let the
// result be processed against a count that had not been taken yet. Any other
// failure produces no result at all, so the count has to come back off -- a
// job whose active count never drains is never finished, and the client's
// results channel stays open forever.
func (tj *TransferJob) uncountSubmission() {
	tj.activeXfer.Add(-1)
}

// deriveSchedulerTag chooses the tag under which a transfer is admitted.
// The tag is the hostname of the first attempt (the primary upstream
// origin); the key is opaque to the scheduler, so a username or prefix can
// be composed into it later without a scheduler change. We deliberately do
// not retag on failover: if the transfer moves from origin A to origin B
// mid-flight, it keeps A's slot for the duration of the transfer. This is a
// small fairness leak bounded by the transfer's lifetime.
//
// A transfer with no usable attempt URL falls back to the empty tag. Every
// such transfer then shares one tag and therefore one set of caps, so log
// it: callers are expected to have resolved at least one attempt by now, and
// silently collapsing them together would look like unexplained throttling.
func deriveSchedulerTag(file *clientTransferFile) string {
	if file == nil || file.file == nil {
		return ""
	}
	if len(file.file.attempts) > 0 && file.file.attempts[0].Url != nil {
		return file.file.attempts[0].Url.Host
	}
	log.Warningln("Transfer has no attempt URL to derive a scheduler tag from; it will share the fallback tag's share of the worker pool")
	return ""
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

// WithFedToken provides a federation token that the client sends as an
// access_token query parameter on the URL to the origin.  Unlike the
// user token (which goes in the Authorization header and is forwarded
// by the director via the authz query parameter), the federation token
// is NOT sent to the director — it is appended to the URL only after
// the director redirect, so it arrives at the origin as a query param.
// This is compatible with both Go-based and XRootD-based origins.
//
// The provider is queried for a fresh token on each transfer attempt,
// so callers can pass a refreshable TokenProvider (e.g. one backed by
// PersistentCache.getFedToken) to handle short-lived tokens that may
// expire during long downloads.
func WithFedToken(provider TokenProvider) TransferOption {
	return option.New(identTransferOptionFedToken{}, provider)
}

// WithTokenProvider supplies a dynamic producer for the destination (or, for
// non-copy transfers, the primary) token.  The provider is queried on every
// token request, so callers can back it with a refreshable source such as an
// encrypted credential store.
func WithTokenProvider(provider TokenProvider) TransferOption {
	return option.New(identTransferOptionTokenProvider{}, provider)
}

// WithSourceTokenProvider supplies a dynamic producer for the source token of a
// third-party-copy transfer.  For a get operation it provides the primary
// token instead.
func WithSourceTokenProvider(provider TokenProvider) TransferOption {
	return option.New(identTransferOptionSourceTokenProvider{}, provider)
}

// Create an option to provide a source token for a third-party-copy transfer
func WithSourceToken(token string) TransferOption {
	return option.New(identTransferOptionSourceToken{}, token)
}

// Create an option to provide a source token location for a third-party-copy transfer
func WithSourceTokenLocation(location string) TransferOption {
	return option.New(identTransferOptionSourceTokenLocation{}, location)
}

// WithDestinationToken provides a token for the destination server in a
// third-party-copy transfer.  For get operations, this is a no-op; for put
// operations it behaves identically to WithToken.
func WithDestinationToken(token string) TransferOption {
	return option.New(identTransferOptionDestinationToken{}, token)
}

// WithDestinationTokenLocation provides a token file for the destination
// server in a third-party-copy transfer.  For get operations, this is a
// no-op; for put operations it behaves identically to WithTokenLocation.
func WithDestinationTokenLocation(location string) TransferOption {
	return option.New(identTransferOptionDestinationTokenLocation{}, location)
}

// WithStatUploadDestination tells DoStat that the path being stat'ed is the
// destination of a pending upload rather than a source to be read.  This
// changes two things: the Director is queried with PUT, so the stat runs
// against origins that accept writes instead of against caches, and
// destination-role token options (WithDestinationToken,
// WithDestinationTokenLocation) apply instead of source-role ones.
//
// Callers pre-flighting an upload destination must set this.  A GET-flavored
// stat would send the caller's write credential to every cache in the
// Director's response, and caches cannot answer for a namespace that grants
// writes without reads.
func WithStatUploadDestination(enable bool) TransferOption {
	return option.New(identTransferOptionStatUploadDestination{}, enable)
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

// WithObjectMetadata attaches a map of uploader-supplied fields to an
// upload job. When non-empty, the resulting PUT carries an
// X-Pelican-Object-Metadata header whose value is the RFC 9651
// Structured Fields rendering of the map (see object_metadata.go).
//
// Values must be scalars: string, bool, int / int64, or float64. The
// keys "path", "size", "etag", and "created_at" are reserved by the
// origin and refused at validation time. The map is propagated to
// every transferFile produced by a recursive upload.
func WithObjectMetadata(fields map[string]any) TransferOption {
	return option.New(identTransferOptionObjectMetadata{}, fields)
}

// WithObjectMetadataFile is the file-shaped sibling of WithObjectMetadata.
// The supplied path must point to a JSON object whose top-level keys
// are scalar (string / number / boolean) values. The file is read
// and validated lazily inside NewTransferJob's option-apply pass,
// so a malformed file or unreadable path surfaces as an error from
// NewTransferJob (and therefore from DoPut) rather than at upload
// time. The same reserved-key rules and value-type restrictions
// described on WithObjectMetadata apply.
//
// If both WithObjectMetadata and WithObjectMetadataFile are supplied,
// later options win — matching the option-application order used by
// every other With…() helper here.
func WithObjectMetadataFile(path string) TransferOption {
	return option.New(identTransferOptionObjectMetadataFile{}, path)
}

// WithObjectMetadataBlob attaches an opaque metadata blob to an
// upload. When non-empty, the upload PUT switches from raw to
// multipart/form-data with two parts: the metadata blob first, the
// object body second. The origin's multipart middleware reads the
// blob into memory (capped by Origin.Metadata.MaxMetadataBytes),
// streams the object part through the existing POSC pipeline, and
// forwards the blob byte-for-byte to the configured metadata
// endpoint as the second part of a multipart/related body.
//
// `contentType` is the on-the-wire Content-Type a receiver sees;
// pass an empty string to default to "application/octet-stream".
// Reserved field names ("metadata", "object" by default) are
// configured on the origin and are not visible to callers — the
// client always sends the metadata part with the origin's
// configured metadata-part name.
func WithObjectMetadataBlob(body []byte, contentType string) TransferOption {
	// Defensive copy so the caller can recycle the byte slice.
	cpy := append([]byte(nil), body...)
	return option.New(identTransferOptionObjectMetadataBlob{}, objectMetadataBlob{
		body:        cpy,
		contentType: contentType,
	})
}

// WithObjectMetadataBlobFile is the file-shaped sibling of
// WithObjectMetadataBlob. The blob is read lazily during
// NewTransferJob's option-apply pass; an unreadable path surfaces
// as an error from DoPut before any network I/O. The blob's
// Content-Type is sniffed from the file extension (".xml" ⇒
// application/xml, ".json" ⇒ application/json, …) and may be
// overridden via WithObjectMetadataContentType.
func WithObjectMetadataBlobFile(path string) TransferOption {
	return option.New(identTransferOptionObjectMetadataBlobFile{}, path)
}

// WithObjectMetadataContentType overrides the Content-Type used for
// the metadata blob supplied via WithObjectMetadataBlobFile. No
// effect on WithObjectMetadataBlob (which takes the content type as
// a constructor argument). Last-supplied wins if both
// WithObjectMetadataContentType and WithObjectMetadataBlob /
// WithObjectMetadataBlobFile are used.
func WithObjectMetadataContentType(contentType string) TransferOption {
	return option.New(identTransferOptionObjectMetadataBlobType{}, contentType)
}

// Create an option to specify the token acquisition logic
//
// Token acquisition (e.g., using OAuth2 to get a token when one
// isn't found in the environment) defaults to `true` but can be
// disabled with this options
func WithAcquireToken(enable bool) TransferOption {
	return option.New(identTransferOptionAcquireToken{}, enable)
}

// WithNonInteractive controls whether token acquisition may fall back to the
// interactive OAuth2 device-code flow.  When enabled (true), acquisition uses
// only cached, refreshable, or locally-generatable tokens and fails instead of
// prompting.  This is intended for callers without a controlling terminal,
// such as the client agent.
func WithNonInteractive(enable bool) TransferOption {
	return option.New(identTransferOptionNonInteractive{}, enable)
}

// WithSourceAcquireToken controls automatic token acquisition for the source
// side of a transfer.  For get operations this is equivalent to WithAcquireToken;
// for put operations it is a no-op.
func WithSourceAcquireToken(enable bool) TransferOption {
	return option.New(identTransferOptionSourceAcquireToken{}, enable)
}

// WithDestinationAcquireToken controls automatic token acquisition for the
// destination side of a transfer.  For put operations this is equivalent to
// WithAcquireToken; for get operations it is a no-op.
func WithDestinationAcquireToken(enable bool) TransferOption {
	return option.New(identTransferOptionDestinationAcquireToken{}, enable)
}

// applyTokenOptions processes token-related transfer options and applies them
// to the provided token generators with correct precedence: role-specific
// options (WithSourceToken, WithDestinationToken, etc.) always override generic
// options (WithToken, WithTokenLocation, WithAcquireToken) regardless of the
// order they appear in the options slice.
//
// For a copy transfer, token is the destination token and srcToken is the
// source token; both must be non-nil.  For a non-copy transfer, only token
// is used (srcToken should be nil) and the upload flag determines whether
// source or destination options apply.
func applyTokenOptions(token, srcToken *tokenGenerator, upload bool, options []TransferOption) {
	isCopy := srcToken != nil

	// First pass: apply generic options.
	for _, opt := range options {
		switch opt.Ident() {
		case identTransferOptionToken{}:
			val := opt.Value().(string)
			token.SetToken(val)
			if isCopy {
				srcToken.SetToken(val)
			}
		case identTransferOptionTokenLocation{}:
			val := opt.Value().(string)
			token.SetTokenLocation(val)
			if isCopy {
				srcToken.SetTokenLocation(val)
			}
		case identTransferOptionAcquireToken{}:
			val := opt.Value().(bool)
			token.EnableAcquire = val
			if isCopy {
				srcToken.EnableAcquire = val
			}
		case identTransferOptionNonInteractive{}:
			val := opt.Value().(bool)
			token.nonInteractive = val
			if isCopy {
				srcToken.nonInteractive = val
			}
		}
	}

	// Second pass: apply role-specific options (these override generic).
	for _, opt := range options {
		switch opt.Ident() {
		case identTransferOptionSourceToken{}:
			if isCopy {
				srcToken.SetToken(opt.Value().(string))
			} else if !upload {
				token.SetToken(opt.Value().(string))
			}
		case identTransferOptionSourceTokenLocation{}:
			if isCopy {
				srcToken.SetTokenLocation(opt.Value().(string))
			} else if !upload {
				token.SetTokenLocation(opt.Value().(string))
			}
		case identTransferOptionSourceAcquireToken{}:
			if isCopy {
				srcToken.EnableAcquire = opt.Value().(bool)
			} else if !upload {
				token.EnableAcquire = opt.Value().(bool)
			}
		case identTransferOptionDestinationToken{}:
			if isCopy {
				token.SetToken(opt.Value().(string))
			} else if upload {
				token.SetToken(opt.Value().(string))
			}
		case identTransferOptionDestinationTokenLocation{}:
			if isCopy {
				token.SetTokenLocation(opt.Value().(string))
			} else if upload {
				token.SetTokenLocation(opt.Value().(string))
			}
		case identTransferOptionDestinationAcquireToken{}:
			if isCopy {
				token.EnableAcquire = opt.Value().(bool)
			} else if upload {
				token.EnableAcquire = opt.Value().(bool)
			}
		case identTransferOptionTokenProvider{}:
			// The destination (or primary, for non-copy transfers) token is
			// produced dynamically by an external provider.
			if p, ok := opt.Value().(TokenProvider); ok && p != nil {
				token.SetExternalProvider(p)
			}
		case identTransferOptionSourceTokenProvider{}:
			if p, ok := opt.Value().(TokenProvider); ok && p != nil {
				if isCopy {
					srcToken.SetExternalProvider(p)
				} else if !upload {
					token.SetExternalProvider(p)
				}
			}
		}
	}
}

// applyJobOptions processes the transfer options that are shared across
// NewTransferJob and NewCopyJob, writing them into the TransferJob.
// Options that are specific to a single job type (Writer, Reader, InPlace,
// ByteRange, ForcePrestageAPI) are left for the caller to handle.
func applyJobOptions(tj *TransferJob, options []TransferOption) {
	for _, opt := range options {
		switch opt.Ident() {
		case identTransferOptionCaches{}:
			tj.prefObjServers = opt.Value().([]*url.URL)
		case identTransferOptionCallback{}:
			tj.callback = opt.Value().(TransferCallbackFunc)
		case identTransferOptionFedToken{}:
			tj.fedToken = opt.Value().(TokenProvider)
		case identTransferOptionSynchronize{}:
			tj.syncLevel = opt.Value().(SyncLevel)
		case identTransferOptionChecksums{}:
			tj.requestedChecksums = opt.Value().([]ChecksumType)
		case identTransferOptionRequireChecksum{}:
			tj.requireChecksum = opt.Value().(bool)
		case identTransferOptionDryRun{}:
			tj.dryRun = opt.Value().(bool)
		case identTransferOptionMetadataChannel{}:
			tj.metadataChan = opt.Value().(chan<- TransferMetadata)
		case identTransferOptionCacheEmbeddedClientMode{}:
			tj.cacheMode = opt.Value().(bool)
		}
	}
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

// Create an option to specify a byte range for partial object downloads
//
// The start and end parameters are inclusive byte offsets (0-indexed).
// Use end=-1 to download from start to the end of the file.
// Example: WithByteRange(0, 1023) downloads the first 1024 bytes.
// Example: WithByteRange(1024, -1) downloads from byte 1024 to the end.
func WithByteRange(start, end int64) TransferOption {
	return option.New(identTransferOptionByteRange{}, ByteRange{Start: start, End: end})
}

// Create an option to receive early transfer metadata before data transfer begins
//
// When provided, the channel will receive a TransferMetadata struct containing
// information like ETag, Content-Length, and Last-Modified as soon as the server
// response headers are received, but before any data is transferred.
// This allows the caller to make decisions (e.g., verify ETag matches expected)
// before committing to the full transfer.
//
// The channel is optional (non-blocking send). If the channel is full or nil,
// the transfer will proceed without waiting.
// The caller should ensure the channel has buffer capacity of at least 1.
func WithMetadataChannel(ch chan<- TransferMetadata) TransferOption {
	return option.New(identTransferOptionMetadataChannel{}, ch)
}

// WithCacheEmbeddedClientMode controls whether the client runs in
// "cache-embedded" mode.  When enabled, the client queries the
// director's origin endpoint (/api/v1.0/director/origin/…) instead of
// the default shortcut endpoint.  This causes the director to redirect
// to origins rather than to caches, which is the correct behaviour when
// the transfer client is itself embedded inside a cache process.
//
// With it enabled, a GET for /test/file.txt is explicitly routed to the
// origin endpoint so the cache can fetch from the origin.  When disabled
// (enabled=false), the same GET is routed through the director's shortcut
// middleware, which redirects to a cache — the correct behaviour for a
// site-local cache, which appears to the federation as a client and
// fetches from other caches rather than directly from origins.
func WithCacheEmbeddedClientMode(enabled bool) TransferOption {
	return option.New(identTransferOptionCacheEmbeddedClientMode{}, enabled)
}

// WithRequestId sets a caller-supplied request ID that is propagated as
// the X-Pelican-JobId header on all HTTP requests made by this transfer.
// When set, it takes precedence over the HTCondor job-ad lookup.
// This is used by the cache to thread an incoming client's request ID
// through to the origin.
func WithRequestId(id string) TransferOption {
	return option.New(identTransferOptionRequestId{}, id)
}

// ContextWithRequestId returns a child context that carries the given
// request ID.  Downstream code can retrieve it with RequestIdFromContext.
func ContextWithRequestId(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIdCtxKey{}, id)
}

// RequestIdFromContext extracts a request ID previously stored with
// ContextWithRequestId.  Returns ("", false) if none is set.
func RequestIdFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIdCtxKey{}).(string)
	return id, ok && id != ""
}

// getJobId returns the request/job ID to use for the X-Pelican-JobId
// header.  It checks the context first (set by the cache when proxying
// a client request), then falls back to the HTCondor job-ad lookup.
func getJobId(ctx context.Context) (string, bool) {
	if id, ok := RequestIdFromContext(ctx); ok {
		return id, true
	}
	return searchJobAd(attrJobId)
}

// Create an option to reject collections during download.
//
// This is off by default, and deliberately so. Pelican's own machinery moves
// bytes through this same client -- the cache submits ordinary non-recursive
// download jobs for the blocks it is filling, and the HTCondor plugin does the
// same on behalf of a batch system -- and none of it has any use for the
// check: it is not interpreting a command line, and it pays for the endpoint
// probe the check needs. Turning this on by default would put that probe in
// front of every cache block fetch. The commands that do interpret a command
// line ask for it explicitly.
//
// When enabled, the client determines whether the remote path is a collection
// before downloading it, and fails the transfer if it is. This is for callers
// that mean to fetch a single object: without it, a collection is downloaded as
// whatever bytes the origin happens to serve for it, which is at best a
// listing and at worst an empty file.
//
// The check rides along with the endpoint probe every download already
// performs, so it does not add a round trip. It is fail-closed: if no endpoint
// will say whether the path is a collection, the transfer fails rather than
// proceeding. An endpoint that will not describe the path it is about to serve
// is not one to take a GET on faith from, and proceeding is how the caller ends
// up with a directory listing saved as though it were their object. The cost of
// that choice is that a download fails against an object server that answers
// neither a byte range nor a PROPFIND; see objectCached for the order those are
// tried in.
func WithRejectCollections(reject bool) TransferOption {
	return option.New(identTransferOptionRejectCollections{}, reject)
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
		case identTransferOptionFedToken{}:
			client.fedToken = option.Value().(TokenProvider)
		case identTransferOptionSynchronize{}:
			client.syncLevel = option.Value().(SyncLevel)
		case identTransferOptionDryRun{}:
			client.dryRun = option.Value().(bool)
		case identTransferOptionCacheEmbeddedClientMode{}:
			client.cacheMode = option.Value().(bool)
		case identTransferOptionRejectCollections{}:
			client.rejectCollections = option.Value().(bool)
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
	if te.scheduler != nil {
		te.scheduler.Stop()
	}
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
	// Retiring the client's last job -- or being handed a job that is no longer
	// in the list at all -- has to leave no entry behind. Storing an
	// empty-but-non-nil slice would make the client look permanently active:
	// the close-time check tests that entry against nil, so the results channel
	// would never close and Shutdown() would wait forever.
	if len((*activeJobs)[id]) <= 1 {
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
			// A job is finished once its lookup is done AND every transfer the
			// lookup handed to the workers has reported back.
			//
			// A lookup failure does not by itself end the job. A recursive walk
			// can fail partway through, after it has already submitted files
			// that are now in flight, and each of those still owes the client a
			// result. Retiring the job here on the strength of lookupErr alone
			// would close the client's results channel out from under them:
			// the next result to arrive is then a send on a closed channel,
			// which takes down the process.
			//
			// The same predicate is applied as each result arrives, so whichever
			// happens last -- the lookup finishing or the final result landing --
			// is what retires the job.
			if job.job.activeXfer.Load() == 0 {
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
						// The channel may have been closed already by
						// TransferClient.Close (which uses closeOnce).
						// Recover from the panic in that case.
						func() {
							defer func() { _ = recover() }()
							close(channel)
						}()
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
				// If a scheduler is configured it is a producer on
				// te.files; stop it first so the close below cannot
				// race with a scheduler dispatch and panic on a
				// send-on-closed channel. Stop() is idempotent —
				// engine.Shutdown() may call it again, harmlessly.
				if te.scheduler != nil {
					te.scheduler.Stop()
				}
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
	operation := config.TokenRead
	if upload {
		operation = config.TokenWrite
	}
	tj = &TransferJob{
		prefObjServers: tc.prefObjServers,
		recursive:      recursive,
		// A recursive job is asking for the collection, so it cannot also
		// refuse one. This covers the ?recursive query form too, which has
		// already been folded into `recursive` above.
		rejectCollections: tc.rejectCollections && !recursive,
		localPath:         localPath,
		remoteURL:         &copyUrl,
		callback:          tc.callback,
		skipAcquire:       tc.skipAcquire,
		dryRun:            tc.dryRun,
		syncLevel:         tc.syncLevel,
		xferType:          transferTypeDownload,
		uuid:              id,
		project:           project,
		token:             newTokenGenerator(&copyUrl, nil, operation, !tc.skipAcquire),
		inPlace:           false, // Default to using temporary files (rsync-style)
	}
	if upload {
		tj.xferType = transferTypeUpload
	}
	if tc.token != "" {
		tj.token.SetToken(tc.token)
	}
	tj.fedToken = tc.fedToken
	tj.cacheMode = tc.cacheMode
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
	}

	tj.ctx, tj.cancel = mergeCancel(ctx, tc.ctx)

	applyTokenOptions(tj.token, nil, upload, options)
	applyJobOptions(tj, options)

	// Handle options specific to direct (non-copy) transfers.
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionWriter{}:
			tj.writer = option.Value().(io.WriteCloser)
		case identTransferOptionReader{}:
			tj.reader = option.Value().(io.ReadCloser)
		case identTransferOptionInPlace{}:
			tj.inPlace = option.Value().(bool)
		case identTransferOptionByteRange{}:
			br := option.Value().(ByteRange)
			tj.byteRange = &br
		case identTransferOptionMetadataChannel{}:
			tj.metadataChan = option.Value().(chan<- TransferMetadata)
		case identTransferOptionCacheEmbeddedClientMode{}:
			tj.cacheMode = option.Value().(bool)
		case identTransferOptionRequestId{}:
			tj.requestId = option.Value().(string)
		case identTransferOptionRejectCollections{}:
			// Narrowed the same way as the client-wide setting above: a
			// recursive job is asking for the collection, so a per-job
			// override cannot refuse one.
			tj.rejectCollections = option.Value().(bool) && !recursive
		case identTransferOptionObjectMetadata{}:
			tj.objectMetadata = option.Value().(map[string]any)
		case identTransferOptionObjectMetadataFile{}:
			path := option.Value().(string)
			fields, ferr := loadObjectMetadataFile(path)
			if ferr != nil {
				err = errors.Wrap(ferr, "WithObjectMetadataFile")
				return
			}
			tj.objectMetadata = fields
		case identTransferOptionObjectMetadataBlob{}:
			blob := option.Value().(objectMetadataBlob)
			tj.objectMetadataBlob = &blob
		case identTransferOptionObjectMetadataBlobFile{}:
			path := option.Value().(string)
			blob, ferr := loadObjectMetadataBlobFile(path)
			if ferr != nil {
				err = errors.Wrap(ferr, "WithObjectMetadataBlobFile")
				return
			}
			tj.objectMetadataBlob = blob
		case identTransferOptionObjectMetadataBlobType{}:
			ct := option.Value().(string)
			// Apply to whatever blob is currently set. If no blob
			// is set yet, allocate an empty placeholder so a later
			// WithObjectMetadataBlobFile / WithObjectMetadataBlob
			// can fill in the body. Apply order is last-wins.
			if tj.objectMetadataBlob == nil {
				tj.objectMetadataBlob = &objectMetadataBlob{}
			}
			tj.objectMetadataBlob.contentType = ct
		}
	}

	// Inject the request ID into the job's context so it propagates
	// through transferFile → downloadHTTP and friends.
	if tj.requestId != "" {
		tj.ctx = ContextWithRequestId(tj.ctx, tj.requestId)
	}

	httpMethod := http.MethodGet
	if upload {
		httpMethod = http.MethodPut
	}

	tj.directorUrl = copyUrl.FedInfo.DirectorEndpoint

	// Use the director response cache with singleflight coalescing for
	// concurrent jobs requesting the same object.  Note we cannot coalesce
	// at the namespace level because we don't know the namespace an object
	// is in a-priori.
	var dirResp server_structs.DirectorResponse
	directorFailed := false
	// With no director in the federation, nothing has told us yet whether this
	// namespace wants a credential -- the origin says so when it answers.  The
	// transfer therefore keeps its token generator either way, so that a
	// rejection carrying token hints has something to acquire onto.
	directorless := copyUrl.FedInfo.DirectorEndpoint == "" && copyUrl.FedInfo.DiscoveryEndpoint != ""
	copyUrlRef := &copyUrl
	dirFlavor := NewDirRespFlavor(httpMethod, tj.cacheMode, copyUrl.RawQuery)
	// A download against a directorless federation resolves locally and pays no
	// round trip: it addresses the object to the host the user named and lets
	// the origin's own rejection say what credential the namespace wants.  An
	// upload has no such second chance -- there is no hint retry on a PUT -- so
	// it still asks first.
	if directorless && !upload {
		dirResp, err = resolveForRequest(tj.ctx, &copyUrl, httpMethod, "", tj.cacheMode)
	} else if tc.engine != nil && tc.engine.dirRespCache != nil {
		dirResp, err = tc.engine.dirRespCache.LookupOrLoad(tj.ctx, copyUrl.FedInfo.DiscoveryEndpoint, dirFlavor, copyUrl.Path, func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			resp, qErr := getDirectorInfoForPath(ctx, copyUrlRef, httpMethod, "", tj.cacheMode)
			return resp, resp.XPelNsHdr.Namespace, qErr
		})
	} else {
		dirResp, err = getDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, "", tj.cacheMode)
	}
	if err != nil {
		// If director query failed but we have explicit caches, create a minimal response and continue
		if len(tj.prefObjServers) > 0 {
			log.Debugln("Director query failed but explicit caches provided, continuing with cache list")
			directorFailed = true
			// Create minimal director response structure
			dirResp = server_structs.DirectorResponse{
				ObjectServers: []*url.URL{},
			}
			tj.dirResp = dirResp
			// Assigned directly rather than through SetDirectorResponse: no
			// director answered, so this placeholder carries no authorization
			// metadata and must not be treated as though a director vouched
			// for it.  The named object servers do not get to supply that
			// metadata either -- they are not the federation's discovery host,
			// so canApplyTokenHint refuses their hints.
			tj.token.DirResp = &dirResp
			err = nil // Clear the error since we're continuing with explicit caches
		} else {
			// No explicit caches, treat this as a fatal error
			var sce *StatusCodeError
			if errors.As(err, &sce) {
				return
			}
			log.Errorln(err)
			err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", pUrl.String())
			return
		}
	} else {
		tj.dirResp = dirResp
		tj.token.SetDirectorResponse(&dirResp)
	}

	// For uploads or when director indicates token is required, get a token
	// If director failed but we have explicit caches, try to get token anyway
	if upload || (!directorFailed && dirResp.XPelNsHdr.RequireToken) || (directorFailed && len(tj.prefObjServers) > 0) || directorless {
		contents, err := tj.token.Get()
		if err != nil || contents == "" {
			// If director failed, token errors are not fatal - we'll try without token
			if directorFailed || directorless {
				log.Debugln("Could not acquire token, will attempt transfer without token")
			} else {
				return nil, errors.Wrap(err, "failed to get token for transfer")
			}
		}

		// The director response may change if it's given a token; let's repeat the query.
		// Skip re-query if the director already failed, or if there is no
		// director to re-query.
		if contents != "" && !directorFailed && !directorless {
			// A director may answer differently once it sees a credential,
			// so this asks again -- but the answer holds for every object
			// in the namespace that this same credential reaches, and a
			// token-protected namespace would otherwise spend a director
			// round trip on every single transfer.  Cache it under a
			// credential-scoped flavor: another token (or none) keys
			// elsewhere and never receives this answer.
			authFlavor := dirFlavor.WithCredential(contents)
			if tc.engine != nil && tc.engine.dirRespCache != nil {
				dirResp, err = tc.engine.dirRespCache.LookupOrLoad(tj.ctx, copyUrl.FedInfo.DiscoveryEndpoint, authFlavor, copyUrl.Path, func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
					resp, qErr := getDirectorInfoForPath(ctx, copyUrlRef, httpMethod, contents, tj.cacheMode)
					return resp, resp.XPelNsHdr.Namespace, qErr
				})
			} else {
				dirResp, err = getDirectorInfoForPath(tj.ctx, &copyUrl, httpMethod, contents, tj.cacheMode)
			}
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
			tj.token.SetDirectorResponse(&dirResp)
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
		token:          NewTokenGenerator(&copyUrl, nil, config.TokenRead, !tc.skipAcquire),
	}
	if tc.token != "" {
		tj.token.SetToken(tc.token)
	}
	tj.fedToken = tc.fedToken
	if tc.tokenLocation != "" {
		tj.token.SetTokenLocation(tc.tokenLocation)
	}

	tj.ctx, tj.cancel = mergeCancel(ctx, tc.ctx)

	applyTokenOptions(tj.token, nil, false, options)
	applyJobOptions(tj, options)

	// Handle the option specific to prestage transfers.
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionForcePrestageAPI{}:
			tj.forcePrestageAPI = option.Value().(bool)
		}
	}

	tj.directorUrl = pelicanURL.FedInfo.DirectorEndpoint

	var dirResp server_structs.DirectorResponse
	if tc.engine != nil && tc.engine.dirRespCache != nil {
		dirResp, err = tc.engine.dirRespCache.LookupOrLoad(tj.ctx, pelicanURL.FedInfo.DiscoveryEndpoint, NewDirRespFlavor(http.MethodGet, false, pelicanURL.RawQuery), pelicanURL.Path, func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			resp, qErr := getDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, "", false)
			return resp, resp.XPelNsHdr.Namespace, qErr
		})
	} else {
		dirResp, err = getDirectorInfoForPath(tj.ctx, pelicanURL, http.MethodGet, "", false)
	}
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
		return
	}
	tj.dirResp = dirResp
	tj.token.SetDirectorResponse(&dirResp)

	log.Debugln("Dir resp:", dirResp.XPelNsHdr)
	if dirResp.XPelNsHdr.RequireToken {
		contents, err := tj.token.Get()
		if err != nil || contents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = getDirectorInfoForPath(tj.ctx, pelicanURL, http.MethodGet, contents, false)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
				return nil, err
			}
			tj.dirResp = dirResp
			tj.token.SetDirectorResponse(&dirResp)
			if tc.engine != nil && tc.engine.dirRespCache != nil && dirResp.XPelNsHdr.Namespace != "" {
				tc.engine.dirRespCache.Store(pelicanURL.FedInfo.DiscoveryEndpoint, NewDirRespFlavor(http.MethodGet, false, pelicanURL.RawQuery).WithCredential(contents), dirResp.XPelNsHdr.Namespace, pelicanURL.Path, dirResp)
			}
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
		// Narrowed the same way NewTransferJob narrows it: a recursive copy is
		// asking for the collection. For a copy the guard is about the source,
		// which is what gets read.
		rejectCollections: tc.rejectCollections && !recursive,
		remoteURL:         &copyDestUrl,
		callback:          tc.callback,
		skipAcquire:       tc.skipAcquire,
		dryRun:            tc.dryRun,
		syncLevel:         tc.syncLevel,
		xferType:          transferTypeCopy,
		uuid:              id,
		project:           project,
		token:             NewTokenGenerator(&copyDestUrl, nil, config.TokenSharedWrite, !tc.skipAcquire),
	}
	tj.fedToken = tc.fedToken
	tj.cacheMode = tc.cacheMode
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

	applyTokenOptions(tj.token, tj.srcToken, false, options)
	applyJobOptions(tj, options)

	// Resolve the destination director information, using the cache when available.
	// First try COPY verb so the director filters to origins that support TPC.
	// If the director doesn't know about COPY (old director) or no origins support
	// it, fall back to PUT which matches the pre-TPC behavior.
	tj.directorUrl = copyDestUrl.FedInfo.DirectorEndpoint
	var dirResp server_structs.DirectorResponse
	destVerb := "COPY"
	// The TPC destination flavor, pinned to COPY even when the query below
	// falls back to PUT: the fallback is part of answering "where may this
	// third-party copy write?", and only this resolution asks that question.
	// Pinning it keeps lookup and store on one key, and keeps the entry from
	// ever answering a plain PUT -- which would be a different question.
	destFlavor := NewDirRespFlavor(destVerb, false, copyDestUrl.RawQuery)
	if tc.engine != nil && tc.engine.dirRespCache != nil {
		copyDestUrlRef := &copyDestUrl
		dirResp, err = tc.engine.dirRespCache.LookupOrLoad(tj.ctx, copyDestUrl.FedInfo.DiscoveryEndpoint, destFlavor, copyDestUrl.Path, func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			resp, qErr := getDirectorInfoForPath(ctx, copyDestUrlRef, destVerb, "", false)
			if qErr != nil {
				// Fall back to PUT if COPY is not supported by the director
				destVerb = http.MethodPut
				resp, qErr = getDirectorInfoForPath(ctx, copyDestUrlRef, destVerb, "", false)
			}
			return resp, resp.XPelNsHdr.Namespace, qErr
		})
	} else {
		dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyDestUrl, destVerb, "")
		if err != nil {
			// Fall back to PUT if COPY is not supported by the director
			destVerb = http.MethodPut
			dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyDestUrl, destVerb, "")
		}
	}
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for destination URL %s", dest.String())
		return
	}
	tj.destDirResp = dirResp
	tj.token.SetDirectorResponse(&dirResp)

	// Acquire token for the destination if needed
	if dirResp.XPelNsHdr.RequireToken {
		contents, tErr := tj.token.Get()
		if tErr != nil || contents == "" {
			err = errors.Wrap(tErr, "failed to get token for copy destination")
			return nil, err
		}
		if contents != "" {
			dirResp, err = GetDirectorInfoForPath(tj.ctx, &copyDestUrl, destVerb, contents)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for destination URL %s", dest.String())
				return nil, err
			}
			tj.destDirResp = dirResp
			tj.token.SetDirectorResponse(&dirResp)
			if tc.engine != nil && tc.engine.dirRespCache != nil && dirResp.XPelNsHdr.Namespace != "" {
				tc.engine.dirRespCache.Store(copyDestUrl.FedInfo.DiscoveryEndpoint, destFlavor.WithCredential(contents), dirResp.XPelNsHdr.Namespace, copyDestUrl.Path, dirResp)
			}
		}
	}

	// Resolve the source director information, using the cache when available.
	var srcDirResp server_structs.DirectorResponse
	if tc.engine != nil && tc.engine.dirRespCache != nil {
		copySrcUrlRef := &copySrcUrl
		srcFlavor := NewDirRespFlavor(http.MethodGet, false, copySrcUrl.RawQuery)
		srcDirResp, err = tc.engine.dirRespCache.LookupOrLoad(tj.ctx, copySrcUrl.FedInfo.DiscoveryEndpoint, srcFlavor, copySrcUrl.Path, func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			resp, qErr := getDirectorInfoForPath(ctx, copySrcUrlRef, http.MethodGet, "", false)
			return resp, resp.XPelNsHdr.Namespace, qErr
		})
	} else {
		srcDirResp, err = GetDirectorInfoForPath(tj.ctx, &copySrcUrl, http.MethodGet, "")
	}
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for source URL %s", src.String())
		return
	}
	tj.srcDirResp = srcDirResp
	tj.srcToken.SetDirectorResponse(&srcDirResp)

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
			tj.srcToken.SetDirectorResponse(&srcDirResp)
			if tc.engine != nil && tc.engine.dirRespCache != nil && srcDirResp.XPelNsHdr.Namespace != "" {
				tc.engine.dirRespCache.Store(copySrcUrl.FedInfo.DiscoveryEndpoint, NewDirRespFlavor(http.MethodGet, false, copySrcUrl.RawQuery).WithCredential(contents), srcDirResp.XPelNsHdr.Namespace, copySrcUrl.Path, srcDirResp)
			}
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
	token := NewTokenGenerator(pelicanURL, nil, config.TokenRead, true)
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

	var dirResp server_structs.DirectorResponse
	// The probe below is itself the question a metadata query would have asked,
	// so a directorless federation is not asked twice.
	directorless := pelicanURL.FedInfo.DirectorEndpoint == "" && pelicanURL.FedInfo.DiscoveryEndpoint != ""
	if directorless {
		dirResp, err = resolveForRequest(ctx, pelicanURL, http.MethodGet, "", false)
	} else if tc.engine != nil && tc.engine.dirRespCache != nil {
		dirResp, err = tc.engine.dirRespCache.LookupOrLoad(ctx, pelicanURL.FedInfo.DiscoveryEndpoint, NewDirRespFlavor(http.MethodGet, false, pelicanURL.RawQuery), pelicanURL.Path, func(lCtx context.Context) (server_structs.DirectorResponse, string, error) {
			resp, qErr := getDirectorInfoForPath(lCtx, pelicanURL, http.MethodGet, "", false)
			return resp, resp.XPelNsHdr.Namespace, qErr
		})
	} else {
		dirResp, err = getDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, "", false)
	}
	if err != nil {
		log.Errorln(err)
		err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
		return
	}
	token.SetDirectorResponse(&dirResp)

	if dirResp.XPelNsHdr.RequireToken {
		var contents string
		contents, err = token.Get()
		if err != nil || contents == "" {
			err = errors.Wrap(err, "failed to get token for cache info query")
			return
		}

		// The director response may change if it's given a token; let's repeat the query.
		if contents != "" {
			dirResp, err = getDirectorInfoForPath(ctx, pelicanURL, http.MethodGet, contents, false)
			if err != nil {
				log.Errorln(err)
				err = errors.Wrapf(err, "failed to get namespace information for remote URL %s", remoteUrl.String())
				return
			}
			token.SetDirectorResponse(&dirResp)
			if tc.engine != nil && tc.engine.dirRespCache != nil && dirResp.XPelNsHdr.Namespace != "" {
				tc.engine.dirRespCache.Store(pelicanURL.FedInfo.DiscoveryEndpoint, NewDirRespFlavor(http.MethodGet, false, pelicanURL.RawQuery).WithCredential(contents), dirResp.XPelNsHdr.Namespace, pelicanURL.Path, dirResp)
			}
		}
	} else if !directorless {
		// Nothing has asked yet, so "no token required" is not a fact; keep the
		// generator so a refusal carrying hints can acquire onto it.
		token = nil
	}

	var sortedServers []*url.URL
	sortedServers, _, err = generateSortedObjServers(dirResp, prefObjServers)
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

	age, size, _, _, err = objectCached(ctx, &cacheUrl, token, false)
	return
}

// Close the transfer client object
//
// Any subsequent job submissions will cause a panic
func (tc *TransferClient) Close() {
	tc.closeOnce.Do(func() {
		log.Debugln("Closing transfer client", tc.id.String())
		tc.closed = true
		// TODO(bbockelm):
		// It's not obvious from the API design but the engine shutdown
		// will _also_ close tc.work (directly, bypassing the `closeOnce`),
		// causing a panic if the client is manually closed afterward.  This
		// could be fixed to avoid confusion around who is supposed to close
		// what.  For now, to avoid panic's for users, we simply recover.
		// recover from the panic if that happened.
		defer func() { _ = recover() }()
		close(tc.work)
	})
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

// Generate the list of object servers (caches or origins) that will be attempted for a single transfer job and populate this info
// in the slice of transferAttemptDetails structs. The incoming sortedObjectServers list is expected to be deduplicated by
// generateSortedObjServers, except that intentional duplicates among the user's preferred caches are preserved (a user may list
// the same cache more than once to force repeated attempts); those duplicates are honored here rather than collapsed.
// nPreferred indicates how many entries at the start of sortedObjectServers came from the user's PreferredCaches
// configuration; those entries will have Preferred=true in the returned details.
//
// directorServersToTry caps only the director-discovered servers. Every user-supplied preferred cache is always tried:
// the user asked for those endpoints explicitly, so we honor the full list in order rather than truncating it.
func getObjectServersToTry(sortedObjectServers []string, job *TransferJob, directorServersToTry int, packOption string, nPreferred int) (transfers []transferAttemptDetails) {
	oServers := make([]string, 0)

	directorListed := 0
	for idx, oServer := range sortedObjectServers {
		isPreferred := idx < nPreferred
		if !isPreferred {
			// The attempt cap applies only to director-discovered servers; preferred caches
			// (which all sort ahead of director servers) are exempt and always included.
			if directorListed == directorServersToTry {
				break
			}
			directorListed++
		}
		oServers = append(oServers, oServer)
		td := transferDetailsOptions{
			NeedsToken: job.dirResp.XPelNsHdr.RequireToken,
			PackOption: packOption,
		}
		newTransfers := generateTransferDetails(oServer, td)
		for i := range newTransfers {
			newTransfers[i].Preferred = isPreferred
		}
		transfers = append(transfers, newTransfers...)
	}
	log.Debugln("Trying the object servers:", oServers)
	return transfers
}

// Take a transfer job and produce one or more transfer file requests.
// The transfer file requests are sent to be processed via the engine
// buildUploadTransfers returns the transfer attempt for an upload job.
func buildUploadTransfers(job *clientTransferJob, packOption string) ([]transferAttemptDetails, error) {
	if len(job.job.dirResp.ObjectServers) == 0 {
		return nil, errors.New("No origins found for upload")
	}
	return []transferAttemptDetails{{
		Url:        job.job.dirResp.ObjectServers[0],
		PackOption: packOption,
	}}, nil
}

// buildCopyTransfers returns the source-server transfer attempts for a TPC copy job.
func buildCopyTransfers(job *clientTransferJob) ([]transferAttemptDetails, error) {
	sortedSrcServers, _, err := generateSortedObjServers(job.job.srcDirResp, job.job.prefObjServers)
	if err != nil {
		log.Errorln("Failed to get source servers for copy:", err)
		return nil, err
	}
	var transfers []transferAttemptDetails
	for _, srcServer := range sortedSrcServers {
		srcServerUrl := *srcServer
		srcServerUrl.Path = path.Clean(job.job.srcURL.Path)
		copiedUrl := srcServerUrl
		transfers = append(transfers, transferAttemptDetails{
			Url: &copiedUrl,
		})
	}
	if len(transfers) == 0 {
		return nil, errors.New("no source servers found for copy")
	}
	return transfers, nil
}

// buildDownloadTransfers returns the transfer attempts for a download or prestage job.
func buildDownloadTransfers(job *clientTransferJob, packOption string) ([]transferAttemptDetails, error) {
	sortedServers, nPreferred, err := generateSortedObjServers(job.job.dirResp, job.job.prefObjServers)
	if err != nil {
		log.Errorln("Failed to get namespaced caches (treated as non-fatal):", err)
	}
	var sortedServerStrings []string
	for _, serverUrl := range sortedServers {
		sortedServerStrings = append(sortedServerStrings, serverUrl.String())
	}

	// The cap applies only to director-discovered servers; all preferred caches are always tried.
	log.Debugf("Trying all %d preferred object servers plus up to %d director-provided servers", nPreferred, ObjectServersToTry)
	transfers := getObjectServersToTry(sortedServerStrings, job.job, ObjectServersToTry, packOption, nPreferred)

	if len(transfers) > 0 {
		log.Traceln("First transfer in list:", transfers[0].Url)
	} else {
		return nil, errors.New("No transfers possible as no object servers were found")
	}
	return transfers, nil
}

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

	// For copy jobs, we will also build the source URL
	var srcUrl *url.URL

	var transfers []transferAttemptDetails
	switch job.job.xferType {
	case transferTypeUpload:
		transfers, err = buildUploadTransfers(job, packOption)
	case transferTypeCopy:
		srcUrl = &url.URL{Path: job.job.srcURL.Path, Scheme: job.job.srcURL.Scheme, Host: job.job.srcURL.Host}
		transfers, err = buildCopyTransfers(job)
	default:
		transfers, err = buildDownloadTransfers(job, packOption)
	}
	if err != nil {
		return
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
			return te.walkDirUpload(job, transfers, job.job.localPath)
		} else if job.job.xferType == transferTypeDownload {
			// For recursive downloads, stat the remote path.
			var statInfo FileInfo
			var statErr error
			var pelicanUrl *pelican_url.PelicanURL
			pelicanUrl, err = pelican_url.Parse(remoteUrl.String(), nil, nil)
			if err != nil {
				return errors.Wrap(err, "failed to parse remote URL for recursive download")
			}
			if job.job.dirResp.XPelNsHdr.CollectionsUrl != nil {
				statInfo, statErr = statHttp(job.job.ctx, pelicanUrl, job.job.dirResp, job.job.token, job.job.fedToken, true)
			} else {
				statInfo, statErr = statHttp(job.job.ctx, pelicanUrl, job.job.dirResp, job.job.token, job.job.fedToken)
			}
			if statErr != nil {
				return errors.Wrap(statErr, "failed to stat remote path for recursive download")
			}
			if statInfo.IsCollection {
				return te.walkDirDownload(job, transfers, remoteUrl)
			}
		} else if job.job.xferType == transferTypeCopy {
			// For copy, stat the SOURCE to see if it's a collection.
			// If it is, walk the source directory listing and emit individual TPC copy jobs.
			var srcPelicanUrl *pelican_url.PelicanURL
			srcPelicanUrl, err = pelican_url.Parse(srcUrl.String(), nil, nil)
			if err != nil {
				return errors.Wrap(err, "failed to parse source URL for recursive copy")
			}
			var statInfo FileInfo
			if job.job.srcDirResp.XPelNsHdr.CollectionsUrl != nil {
				statInfo, err = statHttp(job.job.ctx, srcPelicanUrl, job.job.srcDirResp, job.job.srcToken, nil, true)
			} else {
				statInfo, err = statHttp(job.job.ctx, srcPelicanUrl, job.job.srcDirResp, job.job.srcToken, nil)
			}
			if err != nil {
				return errors.Wrap(err, "failed to stat source path for recursive copy")
			}

			if statInfo.IsCollection {
				return te.walkDirCopy(job, transfers, srcUrl)
			}
		}
		log.Debugln("Remote path is not a collection; proceeding with single file transfer")
	} else if job.job.xferType == transferTypePrestage {
		// For prestage, stat using only the collectionsUrl (origin).
		if job.job.dirResp.XPelNsHdr.CollectionsUrl != nil {
			var statInfo FileInfo
			var pelicanUrl *pelican_url.PelicanURL
			pelicanUrl, err = pelican_url.Parse(remoteUrl.String(), nil, nil)
			if err != nil {
				return
			}
			statInfo, err = statHttp(job.job.ctx, pelicanUrl, job.job.dirResp, job.job.token, job.job.fedToken, true)
			if err != nil {
				err = errors.Wrap(err, "failed to stat object to prestage")
				return
			}
			if statInfo.IsCollection {
				return te.walkDirDownload(job, transfers, remoteUrl)
			}
		}
	} else if job.job.rejectCollections && job.job.xferType == transferTypeCopy {
		// A third-party copy reads the source the same way a download does, so
		// it deserves the same refusal -- but it never reaches downloadObject,
		// where the refusal for ordinary downloads lives, because the bytes
		// move between two remote servers. Stat the source directly. The
		// recursive branch above already stats it for a different reason, so
		// this costs a non-recursive copy the one request that branch would
		// have spent anyway.
		var srcPelicanUrl *pelican_url.PelicanURL
		srcPelicanUrl, err = pelican_url.Parse(srcUrl.String(), nil, nil)
		if err != nil {
			return errors.Wrap(err, "failed to parse source URL for copy")
		}
		var statInfo FileInfo
		if job.job.srcDirResp.XPelNsHdr.CollectionsUrl != nil {
			statInfo, err = statHttp(job.job.ctx, srcPelicanUrl, job.job.srcDirResp, job.job.srcToken, nil, true)
		} else {
			statInfo, err = statHttp(job.job.ctx, srcPelicanUrl, job.job.srcDirResp, job.job.srcToken, nil)
		}
		if err != nil {
			return error_codes.NewResolutionError(
				errors.Wrapf(err, "could not confirm whether source %s is a collection; refusing to copy", srcUrl.Path),
			)
		}
		if statInfo.IsCollection {
			return error_codes.NewParameterError(
				errors.Errorf("source path %s is a collection; use a recursive transfer (--recursive on the command line) to copy its contents", srcUrl.Path),
			)
		}
	}

	log.Debugln("Queuing transfer for object", remoteUrl.String(), "with first transfer URL:", transfers[0].Url.String())
	// Counted before submission: a scheduler rejection produces a synthetic
	// result right away, and runMux decrements on every result, so counting
	// afterwards would race that result's delivery.
	job.job.activeXfer.Add(1)
	submitErr := te.submitFile(job.job.ctx, &clientTransferFile{
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
			fedToken:           job.job.fedToken,
			attempts:           transfers,
			project:            job.job.project,
			writer:             job.job.writer,
			reader:             job.job.reader,
			byteRange:          job.job.byteRange,
			metadataChan:       job.job.metadataChan,
			objectMetadata:     job.job.objectMetadata,
			objectMetadataBlob: job.job.objectMetadataBlob,
		},
	})
	if submitErr != nil {
		if errors.Is(submitErr, ErrTooManyRequests) {
			// submitFile already pushed a synthetic failure result for this
			// file, so the counts above are matched and the job completes
			// normally with a 429 result.
			log.Debugln("Scheduler rejected transfer for", remoteUrl.String(), ":", submitErr)
			return
		}
		// Nothing was queued and no result is coming, so this file must not
		// stay on the job's books.
		job.job.uncountSubmission()
		err = submitErr
		return
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
			// Wrap the per-file body in a closure so the scheduler's
			// schedDone hook (if any) fires exactly once per file via
			// defer, not once for the worker's entire lifetime.
			if err := runTransferWorkerFile(ctx, file, results); err != nil {
				return err
			}
		}
	}
}

// runTransferWorkerFile processes one file dequeued by a transfer
// worker. It always fires file.file.schedDone (if set) on exit.
// Returns a non-nil error only if the worker itself should exit (e.g.
// ctx cancellation while we were trying to write results).
func runTransferWorkerFile(ctx context.Context, file *clientTransferFile, results chan<- *clientTransferResults) error {
	if file.file != nil && file.file.schedDone != nil {
		schedDone := file.file.schedDone
		file.file.schedDone = nil
		defer schedDone()
	}
	if file.file.ctx.Err() == context.Canceled {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- &clientTransferResults{
			id:      file.uuid,
			results: workerFailureResult(file, file.file.ctx.Err()),
		}:
		}
		return nil
	}
	if file.file.err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- &clientTransferResults{
			id:      file.uuid,
			results: workerFailureResult(file, file.file.err),
		}:
		}
		return nil
	}
	var err error
	var transferResults TransferResults
	switch file.file.xferType {
	case transferTypeUpload, transferTypeCopy:
		// Both of these report their own first-byte signal to the scheduler
		// (see the schedFirstByte docs on transferFile), so they stay in the
		// "starving" bucket — and thus under the smaller starving cap — until
		// the destination proves it is responding.
		if file.file.xferType == transferTypeUpload {
			transferResults, err = uploadObject(file.file)
		} else {
			transferResults, err = copyHTTP(file.file)
		}
	default:
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
	if file.file.job != nil && file.file.job.dirResp.RedirectInfo != nil {
		transferResults.DirectorDecision = file.file.job.dirResp.RedirectInfo
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case results <- &clientTransferResults{id: file.uuid, results: transferResults}:
	}
	return nil
}

// attemptSorter pairs a responsiveness score with a transfer attempt for sorting.
type attemptSorter struct {
	good    int
	attempt transferAttemptDetails
}

// compareAttempts is the comparison function used by sortAttempts.
// Preferred (user-configured) servers always sort before director-provided servers.
// Within the same preference tier, servers are sorted by responsiveness (good values).
func compareAttempts(left attemptSorter, right attemptSorter) int {
	// Preferred servers always sort before director-provided (fallback) servers.
	if left.attempt.Preferred != right.attempt.Preferred {
		if left.attempt.Preferred {
			return -1
		}
		return 1
	}
	// Within the same preference tier, sort by responsiveness.
	if left.good > right.good {
		return -1
	}
	if left.good < right.good {
		return 1
	}
	return 0
}

// collectionCheckTimeout bounds the probe when its answer decides whether a
// download is refused. It is deliberately far longer than the budget for
// merely ordering endpoints: an answer that arrives late is still useful,
// whereas no answer at all fails the download outright. It remains a bound, so
// an unresponsive federation degrades to a refusal rather than hanging.
const collectionCheckTimeout = 10 * time.Second

// sortAttempts sees whether some of multiple potential attempts can be quickly
// eliminated.
//
// Attempts a HEAD against all the endpoints simultaneously.  Put any that don't
// respond within the probe budget behind those that do respond.
//
// wantCollectionInfo additionally reports whether the path names a collection.
// Asking for it changes three things: the per-endpoint probe learns the answer
// at no extra cost (see objectCached), a lone endpoint is still probed, where
// otherwise there would be nothing to sort and the function would return
// immediately, and the probe budget lengthens because the answer now decides
// whether the transfer happens at all.
func sortAttempts(ctx context.Context, path string, attempts []transferAttemptDetails, token *tokenGenerator, wantCollectionInfo bool) (size int64, collection collectionAnswer, results []transferAttemptDetails) {
	size = -1
	if len(attempts) < 2 && !wantCollectionInfo {
		results = attempts
		return
	}
	if len(attempts) == 0 {
		results = attempts
		return
	}
	type checkResults struct {
		idx  int
		size uint64
		age  int
		// answeredCollection distinguishes "this endpoint told us" from "this
		// endpoint did not": an unanswered question is not the same as a
		// negative answer, and the caller refuses the download rather than
		// guess.
		answeredCollection bool
		isCollection       bool
		err                error
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
	// Ranking endpoints and asking whether the path is a collection want
	// different budgets. A second is plenty to decide which cache to prefer,
	// and giving up on that is harmless -- the download proceeds against an
	// unsorted list. The collection answer is acted on, so abandoning it is
	// not harmless: the download the caller asked to have guarded fails for
	// want of an answer. A healthy endpoint answers a Depth-0 PROPFIND well
	// inside the longer budget, and a first success still cancels the rest, so
	// this only costs time when every endpoint is slow -- which is when the
	// answer is worth waiting for.
	probeTimeout := time.Second
	if wantCollectionInfo {
		probeTimeout = collectionCheckTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	for idx, transferEndpoint := range attempts {
		tUrl := *transferEndpoint.Url
		tUrl.Path = path
		unixSocket := transferEndpoint.UnixSocket

		go func(idx int, tUrl *url.URL) {
			// A unix:// endpoint is the local cache. Ranking it is pointless
			// -- it is always tried first -- and probing it with a ranged GET
			// would make it start filling the object we may be about to
			// refuse, so ordinarily it is skipped outright.
			if tUrl.Scheme == "unix" {
				if !wantCollectionInfo {
					headChan <- checkResults{idx, 0, -1, false, false, nil}
					return
				}
				// Skipping it is not an option once the answer is load
				// bearing: a client whose only object server is the local
				// cache would have nothing to refuse or allow on. The local
				// cache serves PROPFIND over the same socket, so ask it, and
				// ask it alone -- a PROPFIND starts no download.
				size, isCollection, propErr := propfindObject(ctx, tUrl, unixSocket, token)
				if propErr != nil {
					log.Debugln("PROPFIND of local cache socket", unixSocket, "went unanswered:", propErr)
					headChan <- checkResults{idx, 0, -1, false, false, nil}
					return
				}
				headChan <- checkResults{idx, uint64(max(size, 0)), -1, true, isCollection, nil}
				return
			}

			if age, size, answered, isCollection, err := objectCached(ctx, tUrl, token, wantCollectionInfo); err != nil {
				// The collection answer survives a failed probe: an endpoint
				// can describe the path accurately and still be unable to
				// serve it, and the answer is about the path.
				headChan <- checkResults{idx, 0, -1, answered, isCollection, err}
				return
			} else {
				headChan <- checkResults{idx, uint64(size), age, answered, isCollection, err}
			}

		}(idx, &tUrl)
	}
	// 1 -> success.
	// 0 -> pending.
	// -1 -> error.
	finished := make(map[int]int)
	for ctr := 0; ctr != len(attempts); ctr++ {
		result := <-headChan
		// Recorded before the health check below, because the two are
		// independent: any endpoint that answered the question answers it for
		// the object as a whole -- they are all describing the same path --
		// even if that same endpoint turned out not to be usable.
		if result.answeredCollection {
			collection.answered = true
			if result.isCollection {
				collection.isCollection = true
			}
		}
		// A shed probe is the one failure that says something about why the
		// question went unanswered, so it is kept rather than flattened in
		// with the rest. The first one is enough; they all mean "ask later".
		if result.err != nil && collection.throttleErr == nil && errors.Is(result.err, ErrTooManyRequests) {
			collection.throttleErr = result.err
		}
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
			// Cancelling the other probes discards whatever they were about to
			// say, which is fine when all they were deciding was sort order,
			// but not while the collection question is still open: the caller
			// refuses the download if nobody answers it, so silencing the
			// endpoints that might have is how a good download gets refused.
			if result.idx == 0 && result.err == nil && (!wantCollectionInfo || collection.answered) {
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
	// Preferred (user-configured) servers are never sorted after director-provided
	// servers, ensuring all preferred caches are tried before falling back to the
	// Director's choices.
	tmpResults := make([]attemptSorter, len(attempts))
	for idx, attempt := range attempts {
		tmpResults[idx] = attemptSorter{finished[idx], attempt}
	}
	results = make([]transferAttemptDetails, len(attempts))
	slices.SortStableFunc(tmpResults, compareAttempts)
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
	// 'downloaded' tracks bytes received locally; it starts at 0 even for ranged downloads.
	var downloaded int64
	// 'rangeStart' is the starting byte offset for the Range header when doing
	// explicit byte-range requests.  It is kept separate from 'downloaded' so that
	// TransferredBytes correctly reflects the actual bytes transferred.
	var rangeStart int64
	if transfer.byteRange != nil {
		rangeStart = transfer.byteRange.Start
	}
	localPath := transfer.localPath
	transferResults.job = transfer.job

	var size int64 = -1
	attempts := transfer.attempts
	// A job that refuses collections has to find out before anything is
	// created locally, or the caller is left holding the empty file this is
	// meant to prevent. The endpoint probe that would otherwise happen further
	// down is simply brought forward and asked one additional question; it is
	// the same requests either way. Skipped for a dry run, which creates
	// nothing and is expected not to reach out to the object servers at all.
	sorted := false
	if transfer.job != nil && transfer.job.ctx != nil && transfer.job.rejectCollections && !transfer.job.dryRun {
		var collection collectionAnswer
		size, collection, attempts = sortAttempts(transfer.job.ctx, transfer.remoteURL.Path, transfer.attempts, probeToken(transfer.token, transfer.fedToken), true)
		sorted = true
		if collection.isCollection {
			err = error_codes.NewParameterError(
				errors.Errorf("remote path %s is a collection; use a recursive transfer (--recursive on the command line) to download its contents", transfer.remoteURL.Path),
			)
			return
		}
		if !collection.answered {
			// A shed probe is why the question went unanswered here, and it is
			// already classified as retryable with the cache's own Retry-After.
			// Reporting the refusal below instead would turn "the cache asked
			// you to wait" into a non-retryable resolution failure and send the
			// caller away for good.
			if collection.throttleErr != nil {
				err = collection.throttleErr
				return
			}
			// Downloading anyway is how the caller ends up with a directory
			// listing saved as though it were their object. An endpoint that
			// cannot answer a PROPFIND for the path it is about to serve is
			// not one to take a GET on faith from, so refuse and say why.
			err = error_codes.NewResolutionError(
				errors.Errorf(
					"no object server could confirm whether %s is a collection; refusing to download",
					transfer.remoteURL.Path),
			)
			return
		}
	}

	// Create hash instances for all known checksum types so we can verify against
	// whatever algorithm the server actually supports. This handles cases like a multiuser
	// origin returning MD5 when CRC32C was requested.
	allHashes, allHashTypes := createAllChecksumHashes()
	hashesWriter := io.MultiWriter(allHashes...)

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
			if !transfer.job.inPlace && localPath != os.DevNull && localPath != "" {
				// Use os.CreateTemp for secure atomic temp file creation in the
				// destination directory, using an rsync-style .basename.* pattern.
				dir := filepath.Dir(localPath)
				base := filepath.Base(localPath)
				fp, err = os.CreateTemp(dir, "."+base+".")
				if err == nil {
					writeDestination = fp.Name()
					fileWriter = fp
				} else {
					return
				}
			}
			// Ensure temporary file is cleaned up if we exit early (errors, panics, etc.)
			// Also handles closing the file; on Windows, open files cannot be removed.
			if !transfer.job.inPlace && writeDestination != localPath {
				defer func() {
					if fp != nil {
						fp.Close()
						fp = nil
					}
					// Only clean up if the temporary file still exists and wasn't renamed
					if _, statErr := os.Stat(writeDestination); statErr == nil {
						if removeErr := os.Remove(writeDestination); removeErr != nil {
							log.Warningln("Failed to remove temporary file:", removeErr)
						}
					}
				}()
			} else {
				defer func() {
					if fp != nil {
						fp.Close()
						fp = nil
					}
				}()
			}
			if fp == nil {
				// If the destination is something strange, like a block device, then the OpenFile below
				// will create the appropriate error message
				if fp, err = os.OpenFile(writeDestination, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
					fileWriter = fp
				} else {
					return
				}
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

	// Sort (re-order) the transfer attempts by querying each endpoint, which
	// also discovers the object size. A job that refuses collections has
	// already done this above.
	if !sorted && transfer.job != nil && transfer.job.ctx != nil {
		size, _, attempts = sortAttempts(transfer.job.ctx, transfer.remoteURL.Path, transfer.attempts, transfer.token, false)
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
	downloadAttemptCount := 0
	for idx, transferEndpoint := range attempts { // For each transfer attempt (usually 3), try to download via HTTP
		downloadAttemptCount++
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
		// If a federation token is set, add it as an access_token query
		// parameter.  The transfer URL already points at the origin (post
		// director redirect), so this goes directly to the origin and is
		// NOT sent to the director.
		if transfer.fedToken != nil {
			if ft, ftErr := transfer.fedToken.Get(); ftErr == nil && ft != "" {
				param := "access_token=" + url.QueryEscape(ft)
				if transferEndpointUrl.RawQuery != "" {
					transferEndpointUrl.RawQuery += "&" + param
				} else {
					transferEndpointUrl.RawQuery = param
				}
			}
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
		fedTokenContents := ""
		if transfer.fedToken != nil {
			fedTokenContents, _ = transfer.fedToken.Get()
		}
		// Determine byte range end (-1 means download to end of file)
		byteRangeEnd := int64(-1)
		if transfer.byteRange != nil {
			byteRangeEnd = transfer.byteRange.End
		}
		attemptDownloaded, timeToFirstByte, cacheAge, serverVersion, attemptETag, err := downloadHTTP(
			ctx, transfer.engine, transfer.callback, transferEndpoint, writeDestination, fileWriter, rangeStart+downloaded, byteRangeEnd, size, tokenContents, transfer.project, transfer.metadataChan, transfer.schedFirstByte,
		)

		// If the endpoint returned a 403 with director-style token hints, learn
		// what token is needed, acquire it, and retry this same endpoint once
		// with the token.  A 403 is returned before any body is written, so
		// retrying is safe.  canApplyTokenHint decides whether the hint is one
		// this transfer may act on at all.
		var hintErr *tokenHintError
		if errors.As(err, &hintErr) && transfer.token.canApplyTokenHint(transferEndpoint.Url) {
			// Acquire on a private generator, coalesced with any sibling file
			// handed the same hint: the job's generator is shared with every
			// other file in this transfer.
			//
			// Retrying with the credential just rejected would only earn the
			// same 403, so a hint that yields nothing new ends the attempt.
			if newTok, tErr := transfer.token.tokenForHint(&hintErr.dirResp); tErr == nil && newTok != "" && newTok != tokenContents {
				log.WithFields(fields).Debugln("Retrying with token after 403 token hint from", transferEndpoint.Url.Host)
				// Publish the credential to the job's generator so the sibling
				// files and the checksum request that follows this download do
				// not each repeat the acquisition.
				transfer.token.cacheToken(newTok)
				tokenContents = newTok
				// The rejected attempt wrote no body, so the scheduler has not
				// been told this endpoint is responsive; the retry is the
				// attempt that will prove it.  schedFirstByte is idempotent.
				attemptDownloaded, timeToFirstByte, cacheAge, serverVersion, attemptETag, err = downloadHTTP(
					ctx, transfer.engine, transfer.callback, transferEndpoint, writeDestination, fileWriter, rangeStart+downloaded, byteRangeEnd, size, tokenContents, transfer.project, transfer.metadataChan, transfer.schedFirstByte,
				)
			}
		}
		// Clear metadata channel after first attempt - we only want to send metadata once
		transfer.metadataChan = nil

		// Track the ETag for resume validation: if the server provided an
		// ETag and we already have one from a previous attempt, make sure
		// they match.  A change means the object was modified between
		// attempts and the partially-downloaded data is no longer valid.
		if attemptETag != "" {
			if transferResults.ETag == "" {
				transferResults.ETag = attemptETag
			} else if transferResults.ETag != attemptETag {
				log.WithFields(fields).Errorf("ETag changed between download attempts (was %q, now %q); aborting resume",
					transferResults.ETag, attemptETag)
				attempt.Error = newTransferAttemptError(
					attempt.Endpoint, "", false, false,
					errors.New("object was modified between download attempts (ETag mismatch); cannot safely resume"),
				)
				transferResults.Attempts = append(transferResults.Attempts, attempt)
				break
			}
		}

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
			log.WithFields(fields).Debugln("Failed to download from", transferEndpoint.Url.String(), ":", err)
			proxyStr, _ := os.LookupEnv("http_proxy")
			if !transferEndpoint.Proxy {
				proxyStr = ""
			}
			serviceStr := attempt.Endpoint
			if transferEndpointUrl.Scheme == "unix" {
				serviceStr = "local-cache"
			}
			wrappedErr, isProxyErr, modifiedProxyStr := wrapDownloadError(err, transferEndpoint.Url.String(), tokenContents, fedTokenContents)
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

		// Skip checksum verification for byte-range downloads.  The server's
		// checksum covers the entire object, not the requested byte range, so
		// comparing it against a partial download will always produce a
		// spurious mismatch.
		if transfer.byteRange != nil {
			log.WithFields(log.Fields{
				"url": transfer.remoteURL.String(),
				"job": transfer.job.ID(),
			}).Debugln("Skipping checksum verification for byte-range download")
		} else {
			// Fetch checksum of the downloaded file, compare it to the calculated.
			// Use downloadAttemptCount (the number of download-loop iterations)
			// rather than len(transferResults.Attempts), which may include extra
			// entries from a failed prestage API call, or len(transferUrls),
			// which is pre-allocated and may contain nil entries for unattempted URLs.
			gotChecksum := false
			checksumHost := ""
			// Iterate through the various sources to fetch the checksums, starting with the successful one.
			for idx := 0; idx < downloadAttemptCount; idx++ {
				url := transferUrls[downloadAttemptCount-idx-1]
				fields := log.Fields{
					"url": url.String(),
					"job": transfer.job.ID(),
				}
				ctx := context.WithValue(transfer.ctx, logFields("fields"), fields)
				tokenContents := ""
				if transfer.token != nil {
					tokenContents, _ = transfer.token.Get()
				}
				if checksums, err := fetchChecksum(ctx, KnownChecksumTypes(), url, tokenContents, transfer.project); err == nil {
					transferResults.ServerChecksums = checksums
					gotChecksum = true
					checksumHost = url.Host
					rememberServiceDigests(url.Host, checksums)
				}
			}
			if !gotChecksum && transfer.requireChecksum {
				transferResults.Error = errors.New("checksum is required but no endpoints were able to provide it")
			}

			// Build map of all computed checksums for verification
			allComputed := make(map[ChecksumType][]byte, len(allHashTypes))
			for idx, t := range KnownChecksumTypes() {
				allComputed[t] = allHashes[idx].(hash.Hash).Sum(nil)
			}

			// Populate ClientChecksums with the originally-requested types for backward compatibility
			requestedTypes := transfer.requestedChecksums
			var quietFallbacks []ChecksumType
			if len(requestedTypes) == 0 {
				requestedTypes = []ChecksumType{AlgDefault}
				// The caller asked for nothing in particular, so a digest
				// this service is known to provide is not a surprise worth
				// warning about.
				quietFallbacks = defaultChecksumTypesForService(checksumHost)
			}
			transferResults.ClientChecksums = make([]ChecksumInfo, 0, len(requestedTypes))
			for _, t := range requestedTypes {
				if val, ok := allComputed[t]; ok {
					transferResults.ClientChecksums = append(transferResults.ClientChecksums, ChecksumInfo{
						Algorithm: t,
						Value:     val,
					})
				}
			}

			// Verify checksums: match any server-provided checksum against our computed values,
			// falling back to non-requested algorithms if the requested ones aren't available
			fields := log.Fields{
				"url": transfer.remoteURL.String(),
				"job": transfer.job.ID(),
			}
			if _, verifyErr := verifyTransferChecksums(
				allComputed, requestedTypes, quietFallbacks, transferResults.ServerChecksums,
				transfer.requireChecksum, fields,
			); verifyErr != nil {
				transferResults.Error = verifyErr
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
	if val, found := getJobId(ctx); found {
		request.Header.Set("X-Pelican-JobId", val)
	}
	request.Header.Set("Want-Digest", wantDigestValue(types))
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
	result = parseDigestHeader(response.Header, fields)
	if len(result) == 0 {
		log.WithFields(fields).Debugln("Server returned no checksum information")
	}
	return
}

// parseDigestHeader parses RFC 3230 Digest response headers and returns
// the parsed checksum values.  It accepts multiple Digest header values
// and comma-separated entries within a single value.
// The optional fields parameter provides structured logging context.
func parseDigestHeader(header http.Header, fields log.Fields) (result []ChecksumInfo) {
	if fields == nil {
		fields = log.Fields{}
	}
	for _, val := range header.Values("Digest") {
		for _, entry := range strings.Split(val, ",") {
			// Per RFC 7230 §7, list elements may be separated by a comma
			// followed by optional whitespace (e.g. "md5=...., crc32c=....").
			// Trim it so the algorithm name doesn't carry a leading space.
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
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
			buf := make([]byte, 32)
			switch info[0] {
			case "crc32c":
				// XRootD has a bug where crc32c is base64 encoded instead (per the spec)
				// hex encoded.  Accept this case.  We've reported this as a bug so ideally
				// future versions use hex instead.  Note: 0x3d is the = character.
				// See: https://github.com/xrootd/xrootd/issues/2456
				if len(info[1]) == 8 && info[1][6] == 0x3d && info[1][7] == 0x3d {
					decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(info[1])))
					if _, err := decoder.Read(buf); err == nil {
						checksumInfo.Value = buf[:4]
						break
					} else {
						log.WithFields(fields).Errorf("Failed to parse base64-encoded checksum value (%s): %s", info[1], err)
					}
				}
				fallthrough
			case "crc32":
				// CRC32/CRC32C values are 32 bits, which is at most 8 hex characters.
				// If the value is longer, the origin likely returned a different algorithm
				// (e.g., MD5) mislabeled as crc32/crc32c. This can happen with the XRootD
				// multiuser plugin when it doesn't support the requested algorithm.
				if len(info[1]) > 8 {
					log.WithFields(fields).Warnf(
						"Server returned %s with value '%s' (%d hex chars, expected at most 8 for a 32-bit checksum); "+
							"the origin may not support %s and returned a different algorithm. Skipping this entry.",
						info[0], info[1], len(info[1]), info[0])
					continue
				}
				// Parse crc32 and crc32c as hexadecimal values.  Per the IANA registry
				// (https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml), these
				// are hex-encoded and should accept leading 0's.  Once parsed, store the
				// corresponding bytes in network order (big-endian) in our byte array.
				if intVal, err := strconv.ParseInt(info[1], 16, 64); err == nil {
					buf[0] = byte((intVal >> 24) & 0xff)
					buf[1] = byte((intVal >> 16) & 0xff)
					buf[2] = byte((intVal >> 8) & 0xff)
					buf[3] = byte(intVal & 0xff)
					checksumInfo.Value = buf[:4]
				} else {
					log.WithFields(fields).Errorf("Failed to parse %s checksum value (%s): %s", info[0], info[1], err)
					continue
				}
			case "md5":
				fallthrough
			case "sha":
				decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(info[1])))
				if count, err := decoder.Read(buf); err != nil {
					log.WithFields(fields).Errorf("Failed to parse %s checksum value (%s): %s", info[0], info[1], err)
					continue
				} else {
					buf = buf[:count]
				}
				checksumInfo.Value = buf
			default:
				log.WithFields(fields).Warningf("Unknown checksum algorithm: %s", info[0])
				continue
			}
			result = append(result, checksumInfo)
		}
	}
	return
}

// Verify that a file on disk matches the expected size. We ignore directories
// and generic stat failures unless the file doesn't exist.
func verifyFileSize(dest string, expectedSize int64, fields log.Fields) error {
	// Skip size check when using custom writer (dest is empty) or writing to /dev/null
	if dest == "" || dest == os.DevNull {
		log.WithFields(fields).Debugf("Skipping size check because destination is (%s)", dest)
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

// acquireFromTokenHint reads the token hints an origin attached to a response
// that refused the request and, if tok may act on them, obtains the credential
// they name and caches it so a retry carries it.  Reports whether it did.
//
// This is how an operation other than a download learns what it needs: a stat,
// a listing, and a cache-age probe all ask their own question first and read
// the answer off the refusal, rather than paying for a metadata query that the
// request was about to make redundant.
func acquireFromTokenHint(tok *tokenGenerator, resp *http.Response) bool {
	if tok == nil || resp == nil || resp.Request == nil {
		return false
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return false
	}
	if resp.Header.Get(server_structs.XPelNs{}.GetName()) == "" {
		return false
	}
	if !tok.canApplyTokenHint(resp.Request.URL) {
		return false
	}
	hint, err := ParseDirectorInfo(resp)
	if err != nil || !hint.XPelNsHdr.RequireToken {
		return false
	}
	contents, err := tok.tokenForHint(&hint)
	if err != nil || contents == "" {
		return false
	}
	// Publish it so the rest of the operation -- the other stat hosts, the rest
	// of a recursive listing -- does not each repeat the acquisition.
	tok.cacheToken(contents)
	return true
}

// tokenHintError is returned by downloadHTTP when an object server responds
// with 403 and director-style X-Pelican-* headers indicating that a token is
// required.  The embedded dirResp carries the parsed token-hint information so
// the caller can acquire the right token and retry the same endpoint.  It
// unwraps to the underlying authorization error so existing error handling
// continues to work if no retry is attempted (or the retry fails).
type tokenHintError struct {
	dirResp server_structs.DirectorResponse
	err     error
}

func (e *tokenHintError) Error() string { return e.err.Error() }
func (e *tokenHintError) Unwrap() error { return e.err }

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
//   - byteRangeEnd: the end byte offset for partial downloads (-1 means download to end of file).
//   - totalSize: the expected size of the object.  If this is -1, the size is unknown.
//   - token: the token to use for authoriation.
//   - project: the project name to be used in the header identifying the transfer to the server.
//   - metadataChan: optional channel to receive early transfer metadata (ETag, size, etc.) before data transfer.
//
// Returns the downloaded size, time to 1st byte downloaded, serverVersion and an error if there is one
func downloadHTTP(ctx context.Context, te *TransferEngine, callback TransferCallbackFunc, transfer transferAttemptDetails, dest string, writer io.Writer, bytesSoFar int64, byteRangeEnd int64, totalSize int64, token string, project string, metadataChan chan<- TransferMetadata, onFirstByte func()) (downloaded int64, timeToFirstByte time.Duration, cacheAge time.Duration, serverVersion string, etag string, err error) {
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
	jobId, found := getJobId(ctx)
	if found {
		req.Header.Set("X-Pelican-JobId", jobId)
	}
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("X-Pelican-Timeout", headerTimeout.Round(time.Millisecond).String())
	if bytesSoFar > 0 || byteRangeEnd >= 0 {
		var rangeHeader string
		if byteRangeEnd >= 0 {
			rangeHeader = fmt.Sprintf("bytes=%d-%d", bytesSoFar, byteRangeEnd)
			log.Debugln("Requesting byte range", bytesSoFar, "to", byteRangeEnd)
		} else {
			rangeHeader = fmt.Sprintf("bytes=%d-", bytesSoFar)
			log.Debugln("Resuming transfer starting at offset", bytesSoFar)
		}
		req.Header.Set("Range", rangeHeader)
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
		// Cap the error-body read: the peer is not necessarily trustworthy,
		// and the body is copied into error strings that outlive the
		// request. Anything useful fits well within the cap.
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		if readErr != nil {
			log.WithFields(fields).Debugln("Failed to read response body for error:", readErr)
		}
		bodyStr := string(bodyBytes)
		log.WithFields(fields).Debugln("Error response body:", bodyStr)
		serverVersion = resp.Header.Get("Server")
		// A server that answers namespace questions about itself -- a standalone
		// origin -- returns the same X-Pelican-* token-hint headers a director
		// would, on the response that turns the request down.  Both codes carry
		// them and both matter: 401 is what a client that sent nothing gets,
		// which is the ordinary first request when no director was asked what
		// this namespace wants, and 403 is what a presented-but-insufficient
		// credential gets.  Surface either as a tokenHintError so the caller can
		// obtain the right credential and retry this same endpoint, reusing the
		// director-response parser.  Whether the hint may be acted on is decided
		// by canApplyTokenHint, not here.
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			if resp.Header.Get(server_structs.XPelNs{}.GetName()) != "" {
				if parsed, perr := ParseDirectorInfo(resp); perr == nil && parsed.XPelNsHdr.RequireToken {
					// Keep the underlying error the shape each status already
					// had, so nothing downstream sees a 401 become a 403.
					var wrapped error
					if resp.StatusCode == http.StatusForbidden {
						pde := &PermissionDeniedError{}
						if trimmed := strings.TrimSpace(bodyStr); trimmed != "" {
							pde.message = "Permission denied: " + trimmed
						}
						wrapped = error_codes.NewAuthorizationError(pde)
					} else {
						sce := StatusCodeError(resp.StatusCode)
						wrapped = wrapStatusCodeError(&sce)
					}
					return 0, 0, -1, serverVersion, "", &tokenHintError{dirResp: parsed, err: wrapped}
				}
			}
		}
		if resp.StatusCode == http.StatusForbidden {
			// Preserve the origin's response body so operators can see why
			// the request was rejected (e.g. scope mismatch, token issue).
			// The message may be further enriched with token-expiry info in
			// wrapDownloadError.
			pde := &PermissionDeniedError{}
			if trimmed := strings.TrimSpace(bodyStr); trimmed != "" {
				pde.message = "Permission denied: " + trimmed
			}
			authErr := error_codes.NewAuthorizationError(pde)
			return 0, 0, -1, serverVersion, "", authErr
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			// The serving cache's fair scheduler shed this request. Parse the
			// structured reason from the body and the Retry-After hint so the
			// error is classified as the specific retryable throttle type and
			// the advertised backoff is carried to the caller / external
			// retrier.
			throttleErr := newThrottleErrorFromResponse(resp, bodyStr, transfer.Url.Host)
			log.WithFields(fields).Warnf("Server %s throttled the request (reason=%s, retry-after=%s)",
				transfer.Url.Host, throttleErr.Reason, throttleErr.RetryAfter)
			return 0, 0, -1, serverVersion, "", throttleErr
		}
		sce := StatusCodeError(resp.StatusCode)
		// Wrap StatusCodeError with appropriate PelicanError based on status code
		wrappedErr := wrapStatusCodeError(&sce)
		httpErr := &HttpErrResp{resp.StatusCode, fmt.Sprintf("request failed (HTTP status %d): %s",
			resp.StatusCode, strings.TrimSpace(bodyStr)), wrappedErr}
		return 0, 0, -1, serverVersion, "", httpErr
	}

	serverVersion = resp.Header.Get("Server")
	etag = resp.Header.Get("ETag")

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

	// Size of the download.
	//
	// responseContentLength captures the raw Content-Length from the HTTP
	// response (the number of bytes in the response body).  For 206 Partial
	// Content this is the range length, not the full object.
	//
	// objectSize is the full object size: for 200 OK it equals
	// responseContentLength; for 206 it is parsed from the Content-Range
	// header (e.g. "bytes 100-199/1000" → 1000).  It is -1 when unknown.
	//
	// totalSize is the value used for progress and size-validation checks;
	// it is adjusted so that (bytesSoFar + downloaded == totalSize) holds
	// on a successful transfer.
	responseContentLength := resp.ContentLength
	objectSize := int64(-1)
	totalSize = resp.ContentLength

	// For 206 responses, parse the full object size from Content-Range and
	// adjust totalSize for the size-validation check.
	if resp.StatusCode == http.StatusPartialContent && (bytesSoFar > 0 || byteRangeEnd >= 0) {
		// For range responses, Content-Length is the size of the range,
		// not the full object.  Reconstruct the expected total so the
		// size check (bytesSoFar + downloaded == totalSize) passes:
		//   - Resume (bytesSoFar > 0, byteRangeEnd < 0): totalSize is
		//     the full object size = Content-Length + bytesSoFar.
		//   - Bounded byte-range (byteRangeEnd >= 0): totalSize is
		//     byteRangeEnd + 1 so that bytesSoFar + downloaded ==
		//     totalSize when downloaded == rangeSize.

		// Always try to extract the full object size from Content-Range.
		if rangeStr := resp.Header.Get("Content-Range"); rangeStr != "" {
			parts := strings.SplitN(rangeStr, "/", 2)
			if len(parts) == 2 && parts[1] != "*" {
				if parsed, parseErr := strconv.ParseInt(parts[1], 10, 64); parseErr == nil {
					objectSize = parsed
				}
			}
		}

		if byteRangeEnd >= 0 {
			// Explicit byte-range: the size check will compare
			// bytesSoFar + downloaded, so set totalSize = end + 1.
			totalSize = byteRangeEnd + 1
		} else if totalSize < 0 {
			if objectSize > 0 {
				totalSize = objectSize
			} else {
				log.WithFields(fields).Debugln("Content-Range header is missing or unparsable; unable to determine size of object")
			}
		} else {
			totalSize += bytesSoFar
		}
	} else if resp.StatusCode == http.StatusOK {
		objectSize = resp.ContentLength
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

		// Verify that the HEAD and GET responses refer to the same object
		// version.  If both provide an ETag and they differ, the object
		// changed between the two requests and the reported size may not
		// match the body being streamed.
		headETag := headResponse.Header.Get("ETag")
		getETag := resp.Header.Get("ETag")
		if headETag != "" && getETag != "" && headETag != getETag {
			log.WithFields(fields).Warnf("ETag mismatch between GET (%s) and HEAD (%s); ignoring HEAD size", getETag, headETag)
		} else {
			contentLengthStr := headResponse.Header.Get("Content-Length")
			if contentLengthStr != "" {
				totalSize, err = strconv.ParseInt(contentLengthStr, 10, 64)
				if err != nil {
					log.WithFields(fields).Errorln("problem converting content-length to an int:", err)
					totalSize = -1
				}
			}
		}
	}
	// When the response uses chunked transfer-encoding, the HTTP layer
	// reports Content-Length as -1 even though the actual body size is
	// known from either a byte-range request or the HEAD fallback above.
	// Reconstruct responseContentLength so the metadata channel reports
	// the real number of bytes to expect.
	if responseContentLength < 0 {
		if byteRangeEnd >= 0 {
			// Byte-range request: body is exactly (end - start + 1) bytes
			responseContentLength = byteRangeEnd - bytesSoFar + 1
		} else if totalSize > 0 {
			responseContentLength = totalSize - bytesSoFar
		}
	}
	if objectSize < 0 && totalSize > 0 {
		objectSize = totalSize
	}
	if callback != nil {
		callback(dest, bytesSoFar, totalSize, false)
	}

	// Send early metadata to the optional channel before starting the actual data transfer
	// This allows the caller to make decisions (e.g., verify ETag) before committing to the transfer
	if metadataChan != nil {
		metadata := TransferMetadata{
			ContentLength: responseContentLength,
			ObjectSize:    objectSize,
			ETag:          resp.Header.Get("ETag"),
			ContentType:   resp.Header.Get("Content-Type"),
			CacheControl:  resp.Header.Get("Cache-Control"),
		}
		// Parse Last-Modified header if present
		if lmStr := resp.Header.Get("Last-Modified"); lmStr != "" {
			if lm, parseErr := http.ParseTime(lmStr); parseErr == nil {
				metadata.LastModified = lm
			}
		}
		// Non-blocking send - if the channel is full, we proceed without blocking
		select {
		case metadataChan <- metadata:
		default:
			log.WithFields(fields).Debugln("Metadata channel full or nil, skipping early metadata send")
		}
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
		writer:      writer,
		onFirstByte: onFirstByte,
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
			return 0, 0, -1, serverVersion, "", error_codes.NewAuthorizationError(&PermissionDeniedError{})
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
		return 0, 0, -1, serverVersion, "", httpErr
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

// uploadNonStarvingSentBytes is the volume of request body the transport must
// have consumed before an upload destination is presumed to be draining the
// connection. Kernel socket buffers plus the transport's own buffering can
// absorb a few megabytes from a peer that has stopped reading, so a small
// number of sent bytes proves nothing; once this many bytes have gone out,
// the far end must actually be consuming them.
const uploadNonStarvingSentBytes = 4 << 20

// progressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type progressReader struct {
	reader io.ReadCloser
	sizer  Sizer
	closed chan bool

	// sentBytes counts what the HTTP transport has consumed from the
	// reader (a close proxy for bytes sent on the wire — the transport's
	// write buffering is a few KiB). When it crosses sentThreshold,
	// onSentThreshold fires once. Both are touched only from Read, which
	// the transport calls from a single goroutine, so no locking.
	sentBytes       int64
	sentThreshold   int64
	onSentThreshold func()
}

// Read implements the common read function for io.Reader
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	if cs, ok := pr.sizer.(*ConstantSizer); ok {
		cs.read.Add(int64(n))
	}
	if pr.onSentThreshold != nil {
		pr.sentBytes += int64(n)
		if pr.sentBytes >= pr.sentThreshold {
			pr.onSentThreshold()
			pr.onSentThreshold = nil
		}
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
		if pw.onFirstByte != nil {
			pw.onFirstByte()
		}
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
		_, statErr := statHttp(transfer.ctx, remoteUrl, dirResp, token, nil)
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

	// Create hash instances for all known checksum types so we can verify against
	// whatever algorithm the server actually supports after upload.
	allHashes, allHashTypes := createAllChecksumHashes()
	hashesWriter := io.MultiWriter(allHashes...)

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
			// Nothing else closes this handle: the request body below is a
			// TeeReader (not a ReadCloser), so the HTTP transport wraps it
			// in a NopCloser and never closes the underlying file. Without
			// this, every filesystem upload leaks a file descriptor — and
			// on Windows leaves the source file locked.
			defer file.Close()
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
	// Buffered: the loop below abandons the upload on several paths (stopped
	// transfer, error on the side channel) without ever receiving here, and an
	// unbuffered channel would wedge runPut's goroutine — and with it the
	// transport still reading the source file — for the life of the process.
	responseChan := make(chan *http.Response, 1)
	reader := &progressReader{reader: ioreader, sizer: sizer, closed: closed}
	// This will write to the checksum hashes as we read from the file
	tee := io.TeeReader(reader, hashesWriter)
	putContext, cancel := context.WithCancel(transfer.ctx)
	transferStartTime := time.Now()
	defer cancel()
	log.Debugln("Full destination URL:", dest.String())
	// Tell the scheduler (if any) the destination is alive on the earliest of
	// three signals: a negotiated 100-continue, the first byte of the final
	// response, or enough request body consumed that the far end must be
	// draining it (without 100-continue, a server that only answers after the
	// whole body would otherwise leave a long upload "starving" for its
	// entire duration). The hook is CAS-guarded upstream, so the three paths
	// firing in any combination is harmless. The trace is scoped to the PUT
	// itself, not to the checksum fetch that reuses putContext. Note that we
	// do not send an Expect: 100-continue header, so Got100Continue only
	// fires when the transport negotiates it on its own.
	requestContext := putContext
	if transfer.schedFirstByte != nil {
		schedFirstByte := transfer.schedFirstByte
		reader.sentThreshold = uploadNonStarvingSentBytes
		reader.onSentThreshold = schedFirstByte
		requestContext = httptrace.WithClientTrace(putContext, &httptrace.ClientTrace{
			Got100Continue:       func() { schedFirstByte() },
			GotFirstResponseByte: func() { schedFirstByte() },
		})
	}
	var request *http.Request

	// Decide whether the wire body is a raw stream (the default,
	// historical shape) or multipart/form-data (set when the caller
	// supplied opaque-blob metadata via WithObjectMetadataBlob /
	// WithObjectMetadataBlobFile). The multipart branch wraps the
	// existing `tee` (which already drives progress + checksum
	// accounting) into the "object" part; the "metadata" part holds
	// the blob bytes.
	wireBody := io.Reader(tee)
	wireContentType := "" // empty = leave existing handling alone (no Content-Type override)
	if transfer.objectMetadataBlob != nil && len(transfer.objectMetadataBlob.body) > 0 && nonZeroSize {
		mpBody, mpCT := buildMultipartUploadBody(tee, transfer.objectMetadataBlob)
		wireBody = mpBody
		wireContentType = mpCT
	}
	// For files that are 0 length, we need to send a PUT request with an nil body
	if nonZeroSize {
		request, err = http.NewRequestWithContext(requestContext, http.MethodPut, dest.String(), wireBody)
	} else {
		request, err = http.NewRequestWithContext(requestContext, http.MethodPut, dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		transferResult.Error = err
		return transferResult, err
	}
	if wireContentType != "" {
		request.Header.Set("Content-Type", wireContentType)
		// Multipart bodies have unknown total length on the wire
		// (the metadata blob size + file size + per-part framing
		// overhead). Force chunked transfer encoding so Go's HTTP
		// client doesn't try to compute a Content-Length we can't
		// supply exactly. The server's POSC pipeline already
		// streams the object part from the multipart reader.
		request.ContentLength = -1
		request.TransferEncoding = []string{"chunked"}
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
	if result, found := getJobId(putContext); found {
		request.Header.Set("X-Pelican-JobId", result)
	}
	// If the caller supplied uploader metadata, render it into the
	// origin-side X-Pelican-Object-Metadata Structured Fields
	// header. We've already validated values during option parsing
	// (see WithObjectMetadata + WithObjectMetadataFile), so an
	// error here means a programmer bug, not a user-input problem.
	if len(transfer.objectMetadata) > 0 {
		hdrVal, hdrErr := buildObjectMetadataHeader(transfer.objectMetadata)
		if hdrErr != nil {
			log.Errorln("Failed to render X-Pelican-Object-Metadata header:", hdrErr)
			transferResult.Error = hdrErr
			return transferResult, hdrErr
		}
		if hdrVal != "" {
			request.Header.Set(ObjectMetadataHeaderName, hdrVal)
		}
	}
	var lastKnownWritten int64
	uploadStart := time.Now()

	useProxy := transfer.attempts[0].Proxy

	putDone := make(chan struct{})
	go func() {
		defer close(putDone)
		runPut(request, responseChan, errorChan, useProxy)
	}()
	// The transport reads the source file until the request finishes, so cancel
	// the PUT and join its goroutine before the deferred file.Close() above can
	// run. Registered after `defer cancel()`, so it runs before it -- cancelling
	// here is what makes the join prompt.
	//
	// This narrows rather than eliminates the overlap: client.Do returns once
	// response headers arrive, so on an early server response the transport's
	// write loop can still be reading the body when runPut returns, and
	// cancellation is asynchronous. os.File tolerates that (the read fails with
	// ErrFileClosing rather than hitting a reused descriptor) and the transfer
	// has already latched its error, so the remaining window is benign.
	//
	// Also drain the response the abandoned PUT may have deposited: nothing
	// else is going to receive it, and its body holds a connection open until
	// the cancel tears it down.
	defer func() {
		cancel()
		<-putDone
		select {
		case resp := <-responseChan:
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		default:
		}
	}()
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

			// Capture ETag from the upload response
			if responseETag := response.Header.Get("ETag"); responseETag != "" {
				transferResult.ETag = responseETag
			}

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
				if response.StatusCode == http.StatusTooManyRequests {
					// The destination throttled the upload; classify it with
					// the structured reason + Retry-After hint so the error is
					// the same retryable throttle type a download would get.
					// runPut re-buffered the (bounded) error body for us.
					bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodySize))
					lastError = newThrottleErrorFromResponse(response, string(bodyBytes), request.URL.Host)
					break Loop
				}
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

		// Fetch the checksums from the server, requesting all known types
		result, err := fetchChecksum(putContext, KnownChecksumTypes(), dest, tokenContents, transfer.job.project)
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
			rememberServiceDigests(dest.Host, result)
		}

		// Build map of all computed checksums for verification
		allComputed := make(map[ChecksumType][]byte, len(allHashTypes))
		for idx, t := range allHashTypes {
			allComputed[t] = allHashes[idx].(hash.Hash).Sum(nil)
		}

		// Populate ClientChecksums with the originally-requested types for backward compatibility
		requestedTypes := transfer.requestedChecksums
		var quietFallbacks []ChecksumType
		if len(requestedTypes) == 0 {
			requestedTypes = []ChecksumType{AlgDefault}
			// The caller asked for nothing in particular, so a digest this
			// service is known to provide is not a surprise worth warning
			// about.
			quietFallbacks = defaultChecksumTypesForService(dest.Host)
		}
		transferResult.ClientChecksums = make([]ChecksumInfo, 0, len(requestedTypes))
		for _, t := range requestedTypes {
			if val, ok := allComputed[t]; ok {
				transferResult.ClientChecksums = append(transferResult.ClientChecksums, ChecksumInfo{
					Algorithm: t,
					Value:     val,
				})
			}
		}

		// Verify checksums: match any server-provided checksum against our computed values
		fields := log.Fields{
			"url": transfer.remoteURL.String(),
			"job": transfer.job.ID(),
		}
		if _, verifyErr := verifyTransferChecksums(
			allComputed, requestedTypes, quietFallbacks, transferResult.ServerChecksums,
			transfer.requireChecksum, fields,
		); verifyErr != nil {
			transferResult.Error = verifyErr
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
	// Headers only: dumping the body would io.ReadAll it into memory, which
	// defeats the bounded read below and hands a hostile destination an
	// unbounded allocation per upload worker. Error bodies are logged (and
	// bounded) a few lines down.
	dump, _ = httputil.DumpResponse(response, false)
	log.Debugf("Dumping response: %s", dump)
	// Note: XRootD used to always return 200 (OK) on upload, even when it was supposed to turn
	// HTTP 201 (Created).  Check for both here; in the future we may want to remove the 200 check
	// if we decide to drop support for the older versions of XRootD.
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		log.Errorln("Error status code:", response.Status)
		log.Debugln("From the server:")
		textResponse, err := io.ReadAll(io.LimitReader(response.Body, maxErrorBodySize))
		if err != nil {
			log.Errorln("Error reading response from server:", err)
			responseChan <- response
			return
		}
		log.Debugln(string(textResponse))
		// Re-buffer the (bounded) body so the consumer on responseChan can
		// still inspect it — e.g. to extract the structured reason from a
		// 429 throttle response.
		response.Body = io.NopCloser(strings.NewReader(string(textResponse)))
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
	if age, _, _, _, err := objectCached(job.ctx, &cache, job.token, false); err == nil {
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

	remoteInfo, err := statHttp(job.ctx, remoteUrl, job.dirResp, job.token, nil)
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
func (te *TransferEngine) walkDirDownload(job *clientTransferJob, transfers []transferAttemptDetails, url *url.URL) error {
	// Create the client to walk the filesystem
	collUrl := job.job.dirResp.XPelNsHdr.CollectionsUrl
	if collUrl == nil {
		return errors.New("Collections URL not found in director response")
	}
	log.Debugln("Trying collections URL: ", collUrl.String())

	client := createWebDavClient(collUrl, job.job.token, job.job.project)
	return te.walkDirDownloadHelper(job, transfers, url.Path, client)
}

// Helper function for the `walkDirDownload`.
//
// Recursively walks through the remote server collection, emitting transfer files
// for the engine to process.
func (te *TransferEngine) walkDirDownloadHelper(job *clientTransferJob, transfers []transferAttemptDetails, remotePath string, client *gowebdav.Client) error {
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
					// Counted before submission: a scheduler rejection produces a
					// synthetic result right away, and runMux decrements on every
					// result, so counting afterwards would race its delivery.
					job.job.activeXfer.Add(1)
					if err := te.submitFile(job.job.ctx, &clientTransferFile{
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
							fedToken:           job.job.fedToken,
							attempts:           transferAttempts,
						},
					}); err != nil {
						if !errors.Is(err, ErrTooManyRequests) {
							// Nothing was queued and no result is coming, so this
							// file must not stay on the job's books.
							job.job.uncountSubmission()
							return err
						}
						// 429 already reported to te.results by submitFile;
						// continue enumerating the collection.
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
			err := te.walkDirDownloadHelper(job, transfers, newPath, client)
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
			// Counted before submission: a scheduler rejection produces a
			// synthetic result right away, and runMux decrements on every
			// result, so counting afterwards would race its delivery.
			job.job.activeXfer.Add(1)
			if err := te.submitFile(job.job.ctx, &clientTransferFile{
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
					fedToken:           job.job.fedToken,
					attempts:           transferAttempts,
				},
			}); err != nil {
				if !errors.Is(err, ErrTooManyRequests) {
					// Nothing was queued and no result is coming, so this
					// file must not stay on the job's books.
					job.job.uncountSubmission()
					return err
				}
			}
		}
	}
	return nil
}

// Helper function for walkDirUpload; not to be called directly
func (te *TransferEngine) walkDirUpload(job *clientTransferJob, transfers []transferAttemptDetails, localPath string) error {
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
				// Counted before submission: a scheduler rejection produces a
				// synthetic result right away, and runMux decrements on every
				// result, so counting afterwards would race its delivery.
				job.job.activeXfer.Add(1)
				if err := te.submitFile(job.job.ctx, &clientTransferFile{
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
				}); err != nil {
					if !errors.Is(err, ErrTooManyRequests) {
						// Nothing was queued and no result is coming, so this
						// file must not stay on the job's books.
						job.job.uncountSubmission()
						return err
					}
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
			err := te.walkDirUpload(job, transfers, newPath)
			if err != nil {
				return err
			}
		} else if skipUpload(job.job, newPath, remoteUrl) {
			log.Infoln("Skipping upload of object", remoteUrl.Path, "as it already exists at the destination")
		} else if info.Type().IsRegular() {
			// Counted before submission: a scheduler rejection produces a
			// synthetic result right away, and runMux decrements on every
			// result, so counting afterwards would race its delivery.
			job.job.activeXfer.Add(1)
			if err := te.submitFile(job.job.ctx, &clientTransferFile{
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
			}); err != nil {
				if !errors.Is(err, ErrTooManyRequests) {
					// Nothing was queued and no result is coming, so this
					// file must not stay on the job's books.
					job.job.uncountSubmission()
					return err
				}
			}
		}
	}
	return err
}

// listHttpEmit walks the collection at remoteUrl (recursively if requested)
// and hands each entry to emit in the order encountered. The emit signature
// mirrors filepath.WalkDirFunc: for a successful entry emit is called with
// (info, nil); for an error attributable to a specific path in the tree
// (e.g. an unreadable subdirectory) emit is called with a FileInfo carrying
// just Name and IsCollection alongside the error. Returning a non-nil error
// from emit unwinds the walk with that error; returning nil after an error
// tells the walker to skip that subtree and continue with the next sibling,
// matching filepath.WalkDir's continuation semantics. This is the streaming
// primitive used by DoList, DoListStream, and DoListSeq.
func listHttpEmit(remoteUrl *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator, recursive bool, depth int, emit func(FileInfo, error) error) error {
	if dirResp.XPelNsHdr.CollectionsUrl == nil {
		return errors.Errorf("Collections URL not found in director response. Are you sure there's an origin for prefix %s that supports listings?", dirResp.XPelNsHdr.Namespace)
	}

	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl
	log.Debugln("Collections URL: ", collectionsUrl.String())

	project, found := searchJobAd(attrProjectName)
	if !found {
		project = ""
	}
	client := createWebDavClient(collectionsUrl, token, project)
	remotePath := remoteUrl.Path

	if recursive {
		return listHttpRecursiveEmit(client, remotePath, 0, depth, emit)
	}
	return listHttpFlatEmit(client, remotePath, emit)
}

// classifyReadDirErr converts the ReadDir-error zoo (404 / 500-that-means-file
// / 405-no-listings / everything else) into a single error suitable for
// bubbling through emit. Returns (nil, nil) when the error meant "this is a
// plain object, not a directory" and info is populated with the stat result --
// the caller should emit that info instead of the error.
func classifyReadDirErr(cli *gowebdav.Client, remotePath string, err error) (fs.FileInfo, error) {
	if gowebdav.IsErrNotFound(err) {
		return nil, error_codes.NewSpecification_FileNotFoundError(errors.New("404: object not found"))
	}
	// Two different errors can mean "this path is an object, not a
	// collection". An XRootD origin answers ReadDir on a plain object with a
	// 500. An origin that answers the PROPFIND correctly -- 207 with a single
	// non-collection response for the object itself -- instead trips
	// gowebdav's own check that "self" must be a collection, which surfaces as
	// a synthesized 405. Neither is a refusal to list, and a Stat settles
	// which case we are in before we report one.
	isServerErr := gowebdav.IsErrCode(err, http.StatusInternalServerError)
	isMethodNotAllowed := gowebdav.IsErrCode(err, http.StatusMethodNotAllowed)
	if isServerErr || isMethodNotAllowed {
		var info fs.FileInfo
		statErr := retryWebDavOperation("Stat", func() error {
			var err error
			info, err = cli.Stat(remotePath)
			return err
		})
		if statErr != nil {
			if isServerErr {
				return nil, errors.Wrap(statErr, "failed to stat remote path")
			}
			// For a 405 a failed stat only means we cannot show the path is an
			// object; fall through and report that listings are unsupported.
		} else if !info.IsDir() {
			return info, nil
		}
	}
	if isMethodNotAllowed {
		// We replace the error from gowebdav with our own because gowebdav
		// returns "ReadDir /prefix/different-path/: 405" which is not very
		// user friendly.
		listingErr := &dirListingNotSupportedError{
			Err: errors.New("405: object listings are not supported by the discovered origin"),
		}
		return nil, error_codes.NewSpecificationError(listingErr)
	}
	return nil, errors.Wrap(err, "failed to read remote collection")
}

// listHttpFlatEmit performs the non-recursive listing at remotePath. It reads
// the immediate children (or, if remotePath is a plain object, emits a single
// entry for it) via emit.
func listHttpFlatEmit(client *gowebdav.Client, remotePath string, emit func(FileInfo, error) error) error {
	var infos []fs.FileInfo
	err := retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = client.ReadDir(remotePath)
		return err
	})
	if err != nil {
		statInfo, classified := classifyReadDirErr(client, remotePath, err)
		if classified == nil && statInfo != nil {
			// The path is a plain object, not a collection; emit it once.
			return emit(FileInfo{
				Name:         remotePath,
				Size:         statInfo.Size(),
				ModTime:      statInfo.ModTime(),
				IsCollection: false,
			}, nil)
		}
		// Bubble the (classified) error through emit so the caller can decide
		// whether to skip or abort. For the flat listing the "subtree" is the
		// entire request, so SkipSubtree and a plain nil return both mean
		// "done here"; only SkipAll and real errors matter as distinct outputs.
		emitErr := emit(FileInfo{Name: remotePath, IsCollection: true}, classified)
		if emitErr == nil || errors.Is(emitErr, SkipSubtree) {
			return nil
		}
		return emitErr
	}

	for _, info := range infos {
		jPath, _ := url.JoinPath(remotePath, info.Name())
		emitErr := emit(FileInfo{
			Name:         jPath,
			Size:         info.Size(),
			ModTime:      info.ModTime(),
			IsCollection: info.IsDir(),
		}, nil)
		if emitErr == nil || errors.Is(emitErr, SkipSubtree) {
			// SkipSubtree is a no-op in the flat listing (no descent to
			// skip); treat it the same as nil so the loop keeps going.
			continue
		}
		return emitErr
	}
	return nil
}

// listHttpRecursiveEmit is the recursive analogue of listHttpFlatEmit. It
// descends into each collection depth-first, honoring maxDepth (-1 = no
// limit) and emitting every visited entry through emit in walk order.
// Per-subdirectory ReadDir failures are routed through emit as
// (FileInfo{Name: path, IsCollection: true}, err); returning nil from emit
// tells the walker to skip the failed subtree and keep going with the next
// sibling, matching filepath.WalkDir's semantics.
func listHttpRecursiveEmit(client *gowebdav.Client, remotePath string, currentDepth, maxDepth int, emit func(FileInfo, error) error) error {
	if maxDepth >= 0 && currentDepth > maxDepth {
		return nil
	}

	var infos []fs.FileInfo
	err := retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = client.ReadDir(remotePath)
		return err
	})
	if err != nil {
		statInfo, classified := classifyReadDirErr(client, remotePath, err)
		if classified == nil && statInfo != nil {
			return emit(FileInfo{
				Name:         remotePath,
				Size:         statInfo.Size(),
				ModTime:      statInfo.ModTime(),
				IsCollection: false,
			}, nil)
		}
		// Give the caller a chance to skip. Returning nil or SkipSubtree
		// unwinds this level cleanly (there's no subtree left to walk); any
		// other error, including SkipAll, propagates so the outer walk can
		// react.
		emitErr := emit(FileInfo{Name: remotePath, IsCollection: true}, classified)
		if emitErr == nil || errors.Is(emitErr, SkipSubtree) {
			return nil
		}
		return emitErr
	}

	for _, info := range infos {
		jPath, _ := url.JoinPath(remotePath, info.Name())
		fi := FileInfo{
			Name:         jPath,
			Size:         info.Size(),
			ModTime:      info.ModTime(),
			IsCollection: info.IsDir(),
		}
		emitErr := emit(fi, nil)
		if emitErr != nil {
			if errors.Is(emitErr, SkipSubtree) {
				// Caller doesn't want us to descend into this entry (only
				// meaningful for collections). Continue with the next sibling.
				continue
			}
			// SkipAll, real errors, or errStopIter all propagate upward.
			return emitErr
		}
		// Recurse into subcollections. maxDepth < 0 means unlimited; otherwise
		// only descend when the next level would still be within budget.
		if info.IsDir() && (maxDepth < 0 || currentDepth+1 < maxDepth) {
			if err := listHttpRecursiveEmit(client, jPath, currentDepth+1, maxDepth, emit); err != nil {
				// SkipAll aborts every enclosing loop up to Walk; SkipSubtree
				// at the child level doesn't reach us (it's consumed there),
				// so anything non-nil here is a real error or SkipAll.
				return err
			}
		}
	}
	return nil
}

// listHttp walks the specified collection and buffers every visited FileInfo
// into a slice. It is a thin wrapper over listHttpEmit for callers that want
// the full result set in memory rather than a stream. Any error surfaced by
// the walker (including a per-subtree ReadDir failure) aborts the walk and is
// returned; partial results are discarded, matching the pre-streaming
// behavior of this function.
func listHttp(remoteUrl *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator, recursive bool, depth int) ([]FileInfo, error) {
	var fileInfos []FileInfo
	err := listHttpEmit(remoteUrl, dirResp, token, recursive, depth, func(info FileInfo, emitErr error) error {
		if emitErr != nil {
			return emitErr
		}
		fileInfos = append(fileInfos, info)
		return nil
	})
	if err != nil && !errors.Is(err, SkipAll) {
		return nil, err
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
		if jobId, found := getJobId(ctx); found {
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
// NOTE: the role of this function is evolving.  Historically it preferred
// querying the collectionsUrl (often an origin endpoint) even though, for an
// end-user stat, a cache with Depth:0 PROPFIND support would suffice.
// The current implementation prefers the ObjectServers returned because their Link-
// header URLs carry the correct origin-side path for both XRootD and
// POSIXv2 origins, whereas collectionsUrl requires reconstructing the
// namespace-relative path.  In cache mode (persistent cache) the
// ObjectServers already point at origins, so the stat reaches the right
// place.  In end-user mode the ObjectServers are typically caches, which
// support Depth:0 PROPFIND.
//
// TODO: revisit whether collectionsUrl should be preferred (or used as a
// fallback) for end-user stat when the ObjectServers are caches.  If
// there is no collectionsUrl the origin has indicated it does not support
// PROPFIND, so we must not attempt to stat against it directly.
// preferCollectionsUrlOnly: if true, only use collectionsUrl (origin) for stat, never caches/ObjectServers.
//
// ctx bounds the work. The PROPFINDs fan out across every stat host and are
// waited on together, so without it a single unresponsive object server holds
// the caller for as long as the transport allows -- and the cache calls this
// on the path of every miss it fills.
func statHttp(ctx context.Context, dest *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator, fedToken TokenProvider, preferCollectionsUrlOnly ...bool) (info FileInfo, err error) {
	useCollectionsOnly := len(preferCollectionsUrlOnly) > 0 && preferCollectionsUrlOnly[0]
	return statHttpImpl(ctx, dest, dirResp, token, fedToken, useCollectionsOnly, false)
}

// statHttpImpl is the recursion-safe internals of statHttp.  The
// alreadyFellBack flag stops the two fallback branches at the bottom
// from ping-ponging: one branch flips useCollectionsOnly false->true,
// the other flips it true->false, so an initial call that hits both
// triggers back-to-back would otherwise recurse forever.  After a
// single fallback we have tried both modes and any remaining failure
// is reported to the caller.
func statHttpImpl(ctx context.Context, dest *pelican_url.PelicanURL, dirResp server_structs.DirectorResponse, token *tokenGenerator, fedToken TokenProvider, useCollectionsOnly bool, alreadyFellBack bool) (info FileInfo, err error) {
	statHosts := make([]url.URL, 0, 3)
	collectionsUrl := dirResp.XPelNsHdr.CollectionsUrl

	if useCollectionsOnly {
		if collectionsUrl != nil {
			statHosts = append(statHosts, *collectionsUrl)
		}
	} else {
		if len(dirResp.ObjectServers) > 0 {
			for idx, oServer := range dirResp.ObjectServers {
				if idx > 2 {
					break
				}
				statHosts = append(statHosts, *oServer)
			}
		} else if collectionsUrl != nil {
			statHosts = append(statHosts, *collectionsUrl)
		}
	}
	// With nothing to ask, the loop below would report success on zero
	// results and hand back a zero-valued FileInfo -- an object of size 0
	// that is not a collection.  Callers use IsCollection to decide where a
	// transfer lands, so a fabricated answer is worse than an error.
	if len(statHosts) == 0 {
		return FileInfo{}, errors.Errorf("no endpoint available to stat %s: "+
			"the director returned neither object servers nor a collections URL", dest.String())
	}
	type statResults struct {
		info FileInfo
		err  error
	}
	resultsChan := make(chan statResults)

	// When a federation token is present but no user token (public
	// namespace), we wrap the federation token in a tokenGenerator so
	// that bearerAuth sends it via the Authorization header.  This is
	// necessary because the stat PROPFIND may be routed through the
	// director, which issues a 307 redirect to the origin.  Query
	// parameters set by the interceptor on the initial request are lost
	// during the redirect, but Authorization headers survive same-host
	// redirects.
	authToken := token
	if authToken == nil && fedToken != nil {
		if ft, ftErr := fedToken.Get(); ftErr == nil && ft != "" {
			authToken = &tokenGenerator{Sync: new(singleflight.Group)}
			authToken.SetToken(ft)
		}
	}
	auth := &bearerAuth{token: authToken}

	for _, statUrl := range statHosts {
		isCollections := collectionsUrl != nil && statUrl.Host == collectionsUrl.Host && statUrl.Path == collectionsUrl.Path

		var client *gowebdav.Client
		var propfindPath string
		if isCollections {
			// For collections URLs the path component is a base prefix
			// (e.g. "/api/v1.0/origin/data"); the federation object path
			// (dest.Path, e.g. "/test/") must be appended.  Use the full
			// collectionsUrl (including its path) as the WebDAV client
			// root and pass dest.Path to Stat(), matching how listHttp
			// and walkDirDownload use the collections URL.
			client = gowebdav.NewAuthClient(statUrl.String(), auth)
			propfindPath = path.Clean(dest.Path)
		} else {
			// ObjectServer URLs already contain the full path to the
			// object (e.g. "/test/" or "/api/v1.0/origin/data/test/").
			// Strip the path to form the client root and use the URL
			// path as the PROPFIND target.
			clientRoot := statUrl
			clientRoot.Path = ""
			clientRoot.RawQuery = ""
			clientRoot.Fragment = ""
			client = gowebdav.NewAuthClient(clientRoot.String(), auth)

			propfindPath = statUrl.Path
			if propfindPath == "" {
				propfindPath = dest.Path
			}
			propfindPath = path.Clean(propfindPath)
		}

		destCopy := statUrl
		destCopy.Path = propfindPath

		// No method on studio-b12/gowebdav's Client takes a context -- not in
		// any release through v0.13.0, nor on master -- so the caller's
		// deadline is attached to each request through the interceptor, which
		// runs on the request the library is about to send. (Not to be
		// confused with golang.org/x/net/webdav, used on the origin side of
		// this repo, whose FileSystem methods do take one.)
		client.SetInterceptor(func(_ string, r *http.Request) {
			*r = *r.WithContext(ctx)
		})

		go func(endpoint *url.URL) {
			canDisableProxy := CanDisableProxy()
			disableProxy := !isProxyEnabled()
			idleConnRetries := 0

			var info FileInfo
			for {
				// Local to this goroutine: every stat host runs one of these
				// concurrently, and the proxy decision below is per-host.
				var transport http.RoundTripper
				if disableProxy {
					log.Debugln("Performing request (without proxy)", endpoint.String())
					transport = config.GetTransportNoProxy()
				} else {
					log.Debugln("Performing request", endpoint.String())
					transport = config.GetTransport()
				}
				client.SetTransport(boundPropfindBody(transport))

				fsinfo, err := client.Stat(endpoint.Path)
				if err == nil {
					// gowebdav reports "nothing I could use in that 207" as a
					// nil *File and no error, tucked inside a non-nil
					// os.FileInfo whose methods take a value receiver -- so
					// reading one panics, on this goroutine, where nothing
					// recovers. Treat it as the failure it is.
					if file, ok := fsinfo.(*gowebdav.File); fsinfo == nil || (ok && file == nil) {
						err = errors.Errorf("PROPFIND response from %s described nothing usable for %s", endpoint.Host, endpoint.Path)
						resultsChan <- statResults{FileInfo{}, err}
						return
					}
					info = FileInfo{
						Size:         fsinfo.Size(),
						IsCollection: fsinfo.IsDir(),
						ModTime:      fsinfo.ModTime(),
					}
					// Extract ETag if the underlying type supports it (gowebdav.File)
					if webdavFile, ok := fsinfo.(interface{ ETag() string }); ok {
						info.ETag = webdavFile.ETag()
					}
					break
				} else if gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) {
					err = errors.Wrapf(err, "Stat request not allowed for object at endpoint %s", endpoint.String())
					resultsChan <- statResults{FileInfo{}, err}
					return
				} else if gowebdav.IsErrNotFound(err) {
					err = errors.Wrapf(ErrObjectNotFound, "object %s not found at endpoint %s", dest.String(), endpoint.String())
					err = error_codes.NewSpecification_FileNotFoundError(err)
					resultsChan <- statResults{FileInfo{}, err}
					return
				} else if gowebdav.IsErrCode(err, http.StatusTooManyRequests) {
					// The endpoint shed the request. Classify it so it is
					// retryable rather than falling through to the generic
					// (non-retryable) bucket below; the WebDAV client does not
					// surface the response, so there is no reason or
					// Retry-After hint to carry.
					err = newThrottleErrorNoResponse(endpoint.Host,
						fmt.Sprintf("stat of %s was throttled at endpoint %s", dest.String(), endpoint.String()))
					resultsChan <- statResults{FileInfo{}, err}
					return
				} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
					// 500 is NOT "not found"; report it as a server error so
					// callers (e.g. uploadObject) can distinguish a genuine
					// absence from an error.
					err = errors.Errorf("stat of %s failed at endpoint %s: server returned 500", dest.String(), endpoint.String())
					resultsChan <- statResults{FileInfo{}, err}
					return
				} else if gowebdav.IsErrCode(err, http.StatusConflict) {
					// 409 Conflict — XRootD caches return this for PROPFIND
					// on directories.  Wrap the sentinel so the loop that
					// collects these results can decide to fall back to
					// the collections URL.
					log.Debugf("Stat of %s at %s returned 409 (directory on cache?); falling back", dest.String(), endpoint.String())
					err = errors.Wrapf(errStatOnCollectionAtCache, "stat of %s at endpoint %s", dest.String(), endpoint.String())
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
				ETag:         info.ETag,
			}, nil}

		}(&destCopy)
	}
	success := false
	notFound := false
	sawConflict := false
	for ctr := 0; ctr < len(statHosts); ctr++ {
		result := <-resultsChan
		if result.err == nil {
			if !success {
				success = true
				info = result.info
			}
		} else if err == nil && result.err != context.Canceled {
			err = result.err
			// Check for not found error
			if errors.Is(result.err, ErrObjectNotFound) {
				notFound = true
			}
		}
		if result.err != nil && errors.Is(result.err, errStatOnCollectionAtCache) {
			sawConflict = true
		}
	}
	// Fallback: if preferCollectionsUrlOnly, got not found, and object servers exist, try default logic
	if useCollectionsOnly && notFound && len(dirResp.ObjectServers) > 0 && !alreadyFellBack {
		// Retry without preferCollectionsUrlOnly; mark the retry as
		// already-fell-back so the sibling fallback below cannot then
		// flip us back to collections-only and ping-pong.
		return statHttpImpl(ctx, dest, dirResp, token, fedToken, false, true)
	}
	// Fallback: if no host succeeded, at least one stat host was a cache
	// that returned 409 on what is likely a collection, and the director
	// gave us a collections URL, retry via the collections URL (origin
	// WebDAV endpoint) which does serve directory listings.
	if !success && sawConflict && !useCollectionsOnly && collectionsUrl != nil && !alreadyFellBack {
		return statHttpImpl(ctx, dest, dirResp, token, fedToken, true, true)
	}
	// Past both fallbacks, a 409 is still an answer rather than just a failure:
	// it is how an XRootD cache says "collection" to a PROPFIND. Reaching here
	// with one means no collections URL was available to describe the path
	// properly, or the retry against it did not succeed either -- so this is a
	// last resort, not a shortcut past the fallbacks above. Without it, a
	// collection reached through an XRootD cache stats as a plain error, and
	// the callers that ask "is this a collection" conclude that it is not,
	// which is how the cache came to store a listing as the object.
	if !success && sawConflict {
		success = true
		info = FileInfo{Name: dest.Path, IsCollection: true}
	}
	if success {
		err = nil
	}
	return
}

// propfindObject asks a single endpoint, directly, whether objectUrl is a
// collection and how large it is.
//
// This deliberately does not go through statHttp: that fans out across every
// object server the director returned and waits for all of them with no
// deadline, which is far too much machinery -- and far too much latency -- to
// put in front of an ordinary download. Here the endpoint is already chosen and
// the caller's context bounds the wait.
//
// unixSocket, when non-empty, is the local cache's socket: the endpoint is
// reached by dialing it rather than by resolving the URL's host.
//
// No method on studio-b12/gowebdav's Client takes a context -- not in any
// release through v0.13.0, nor on master -- so the caller's deadline is
// attached through the interceptor, which runs on the request the library is
// about to send. Without that, a stalled endpoint would hang the download for
// as long as the transport allowed. The interceptor also restores the query,
// which carries the authorization some endpoints want and which gowebdav has
// no way to pass through.
//
// This is the WebDAV *client*; golang.org/x/net/webdav, which the origin side
// of this repo serves with, is a different package whose FileSystem methods do
// take a context. Upgrading gowebdav would not remove the need for this.
func propfindObject(ctx context.Context, objectUrl *url.URL, unixSocket string, token *tokenGenerator) (size int64, isCollection bool, err error) {
	base := *objectUrl
	base.Path = ""
	base.RawQuery = ""
	transport := config.GetTransport()
	if unixSocket != "" {
		// Same treatment downloadHTTP gives a unix:// endpoint: the scheme has
		// to become one net/http understands, and the host is a label for log
		// messages since the dialer ignores it.
		transport = transport.Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", unixSocket)
		}
		base.Scheme = "http"
		base.Host = "localhost"
	}
	client := gowebdav.NewAuthClient(base.String(), &bearerAuth{token: token})
	client.SetTransport(transport)
	query := objectUrl.RawQuery
	client.SetInterceptor(func(_ string, r *http.Request) {
		*r = *r.WithContext(ctx)
		if query != "" && r.URL.RawQuery == "" {
			r.URL.RawQuery = query
		}
	})

	info, statErr := client.Stat(objectUrl.Path)
	if statErr != nil {
		// An XRootD cache reports a collection by refusing the PROPFIND with
		// 409 rather than describing it, so the refusal is itself the answer.
		if gowebdav.IsErrCode(statErr, http.StatusConflict) {
			log.Debugln("PROPFIND of", objectUrl.Path, "at", objectUrl.Host, "returned 409; treating as a collection")
			return -1, true, nil
		}
		return -1, false, statErr
	}
	// gowebdav hands back a nil *File and no error when it finds nothing it
	// can use in the multistatus: a 207 whose only propstat is a 404, one with
	// no response element, or a body its parser choked on -- it discards decode
	// errors silently. The nil arrives inside a non-nil os.FileInfo, and File's
	// methods take a value receiver, so reading one panics on the spot rather
	// than yielding zero values. This probe runs on a bare goroutine per
	// endpoint, so that panic would take the process down on behalf of whatever
	// object server the director happened to name. Count it as no answer.
	if file, ok := info.(*gowebdav.File); info == nil || (ok && file == nil) {
		return -1, false, errors.Errorf("PROPFIND response from %s described nothing usable for %s", objectUrl.Host, objectUrl.Path)
	}
	return info.Size(), info.IsDir(), nil
}

// probeDrainLimit caps how much of an endpoint probe's response body is read
// before the rest is abandoned. The probe wants headers, not content.
const probeDrainLimit = 32 * 1024

// propfindBodyLimit bounds a Depth-0 PROPFIND response.
//
// Every PROPFIND this package sends to learn about a single path asks with
// Depth: 0, so a conforming answer describes exactly one resource: one href
// and a handful of properties, a few kilobytes at the outside. The limit is
// far above that because it is not a budget, it is a backstop -- gowebdav
// decodes the body into memory with no bound of its own, so without one a
// server that streams an endless href grows the heap until something dies,
// and these run on goroutines the caller does not wait on.
//
// Depth: 1 listings are a different matter and do not come through here; see
// walkDirDownload and friends, which stream a whole collection on purpose.
const propfindBodyLimit = 256 * 1024

// errPropfindTooLarge is what a reader gets for the part of a PROPFIND
// response past propfindBodyLimit.
var errPropfindTooLarge = errors.Errorf("PROPFIND response exceeded %d bytes", propfindBodyLimit)

// boundedBodyTransport caps the response bodies of everything sent through it.
// gowebdav offers no hook for this, so it goes in at the transport.
type boundedBodyTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t *boundedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: t.limit}
	return resp, nil
}

// boundedBody fails the read rather than truncating it. A short read would
// leave gowebdav's parser holding a half-document, and it discards decode
// errors silently, so the caller would be told "nothing here" for what is
// really "too much here".
type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errPropfindTooLarge
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// boundPropfindBody wraps a transport so a Depth-0 PROPFIND cannot read an
// unbounded response into memory.
func boundPropfindBody(base http.RoundTripper) http.RoundTripper {
	return &boundedBodyTransport{base: base, limit: propfindBodyLimit}
}

// probeToken picks the credential the endpoint probe should present.
//
// The download itself carries a federation token as an `access_token` query
// parameter, added per-attempt once an endpoint has been chosen. The probe runs
// before that and has only the user token, so on a namespace where the
// federation token is the only credential -- a public namespace read by a
// client that acquired none of its own -- every probe would be refused, and a
// refused probe now fails the download instead of merely misordering it.
// Falling back to the federation token as a bearer credential is what statHttp
// does for the same reason; see the note there about redirects.
func probeToken(token *tokenGenerator, fedToken TokenProvider) *tokenGenerator {
	if token != nil {
		if contents, err := token.Get(); err == nil && contents != "" {
			return token
		}
	}
	if fedToken != nil {
		if contents, err := fedToken.Get(); err == nil && contents != "" {
			probe := &tokenGenerator{Sync: new(singleflight.Group)}
			probe.SetToken(contents)
			return probe
		}
	}
	return token
}

// collectionAnswer is what an endpoint probe learned about whether a path is a
// collection. `answered` is separate from `isCollection` because not knowing is
// not the same as knowing it is an object: a caller that refuses collections
// refuses on either, rather than downloading something it cannot describe.
type collectionAnswer struct {
	answered     bool
	isCollection bool
	// throttleErr is a 429 seen while asking, kept because it changes what an
	// unanswered question means. A caller that refuses collections refuses
	// when nobody answered, and "every endpoint was too busy to say" is a
	// retryable condition carrying a Retry-After, where "every endpoint
	// declined to say" is not. Reporting the latter for the former would tell
	// a client to give up on a cache that only asked it to wait.
	throttleErr error
}

// objectCached checks if a given URL is present at the first cache in the
// director response.
//
// Note that xrootd returns an `Age` header for GETs but only a `Content-Length`
// header for HEADs.  If `Content-Range` is found, we will use that header; if not,
// we will issue two commands.
//
// wantCollectionInfo asks objectCached to determine whether the URL names a
// collection as well as sizing it. It costs nothing extra: the fall-back
// request objectCached already makes to learn the size becomes a PROPFIND,
// which reports both.
func objectCached(ctx context.Context, objectUrl *url.URL, token *tokenGenerator, wantCollectionInfo bool) (age int, size int64, answeredCollection bool, isCollection bool, err error) {

	age = -1

	headClient := config.GetClient()
	headRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, objectUrl.String(), nil)
	if err != nil {
		return
	}
	// RFC 7233 syntax. The unit prefix used to be missing, which XRootD
	// tolerates -- it skips whatever precedes the `=` without checking it --
	// but every standards-compliant server rejects, answering either with the
	// whole object or with a 416. That made the one request this probe is
	// supposed to cost into two everywhere except XRootD, and against a server
	// that answers 416 it made the endpoint look broken.
	headRequest.Header.Set("Range", "bytes=0-0")
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
	// An origin that answers namespace questions about itself says on the
	// refusal which credential would have worked.  Take it and ask once more,
	// so this probe learns the same way the transfer it precedes does.
	if acquireFromTokenHint(token, headResponse) {
		_, _ = io.Copy(io.Discard, io.LimitReader(headResponse.Body, probeDrainLimit))
		headResponse.Body.Close()
		retryRequest, retryErr := http.NewRequestWithContext(ctx, http.MethodGet, objectUrl.String(), nil)
		if retryErr != nil {
			err = retryErr
			return
		}
		retryRequest.Header.Set("Range", "bytes=0-0")
		if tokenContents, tokErr := token.Get(); tokErr == nil && tokenContents != "" {
			retryRequest.Header.Set("Authorization", "Bearer "+tokenContents)
		}
		headResponse, err = headClient.Do(retryRequest)
		if err != nil {
			return
		}
	}
	// The probe wants headers, but an *error* response's body carries the
	// structured reason that tells a throttle apart from any other refusal, so
	// keep a bounded prefix in that case only; on the success path nothing is
	// retained.
	var bodyPrefix []byte
	if headResponse.StatusCode >= 400 {
		bodyPrefix, _ = io.ReadAll(io.LimitReader(headResponse.Body, maxErrorBodySize))
	}
	// Whatever is left is drained so the connection can be reused, but only up
	// to a bound. Not every server honors a one-byte range, and one that does
	// not answers with the whole object; this probe runs against every endpoint
	// of every download, so an unbounded drain would stream objects in full
	// only to throw them away. Reading is allowed to fail -- the headers are
	// already in hand either way.
	if _, err := io.Copy(io.Discard, io.LimitReader(headResponse.Body, probeDrainLimit)); err != nil {
		log.Debugln("Failure when reading the one-byte-response body - expected because the body is discarded:", err)
	}
	headResponse.Body.Close()
	gotContentRange := false
	if headResponse.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		// Not an unhealthy endpoint, just one that would not serve the range
		// asked for. Nothing was learned, but nothing is wrong either: fall
		// through to the request below, which asks without a range.
		log.Debugln("Endpoint", objectUrl.Host, "did not satisfy the probe's byte range")
	} else if headResponse.StatusCode <= 300 {
		if contentRangeStr := headResponse.Header.Get("Content-Range"); contentRangeStr != "" {
			if after, found := strings.CutPrefix(contentRangeStr, "bytes 0-0/"); found {
				if afterParsed, err := strconv.Atoi(after); err == nil {
					size = int64(afterParsed)
					// Only a 206 means the range was actually served. A 200
					// carrying a Content-Range is a server contradicting
					// itself, and this value decides whether a download is
					// refused, so take it only when the status agrees.
					gotContentRange = headResponse.StatusCode == http.StatusPartialContent
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
	} else if headResponse.StatusCode == http.StatusTooManyRequests {
		// Throttled: classify as the retryable throttle type, carrying the
		// reason from the body and the Retry-After hint.
		//
		// Return rather than falling through to the HEAD retry below. The
		// cache answers HEAD without going through its fair scheduler, so a
		// HEAD would likely succeed and overwrite this error, reporting the
		// object's cache status as authoritative when in fact the request
		// that would tell us was shed.
		err = newThrottleErrorFromResponse(headResponse, string(bodyPrefix), objectUrl.Host)
		return
	} else {
		sce := StatusCodeError(headResponse.StatusCode)
		err = &HttpErrResp{
			Code: headResponse.StatusCode,
			Str:  fmt.Sprintf("request failed (%d)", headResponse.StatusCode),
			Err:  &sce,
		}
	}
	// Early return -- all the info we wanted was in the GET response. A server
	// that satisfied a byte range served an object: collections have no byte
	// ranges to serve, so there is nothing further to ask about.
	if gotContentRange {
		answeredCollection = wantCollectionInfo
		return
	}

	// The size is not in the GET response, so a second request is needed. When
	// the caller also wants to know whether this is a collection, ask by
	// PROPFIND rather than HEAD -- it answers both questions in the one
	// request a HEAD would have cost.
	if wantCollectionInfo {
		var propErr error
		if size, isCollection, propErr = propfindObject(ctx, objectUrl, "", token); propErr == nil {
			// Whether the path is a collection and whether this endpoint can
			// serve it are separate questions, so a PROPFIND answering the
			// first does not overturn a ranged GET that failed the second: err
			// is left as it was found. The caller records the answer either
			// way, and an endpoint that describes an object it will not serve
			// stays sorted behind ones that will.
			answeredCollection = true
			return
		}
		// The endpoint did not answer. Fall through to the HEAD so sizing and
		// endpoint selection keep working, but leave the collection question
		// unanswered -- the caller decides what to do about that, and refusing
		// is the safe choice when the alternative is writing an unknown
		// response to the caller's file.
		log.Debugln("PROPFIND unanswered at", objectUrl.Host, ":", propErr)
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
	} else if headResponse.StatusCode == http.StatusTooManyRequests {
		err = newThrottleErrorFromResponse(headResponse, "", objectUrl.Host)
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
