/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"context"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/param"
)

const (
	// ChunkSize is the notification granularity - notify waiters every 128KB
	ChunkSize = 128 * 1024

	// DefaultPrefetchTimeout is the default time after which a prefetch with no active
	// clients will be cancelled
	DefaultPrefetchTimeout = 20 * time.Second

	// PrefetchSemaphoreReleaseInterval is how often to release and reacquire the prefetch semaphore
	PrefetchSemaphoreReleaseInterval = 5 * time.Second

	// ETAUpdateInterval is how often to update the ETA estimate
	ETAUpdateInterval = 250 * time.Millisecond

	// DefaultInitialRate is the initial assumed download rate (1 MB/s)
	DefaultInitialRate = 1024 * 1024

	// ETAStaleThreshold is how long an ETA can be late before waiters give up
	ETAStaleThreshold = 5 * time.Second
)

// BlockFetcherV2 handles fetching missing blocks from the origin using the Pelican transfer client.
// It supports:
// - Per-128KB notification channels for partial completion
// - Client registration for data requests
// - Prefetch with semaphore management
// - Configurable timeout for prefetch cancellation when no active clients
//
// Each BlockFetcherV2 creates its own TransferClient from the shared
// TransferEngine.  This prevents concurrent doFetch goroutines (e.g. during
// auto-repair) from stealing results off a shared Results() channel.
type BlockFetcherV2 struct {
	storage      *StorageManager
	instanceHash InstanceHash
	originURL    string
	token        string
	fedToken     client.TokenProvider // Federation token provider; resolves to access_token query param
	meta         *CacheMetadata
	tc           *client.TransferClient

	// Prefetch configuration
	prefetchTimeout time.Duration
	prefetchSem     chan struct{} // Shared semaphore to limit concurrent prefetches across all fetchers

	mu sync.Mutex

	// Fetch tracking - one entry per fetch operation
	activeFetches map[fetchKey]*fetchOperation

	// Client activity tracking: stores the UnixNano timestamp of the last
	// client-initiated fetch operation.  The idle timer cancels only when
	// this timestamp, and the last time a reader attached to or detached
	// from blockState, are older than prefetchTimeout, ensuring a brief gap
	// between sequential reads doesn't kill the transfer.
	lastClientActivity atomic.Int64

	// blockState is the object's shared block state, which counts the
	// object's open readers (see ObjectBlockState.AttachReader).  While any
	// is open the fetcher is never idle.  Holding it also keeps it the one
	// state every reader of the object gets.
	blockState *ObjectBlockState
}

// fetchKey uniquely identifies a fetch operation
type fetchKey struct {
	startBlock uint32
	endBlock   uint32
}

// ChunkNotification contains information about a chunk's completion status
type ChunkNotification struct {
	ChunkIndex int64     // Which chunk this notification is for
	Completed  bool      // True if this chunk is complete
	Error      error     // Non-nil if an error occurred
	ETA        time.Time // Estimated time of completion (updated atomically)
}

// fetchOperation tracks an active fetch operation
type fetchOperation struct {
	// Chunk completion tracking - maps chunk index to a channel that will be closed when complete
	// Using close() for notification is safer than sending values (no panic on closed channel)
	chunkComplete map[int64]chan struct{}

	// Completion state
	done      bool
	err       error
	doneCh    chan struct{} // Closed when fetch completes
	cancelFn  context.CancelFunc
	mu        sync.Mutex
	lastChunk int64 // Last completed chunk index

	// ETA estimation using EWMA
	bytesDownloaded atomic.Int64
	totalBytes      int64
	startByte       int64 // Absolute byte offset where this fetch starts
	startTime       time.Time
	rate            ewma.MovingAverage // bytes per second
	etaUnixNano     atomic.Int64       // Estimated completion time as UnixNano (for atomic access)
}

// BlockFetcherV2Config holds configuration for the block fetcher
type BlockFetcherV2Config struct {
	PrefetchTimeout time.Duration
	// PrefetchSem is a shared semaphore limiting the total number of
	// concurrent prefetches across all fetchers and downloads.  When
	// nil, a per-fetcher semaphore is created with capacity 5.
	PrefetchSem chan struct{}
}

// NewBlockFetcherV2 creates a new block fetcher using the Pelican transfer client.
// It creates its own TransferClient from the given TransferEngine to avoid
// sharing Results() channels with other callers.
func NewBlockFetcherV2(
	storage *StorageManager,
	instanceHash InstanceHash, originURL, token string,
	fedToken client.TokenProvider,
	te *client.TransferEngine,
	cfg BlockFetcherV2Config,
) (*BlockFetcherV2, error) {
	meta, err := storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	if cfg.PrefetchTimeout == 0 {
		cfg.PrefetchTimeout = param.LocalCache_PrefetchTimeout.GetDuration()
		if cfg.PrefetchTimeout == 0 {
			cfg.PrefetchTimeout = DefaultPrefetchTimeout
		}
	}

	prefetchSem := cfg.PrefetchSem
	if prefetchSem == nil {
		// No shared semaphore provided; create a local one.
		maxPrefetch := param.LocalCache_MaxConcurrentPrefetch.GetInt()
		if maxPrefetch == 0 {
			maxPrefetch = 5
		}
		prefetchSem = make(chan struct{}, maxPrefetch)
	}

	blockState, err := storage.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	// Create a dedicated TransferClient so this fetcher's doFetch goroutines
	// have their own Results() channel and cannot steal results intended for
	// other callers sharing the same TransferEngine.
	tc, err := te.NewClient(client.WithAcquireToken(false), client.WithCacheEmbeddedClientMode(useEmbeddedCacheMode()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create transfer client for block fetcher")
	}

	return &BlockFetcherV2{
		storage:         storage,
		blockState:      blockState,
		instanceHash:    instanceHash,
		originURL:       originURL,
		token:           token,
		fedToken:        fedToken,
		meta:            meta,
		tc:              tc,
		prefetchTimeout: cfg.PrefetchTimeout,
		prefetchSem:     prefetchSem,
		activeFetches:   make(map[fetchKey]*fetchOperation),
	}, nil
}

// touchClientActivity records that a client is actively using this fetcher.
// The prefetch idle timer uses this timestamp to decide when to cancel.
func (bf *BlockFetcherV2) touchClientActivity() {
	bf.lastClientActivity.Store(time.Now().UnixNano())
}

// idleSince returns how long it has been since the last client-initiated
// fetch through this fetcher or, when no reader of the object is open, since
// the last one closed.  It returns zero while a reader is open, and a very
// large duration if there was never any activity (i.e. pure prefetch with no
// client interest).
func (bf *BlockFetcherV2) idleSince() time.Duration {
	var last time.Time
	if ns := bf.lastClientActivity.Load(); ns != 0 {
		last = time.Unix(0, ns)
	}
	if bf.blockState != nil {
		open, change := bf.blockState.readerActivity()
		if open {
			return 0
		}
		if change.After(last) {
			last = change
		}
	}
	if last.IsZero() {
		return time.Duration(1<<63 - 1) // max duration
	}
	return time.Since(last)
}

// idleCheckInterval is how often a transfer checks whether it has gone
// idle: a fraction of the timeout, so the cancel lands soon after the timeout
// rather than up to a whole check interval later, but no more often than
// every few milliseconds, nor less often than every two seconds.
func (bf *BlockFetcherV2) idleCheckInterval() time.Duration {
	return min(max(bf.prefetchTimeout/4, 10*time.Millisecond), 2*time.Second)
}

// idle reports whether no reader of the object is open and none has been,
// nor has any client fetched through this fetcher, for prefetchTimeout.  A
// reader keeps the object's fill going for as long as it is open, however
// slowly it reads, so a transfer outruns a slow client instead of being
// cancelled under it.
func (bf *BlockFetcherV2) idle() bool {
	return bf.idleSince() > bf.prefetchTimeout
}

// Close shuts down the fetcher's dedicated TransferClient.
// Must be called when the fetcher is no longer needed.
func (bf *BlockFetcherV2) Close() {
	if bf.tc != nil {
		bf.tc.Close()
	}
}

// FetchBlocks fetches the specified range of blocks from the origin.
// Blocks until all requested blocks are available or an error occurs.
// Implicitly marks this fetcher as having active client interest.
func (bf *BlockFetcherV2) FetchBlocks(ctx context.Context, startBlock, endBlock uint32) error {
	bf.touchClientActivity()
	_, err := bf.FetchBlocksAsync(ctx, startBlock, endBlock)
	if err != nil {
		return err
	}
	// FetchBlocksAsync already waits for completion when doneCh is returned
	return nil
}

// FetchBlocksAsync fetches blocks asynchronously and returns a channel that will be closed
// when the fetch completes (either successfully or with error).
// The returned error is non-nil only if the fetch couldn't be started.
// Check the fetchOperation for the final error after doneCh is closed.
// Implicitly marks this fetcher as having active client interest.
func (bf *BlockFetcherV2) FetchBlocksAsync(ctx context.Context, startBlock, endBlock uint32) (*fetchOperation, error) {
	bf.touchClientActivity()
	key := fetchKey{startBlock, endBlock}

	bf.mu.Lock()

	// Check if this exact range is already being fetched
	if op, exists := bf.activeFetches[key]; exists {
		bf.mu.Unlock()
		// Wait for existing operation
		select {
		case <-op.doneCh:
			return op, op.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check for overlapping fetches — use ETA-based coalescing to decide
	// whether to piggyback on the existing operation or start a new one.
	// If the existing operation will produce our needed blocks "soon enough"
	// (within ETAStaleThreshold), we wait on its chunk notification.
	// Otherwise we start an independent fetch so the reader doesn't stall
	// behind a slow sequential download.
	for k, op := range bf.activeFetches {
		if !bf.rangesOverlap(k, key) {
			continue
		}

		// Compute the chunk index for the first byte of our requested range.
		startChunkByte := int64(startBlock) * BlockDataSize
		chunkIdx := startChunkByte / ChunkSize

		if op.IsChunkETAStale(chunkIdx) {
			// ETA is already stale — the overlapping operation is too slow
			// to supply our blocks in time.  Skip it and start our own
			// fetch below.
			continue
		}

		// ETA looks good — wait on the overlapping operation's chunk
		// channel instead of starting a redundant download.
		bf.mu.Unlock()
		completed, err := bf.WaitForChunkWithETA(ctx, op, chunkIdx)
		if err != nil {
			return nil, err
		}
		if completed {
			// Chunk arrived.  Retry to pick up any remaining blocks
			// not covered by the overlapping operation.
			return bf.FetchBlocksAsync(ctx, startBlock, endBlock)
		}
		// ETA went stale while waiting — retry; next iteration will
		// skip the stale operation and start our own fetch.
		return bf.FetchBlocksAsync(ctx, startBlock, endBlock)
	}

	// Calculate total bytes for this fetch
	startOffset := int64(startBlock) * BlockDataSize
	endOffset := int64(endBlock+1) * BlockDataSize
	if endOffset > bf.meta.ContentLength {
		endOffset = bf.meta.ContentLength
	}
	totalBytes := endOffset - startOffset

	// Create new fetch operation with ETA tracking
	fetchCtx, cancelFn := context.WithCancel(ctx)
	op := &fetchOperation{
		chunkComplete: make(map[int64]chan struct{}),
		doneCh:        make(chan struct{}),
		cancelFn:      cancelFn,
		totalBytes:    totalBytes,
		startByte:     startOffset,
		startTime:     time.Now(),
		rate:          ewma.NewMovingAverage(10), // 10-second moving average
	}

	// Initialize rate with default (1 MB/s)
	op.rate.Set(float64(DefaultInitialRate))

	// Initialize ETA based on default rate
	estimatedDuration := time.Duration(float64(totalBytes) / float64(DefaultInitialRate) * float64(time.Second))
	op.etaUnixNano.Store(time.Now().Add(estimatedDuration).UnixNano())

	bf.activeFetches[key] = op
	bf.mu.Unlock()

	// Start the fetch in a goroutine
	go bf.doFetch(fetchCtx, op, key)

	// Wait for completion
	select {
	case <-op.doneCh:
		return op, op.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetChunkChannel returns a channel that will be closed when the specified chunk is complete.
// This is the safe notification pattern - callers wait for close, no values are sent.
// Returns nil if the chunk is already complete.
func (bf *BlockFetcherV2) GetChunkChannel(op *fetchOperation, chunkIndex int64) <-chan struct{} {
	op.mu.Lock()
	defer op.mu.Unlock()

	// If chunk is already complete, return nil (caller should check data directly)
	if chunkIndex <= op.lastChunk && op.lastChunk > 0 {
		return nil
	}

	// If already done with error, return closed channel
	if op.done {
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	// Get or create channel for this chunk
	if ch, exists := op.chunkComplete[chunkIndex]; exists {
		return ch
	}

	ch := make(chan struct{})
	op.chunkComplete[chunkIndex] = ch
	return ch
}

// GetETA returns the estimated time of completion for the entire fetch operation.
// For per-chunk estimates, use GetChunkETA instead.
func (op *fetchOperation) GetETA() time.Time {
	return time.Unix(0, op.etaUnixNano.Load())
}

// GetChunkETA returns the estimated time when a specific chunk will be
// available.  If the chunk is already downloaded (chunkIndex <= lastChunk)
// the returned time is in the past.  The estimate is based on the current
// download position and the EWMA rate.
func (op *fetchOperation) GetChunkETA(chunkIndex int64) time.Time {
	lastDone := op.lastChunk
	if chunkIndex <= lastDone && lastDone > 0 {
		return time.Time{} // already available
	}

	op.mu.Lock()
	rateValue := op.rate.Value()
	op.mu.Unlock()

	if rateValue <= 0 {
		return op.GetETA() // fall back to whole-operation ETA
	}

	// Bytes from current download position to the end of the requested chunk.
	chunkEndByte := (chunkIndex + 1) * ChunkSize
	downloaded := op.bytesDownloaded.Load()
	bytesUntilChunk := chunkEndByte - (op.startByte + downloaded)
	if bytesUntilChunk <= 0 {
		return time.Time{} // already past this chunk
	}

	return time.Now().Add(time.Duration(float64(bytesUntilChunk) / rateValue * float64(time.Second)))
}

// GetProgress returns the current download progress (bytes downloaded, total bytes, rate in bytes/sec)
func (op *fetchOperation) GetProgress() (downloaded int64, total int64, rateBytes float64) {
	op.mu.Lock()
	rateBytes = op.rate.Value()
	op.mu.Unlock()
	return op.bytesDownloaded.Load(), op.totalBytes, rateBytes
}

// IsChunkETAStale returns true if the per-chunk ETA for the given chunk
// has passed by more than ETAStaleThreshold.
func (op *fetchOperation) IsChunkETAStale(chunkIndex int64) bool {
	eta := op.GetChunkETA(chunkIndex)
	if eta.IsZero() {
		return false // Chunk already complete
	}
	return time.Now().After(eta.Add(ETAStaleThreshold))
}

// WaitForChunkWithETA waits for a chunk to complete, but gives up if the
// per-chunk ETA becomes stale.  Returns true if the chunk completed, false
// if the ETA became stale (caller should try direct download).
func (bf *BlockFetcherV2) WaitForChunkWithETA(ctx context.Context, op *fetchOperation, chunkIndex int64) (completed bool, err error) {
	bf.touchClientActivity()
	ch := bf.GetChunkChannel(op, chunkIndex)
	if ch == nil {
		// Already complete
		return true, nil
	}

	etaCheckTicker := time.NewTicker(ETAUpdateInterval)
	defer etaCheckTicker.Stop()

	for {
		select {
		case <-ch:
			// Chunk completed
			bf.touchClientActivity()
			if op.err != nil {
				return false, op.err
			}
			return true, nil
		case <-op.doneCh:
			// Entire operation completed
			return op.err == nil, op.err
		case <-etaCheckTicker.C:
			// Check if per-chunk ETA is stale
			if op.IsChunkETAStale(chunkIndex) {
				return false, nil // Let caller try direct download
			}
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

// rangesOverlap checks if two fetch ranges overlap
func (bf *BlockFetcherV2) rangesOverlap(a, b fetchKey) bool {
	return a.startBlock <= b.endBlock && b.startBlock <= a.endBlock
}

// doFetch performs the actual fetch operation
func (bf *BlockFetcherV2) doFetch(ctx context.Context, op *fetchOperation, key fetchKey) {
	defer func() {
		bf.mu.Lock()
		delete(bf.activeFetches, key)
		bf.mu.Unlock()
		close(op.doneCh)
	}()

	// Calculate byte range
	startOffset := int64(key.startBlock) * BlockDataSize
	endOffset := int64(key.endBlock+1)*BlockDataSize - 1
	if endOffset >= bf.meta.ContentLength {
		endOffset = bf.meta.ContentLength - 1
	}

	// Determine whether a client is actively waiting.  If no client
	// has ever touched this fetcher, this is a prefetch and we limit
	// concurrency via the shared semaphore.
	hasRecentActivity := bf.lastClientActivity.Load() > 0

	var prefetchMode bool
	if !hasRecentActivity {
		prefetchMode = true
		select {
		case bf.prefetchSem <- struct{}{}:
			// Got semaphore
			defer func() { <-bf.prefetchSem }()
		case <-ctx.Done():
			op.err = ctx.Err()
			return
		}
	}

	// The BlockWriter's writeCurrentBlock checks the live shared block
	// state on every write to skip already-downloaded blocks, so there
	// is no need to pass a snapshot bitmap.  This avoids cloning a
	// potentially large bitmap into memory.
	//
	// Create a buffered BlockWriter from the storage layer.  It handles
	// arbitrary write sizes, encrypts at block boundaries, and skips
	// blocks already present according to the shared state.
	storageWriter, err := bf.storage.NewBlockWriter(bf.instanceHash, key.startBlock, nil, nil)
	if err != nil {
		op.err = errors.Wrap(err, "failed to create block writer for fetch")
		bf.notifyAllChunks(op)
		return
	}

	// Wrap the BlockWriter to provide chunk notification and ETA tracking
	writer := &blockWriter{
		inner:          storageWriter,
		startOffset:    startOffset,
		currentPos:     startOffset,
		op:             op,
		bf:             bf,
		prefetchMode:   prefetchMode,
		lastSemRelease: time.Now(),
		lastRateUpdate: time.Now(),
		lastFlush:      time.Now(),
	}
	// writer is closed (or aborted) by awaitTransfer once the transfer is
	// under way; until then every early return aborts it.

	// Parse the origin URL and set up the transfer
	sourceURL, err := url.Parse(bf.originURL)
	if err != nil {
		writer.Abort()
		op.err = errors.Wrap(err, "invalid source URL")
		bf.notifyAllChunks(op)
		return
	}
	sourceURL.Scheme = "pelican"
	// The client's cache mode (set on the transfer client, see
	// useEmbeddedCacheMode) causes queryDirector to route through the
	// director's origin endpoint, so origins that disable direct clients are
	// reachable.  In site-local mode embedded mode is disabled and the
	// director redirects us to other caches instead.

	// Build transfer options with a byte range so we only download the
	// blocks we actually need instead of the entire object.
	//
	// The range has to come from the version of the object being filled.
	// The origin may have replaced the object since it was first fetched,
	// and splicing the new version's bytes into the old one's blocks would
	// serve a mix of the two as one object.  The engine refuses, on every
	// attempt and before writing any of its body, a response carrying
	// another entity tag.  This needs an origin that sends entity tags: an
	// XRootD-backed origin (XrdHttp) sends none, so its objects have no
	// tag to hold a range to, and a replaced object is spliced as before.
	opts := []client.TransferOption{
		client.WithWriter(writer),
		client.WithByteRange(startOffset, endOffset),
	}
	if bf.meta.ETag != "" {
		opts = append(opts, client.WithExpectedETag(bf.meta.ETag))
	}
	if bf.token != "" {
		opts = append(opts, client.WithToken(bf.token))
	}
	if bf.fedToken != nil {
		opts = append(opts, client.WithFedToken(bf.fedToken))
	}

	tj, err := bf.tc.NewTransferJob(ctx, sourceURL, "", false, false, opts...)
	if err != nil {
		writer.Abort()
		op.err = errors.Wrap(err, "failed to create transfer job")
		bf.notifyAllChunks(op)
		return
	}

	if err := bf.tc.Submit(tj); err != nil {
		writer.Abort()
		op.err = errors.Wrap(err, "failed to submit transfer job")
		bf.notifyAllChunks(op)
		return
	}

	bf.awaitTransfer(ctx, op, bf.tc.Results(), tj.ID(), writer, prefetchMode, nil)
	bf.dropIfVersionChanged(op.err)
}

// dropIfVersionChanged removes the cached instance when a fetch found the
// origin serving a different version of it (err is the fetch's result).
// Nothing more of this instance can be fetched, so it can never be
// completed; dropping it (and the latest-version pointer to it) makes the
// next request fetch the current version.
func (bf *BlockFetcherV2) dropIfVersionChanged(err error) {
	if err == nil || !errors.Is(err, client.ErrObjectVersionChanged) {
		return
	}
	log.Warnf("The origin no longer serves the version of %s being cached (%v); dropping the cached copy so it is fetched again",
		bf.originURL, err)
	if err := bf.storage.Delete(bf.instanceHash); err != nil {
		log.Warnf("Failed to drop %s after its origin changed: %v", bf.instanceHash, err)
	}
}

// awaitTransfer drives an in-flight transfer to completion.
// It reads from the results channel, matches the given job ID,
// applies idle-timeout cancellation (when prefetchMode is true),
// updates chunk notifications via the blockWriter, and calls
// onDone on successful completion.
func (bf *BlockFetcherV2) awaitTransfer(
	ctx context.Context,
	op *fetchOperation,
	results <-chan client.TransferResults,
	jobID string,
	writer *blockWriter,
	prefetchMode bool,
	onDone func(),
) {
	// Only a transfer that finished cleanly may close the writer; on any
	// other way out the body stopped somewhere arbitrary, possibly
	// mid-block, and the writer must discard what it has not completed.
	succeeded := false
	defer func() {
		if succeeded {
			if err := writer.Close(); err != nil {
				log.Warnf("Failed to finish writing blocks of %s: %v", bf.instanceHash, err)
			}
		} else {
			writer.Abort()
		}
	}()

	idleTicker := time.NewTicker(bf.idleCheckInterval())
	defer idleTicker.Stop()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				// Results channel closed
				return
			}
			if result.ID() == jobID {
				if result.Error != nil {
					op.err = result.Error
				} else {
					succeeded = true
					if onDone != nil {
						onDone()
					}
				}
				// Notify all remaining waiters (both success and error)
				bf.notifyAllChunks(op)
				return
			}

		case <-idleTicker.C:
			// In prefetch mode, cancel once no client is using the object.
			if prefetchMode && bf.idle() {
				log.Debugf("Prefetch timeout for %s — idle for %v, cancelling", bf.instanceHash, bf.idleSince())
				op.cancelFn()
				op.err = errors.New("prefetch cancelled due to idle timeout")
				bf.notifyAllChunks(op)
				return
			}

		case <-ctx.Done():
			op.err = ctx.Err()
			bf.notifyAllChunks(op)
			return
		}
	}
}

// AdoptTransfer takes ownership of an already-in-flight full-object transfer
// initiated by performDownload and drives it to completion using the fetcher's
// existing idle-timeout and chunk-notification machinery.
//
// Instead of creating a new BlockWriter, AdoptTransfer wraps the
// decisionWriter's existing BlockWriter with the fetcher's blockWriter adapter
// via dw.HandoffBlockWriter.  All subsequent data written by the transfer
// engine flows through the adapter, gaining chunk notification and ETA
// tracking.  Blocks already written before the handoff are harmlessly skipped
// (the shared bitmap check in writeCurrentBlock handles this).
//
// Parameters:
//   - ctx:         the transfer's context (cancelled on cache close)
//   - cancelTransfer: cancels the transfer itself; called when the object
//     goes idle -- no reader open (see ObjectBlockState.AttachReader) for
//     prefetchTimeout
//   - tc:          the TransferClient that owns the transfer (closed on exit)
//   - dw:          the decisionWriter whose BlockWriter will be wrapped
//   - resultChan:  pre-filtered channel delivering the single matching result
//   - egrp:        errgroup for goroutine lifecycle management (test cleanup)
//   - wg:          waitgroup to track goroutine completion (decremented on exit)
//   - onExit:      called when the adopted transfer exits for any reason
//     (clear downloading flag, close completionDone, etc.)
//
// The method starts a goroutine (managed via egrp) and returns the
// fetchOperation for chunk notification and ETA queries.
func (bf *BlockFetcherV2) AdoptTransfer(
	ctx context.Context,
	cancelTransfer context.CancelFunc,
	tc *client.TransferClient,
	dw *decisionWriter,
	resultChan <-chan *client.TransferResults,
	egrp *errgroup.Group,
	wg *sync.WaitGroup,
	onExit func(err error),
) *fetchOperation {
	// Record initial client activity so the idle timer does not
	// immediately cancel the newly adopted transfer.  A client
	// triggered this download; it will register via FetchBlocks or
	// CreateFetchCallback shortly.
	bf.touchClientActivity()
	totalBlocks := uint32((bf.meta.ContentLength + BlockDataSize - 1) / BlockDataSize)
	if totalBlocks == 0 {
		totalBlocks = 1
	}

	key := fetchKey{startBlock: 0, endBlock: totalBlocks - 1}
	totalBytes := bf.meta.ContentLength

	innerCtx, cancelFn := context.WithCancel(ctx)
	op := &fetchOperation{
		chunkComplete: make(map[int64]chan struct{}),
		doneCh:        make(chan struct{}),
		cancelFn:      cancelFn,
		totalBytes:    totalBytes,
		startByte:     0,
		startTime:     time.Now(),
		rate:          ewma.NewMovingAverage(10),
	}
	op.rate.Set(float64(DefaultInitialRate))
	estimatedDuration := time.Duration(float64(totalBytes) / float64(DefaultInitialRate) * float64(time.Second))
	op.etaUnixNano.Store(time.Now().Add(estimatedDuration).UnixNano())

	bf.mu.Lock()
	bf.activeFetches[key] = op
	bf.mu.Unlock()

	// Wrap the decisionWriter's BlockWriter with a blockWriter adapter
	// that provides chunk notification and ETA tracking.  The swap is
	// atomic with respect to dw.Write.
	adapter := dw.HandoffBlockWriter(func(bw *BlockWriter, bytesWritten int64) io.WriteCloser {
		return &blockWriter{
			inner:          bw,
			startOffset:    0,
			currentPos:     bytesWritten,
			op:             op,
			bf:             bf,
			prefetchMode:   false, // adopted transfers always have a client
			lastSemRelease: time.Now(),
			lastRateUpdate: time.Now(),
			lastFlush:      time.Now(),
		}
	})

	wg.Add(1)
	egrp.Go(func() error {
		defer wg.Done()
		defer func() {
			bf.mu.Lock()
			delete(bf.activeFetches, key)
			bf.mu.Unlock()
			close(op.doneCh)
			// Close the transfer client first to ensure no more writes
			// flow through the adapter.  Without this ordering, an
			// idle-timeout cancel can close the adapter while the HTTP
			// body reader is still calling dw.Write → adapter.Write →
			// BlockWriter.Write, producing spurious "writer is closed"
			// errors.
			tc.Close()
			// Now safe to close the adapter → closes the underlying
			// *BlockWriter → fires onComplete if all blocks are
			// downloaded.  A transfer that failed, timed out or was
			// cancelled stopped at an arbitrary byte, so its writer is
			// aborted instead: see BlockWriter.Abort.
			if aborter, ok := adapter.(interface{ Abort() }); ok && op.err != nil {
				aborter.Abort()
			} else {
				adapter.Close()
			}
			if onExit != nil {
				onExit(op.err)
			}
		}()

		// finish records the transfer's result, persisting the checksums of
		// a clean one, and wakes every waiter.
		finish := func(result *client.TransferResults) {
			switch {
			case result == nil:
				// The transfer client shut down without reporting this
				// job -- performDownload forwards that as nil.  Nothing
				// says the body arrived whole, so it is a failure, not a
				// success: closing the writer would finalize an object
				// of unknown size wherever its input stopped.
				op.err = errAdoptedTransferUnreported
				log.Warnf("Adopted transfer for %s ended without a result", bf.instanceHash)
			case result.Error != nil:
				op.err = result.Error
				log.Warnf("Adopted transfer failed for %s: %v", bf.instanceHash, result.Error)
			default:
				// Persist checksums from the transfer result into the cache
				// metadata.  We must do this here -- when the result arrives
				// -- rather than relying on the BlockWriter's onComplete
				// callback: the client only knows the checksums after the
				// body finishes downloading (it fetches the origin's Digest
				// and finalizes its own hashes post-transfer), but onComplete
				// fires the moment the final block is written, before the
				// result is delivered.  Persisting here (via the additive
				// MergeMetadata) guarantees a subsequent HEAD/GET can relay a
				// Digest header.
				checksums := clientChecksumsToCache(result)
				dw.dl.checksums = checksums
				if len(checksums) > 0 {
					if err := bf.storage.MergeMetadata(bf.instanceHash,
						&CacheMetadata{Checksums: checksums}); err != nil {
						log.Warnf("Failed to persist checksums for %s: %v", bf.instanceHash, err)
					}
				}
			}
			bf.notifyAllChunks(op)
		}

		// finishStopped records the result of a transfer the fetcher itself
		// stopped, for the reason given.  The result still decides: a
		// transfer that finished before the cancel took effect is a success,
		// and one that failed for a reason of its own -- say its checksum
		// did not match the body that had all arrived -- reports that
		// reason.  Only a transfer that reports nothing, or the cancellation
		// itself, is put down to the stop.
		finishStopped := func(result *client.TransferResults, stop error) {
			if result != nil && (result.Error == nil || !errors.Is(result.Error, context.Canceled)) {
				finish(result)
				return
			}
			op.err = stop
			bf.notifyAllChunks(op)
		}

		idleTicker := time.NewTicker(bf.idleCheckInterval())
		defer idleTicker.Stop()

		for {
			select {
			case result := <-resultChan:
				finish(result)
				return nil

			case <-idleTicker.C:
				if !bf.idle() {
					continue
				}
				// Nobody is reading the object any more: stop fetching it.
				// The cancel takes effect at the transfer engine, so wait for
				// its result before touching the writer.
				log.Debugf("Adopted transfer idle for %s (no reader for %v); cancelling",
					bf.instanceHash, bf.idleSince())
				cancelTransfer()
				finishStopped(<-resultChan, errAdoptedTransferIdle)
				return nil

			case <-innerCtx.Done():
				// The cache is shutting down.  Wait for the transfer engine
				// to give up too, so it is not still writing when the
				// deferred cleanup closes the adapter and client.
				finishStopped(<-resultChan, innerCtx.Err())
				return nil
			}
		}
	})

	return op
}

// errAdoptedTransferUnreported is an adopted transfer's error when the
// transfer client went away without reporting the job's result.
var errAdoptedTransferUnreported = errors.New("the transfer ended without reporting a result")

// errAdoptedTransferIdle is an adopted transfer's error when it was cancelled
// because no reader was using the object any more.
var errAdoptedTransferIdle = errors.New("download cancelled: no reader for the idle timeout")

// notifyAllChunks closes all chunk notification channels (for both success and error cases)
// Using close() is safe - multiple closes are handled, and receivers see the close immediately
func (bf *BlockFetcherV2) notifyAllChunks(op *fetchOperation) {
	op.mu.Lock()
	defer op.mu.Unlock()

	op.done = true
	for _, ch := range op.chunkComplete {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
	}
	op.chunkComplete = nil
}

// blockWriter implements io.WriteCloser and delegates to the storage
// layer's BlockWriter for buffered, block-aligned, encrypted writes.
// It adds chunk-level notification and ETA tracking on top.
type blockWriter struct {
	inner           *BlockWriter // buffered block writer from storage.go
	startOffset     int64
	currentPos      int64
	op              *fetchOperation
	bf              *BlockFetcherV2
	prefetchMode    bool
	lastSemRelease  time.Time
	lastRateUpdate  time.Time
	lastFlush       time.Time
	bytesThisPeriod int64
}

func (w *blockWriter) Write(p []byte) (n int, err error) {
	// Delegate to the buffered BlockWriter which handles arbitrary
	// chunk sizes, block alignment, encryption, and bitmap updates.
	if _, err := w.inner.Write(p); err != nil {
		return 0, errors.Wrap(err, "failed to write blocks")
	}

	bytesWritten := int64(len(p))

	// Update bytes downloaded for ETA tracking
	w.op.bytesDownloaded.Add(bytesWritten)
	w.bytesThisPeriod += bytesWritten

	// Update rate estimate periodically (~250ms)
	if time.Since(w.lastRateUpdate) >= ETAUpdateInterval {
		elapsed := time.Since(w.lastRateUpdate).Seconds()
		if elapsed > 0 {
			currentRate := float64(w.bytesThisPeriod) / elapsed
			w.op.mu.Lock()
			w.op.rate.Add(currentRate)
			rateValue := w.op.rate.Value()
			w.op.mu.Unlock()

			// Update ETA atomically
			bytesRemaining := w.op.totalBytes - w.op.bytesDownloaded.Load()
			if rateValue > 0 && bytesRemaining > 0 {
				remainingSeconds := float64(bytesRemaining) / rateValue
				newETA := time.Now().Add(time.Duration(remainingSeconds * float64(time.Second)))
				w.op.etaUnixNano.Store(newETA.UnixNano())
			}
		}
		w.bytesThisPeriod = 0
		w.lastRateUpdate = time.Now()
	}

	// Periodically flush the underlying BlockWriter so that blocks
	// become visible to concurrent streaming readers without waiting
	// for the full writeBatchBlocks batch to accumulate.
	if time.Since(w.lastFlush) >= ETAUpdateInterval {
		if err := w.inner.Flush(); err != nil {
			return 0, errors.Wrap(err, "failed to flush blocks")
		}
		w.lastFlush = time.Now()
	}

	// Calculate which chunks this write completes
	oldChunk := w.currentPos / ChunkSize
	w.currentPos += bytesWritten
	newChunk := (w.currentPos - 1) / ChunkSize

	// Notify for each completed chunk by closing the channel
	if newChunk > oldChunk {
		w.op.mu.Lock()
		for chunk := oldChunk + 1; chunk <= newChunk; chunk++ {
			if ch, ok := w.op.chunkComplete[chunk]; ok {
				close(ch)
				delete(w.op.chunkComplete, chunk)
			}
			w.op.lastChunk = chunk
		}
		w.op.mu.Unlock()
	}

	// In prefetch mode, periodically release and reacquire the semaphore
	// so other prefetches/downloads can make progress.
	if w.prefetchMode && time.Since(w.lastSemRelease) > PrefetchSemaphoreReleaseInterval {
		// Release semaphore briefly to let others run
		<-w.bf.prefetchSem

		// Reacquire semaphore
		w.bf.prefetchSem <- struct{}{}
		w.lastSemRelease = time.Now()
	}

	return len(p), nil
}

func (w *blockWriter) Close() error {
	return w.inner.Close()
}

// Abort closes the writer after a failed or cancelled transfer; see
// BlockWriter.Abort.
func (w *blockWriter) Abort() {
	w.inner.Abort()
}

// CloseWithError is how the transfer engine closes the writer when a
// transfer ends -- before BlockFetcherV2 sees the result -- with the
// transfer's error, or nil on success.
func (w *blockWriter) CloseWithError(err error) error {
	if err != nil {
		w.Abort()
		return nil
	}
	return w.Close()
}

// CreateFetchCallback returns a callback function for the RangeReader
func (bf *BlockFetcherV2) CreateFetchCallback() func(ctx context.Context, startBlock, endBlock uint32) error {
	return bf.FetchBlocks
}

// StartPrefetch starts prefetching the entire object in the background.
// The prefetch will be cancelled if there are no active clients for the prefetch timeout period.
func (bf *BlockFetcherV2) StartPrefetch(ctx context.Context) {
	totalBlocks := uint32((bf.meta.ContentLength + BlockDataSize - 1) / BlockDataSize)
	if totalBlocks == 0 {
		return
	}

	go func() {
		err := bf.FetchBlocks(ctx, 0, totalBlocks-1)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Debugf("Prefetch failed for %s: %v", bf.instanceHash, err)
		}
	}()
}
