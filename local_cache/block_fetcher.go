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
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

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
	instanceHash string
	originURL    string
	token        string
	meta         *CacheMetadata
	tc           *client.TransferClient

	// Prefetch configuration
	prefetchTimeout time.Duration
	prefetchSem     chan struct{} // Semaphore to limit concurrent prefetches

	mu sync.Mutex

	// Fetch tracking - one entry per fetch operation
	activeFetches map[fetchKey]*fetchOperation

	// Client tracking
	activeClients atomic.Int32
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
	startTime       time.Time
	rate            ewma.MovingAverage // bytes per second
	etaUnixNano     atomic.Int64       // Estimated completion time as UnixNano (for atomic access)
}

// BlockFetcherV2Config holds configuration for the block fetcher
type BlockFetcherV2Config struct {
	PrefetchTimeout       time.Duration
	MaxConcurrentPrefetch int
}

// NewBlockFetcherV2 creates a new block fetcher using the Pelican transfer client.
// It creates its own TransferClient from the given TransferEngine to avoid
// sharing Results() channels with other callers.
func NewBlockFetcherV2(
	storage *StorageManager,
	instanceHash, originURL, token string,
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

	if cfg.MaxConcurrentPrefetch == 0 {
		cfg.MaxConcurrentPrefetch = param.LocalCache_MaxConcurrentPrefetch.GetInt()
		if cfg.MaxConcurrentPrefetch == 0 {
			cfg.MaxConcurrentPrefetch = 5
		}
	}

	// Create prefetch semaphore
	prefetchSem := make(chan struct{}, cfg.MaxConcurrentPrefetch)

	// Create a dedicated TransferClient so this fetcher's doFetch goroutines
	// have their own Results() channel and cannot steal results intended for
	// other callers sharing the same TransferEngine.
	tc, err := te.NewClient(client.WithAcquireToken(false))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create transfer client for block fetcher")
	}

	return &BlockFetcherV2{
		storage:         storage,
		instanceHash:    instanceHash,
		originURL:       originURL,
		token:           token,
		meta:            meta,
		tc:              tc,
		prefetchTimeout: cfg.PrefetchTimeout,
		prefetchSem:     prefetchSem,
		activeFetches:   make(map[fetchKey]*fetchOperation),
	}, nil
}

// RegisterClient registers a client as waiting for data from this fetcher.
// Returns a function to call when the client is done.
func (bf *BlockFetcherV2) RegisterClient() func() {
	bf.activeClients.Add(1)
	return func() {
		bf.activeClients.Add(-1)
	}
}

// Close shuts down the fetcher's dedicated TransferClient.
// Must be called when the fetcher is no longer needed.
func (bf *BlockFetcherV2) Close() {
	if bf.tc != nil {
		bf.tc.Close()
	}
}

// HasActiveClients returns true if there are clients waiting for data
func (bf *BlockFetcherV2) HasActiveClients() bool {
	return bf.activeClients.Load() > 0
}

// FetchBlocks fetches the specified range of blocks from the origin.
// Blocks until all requested blocks are available or an error occurs.
func (bf *BlockFetcherV2) FetchBlocks(ctx context.Context, startBlock, endBlock uint32) error {
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
func (bf *BlockFetcherV2) FetchBlocksAsync(ctx context.Context, startBlock, endBlock uint32) (*fetchOperation, error) {
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

	// Check for overlapping fetches and potentially join them
	for k, op := range bf.activeFetches {
		if bf.rangesOverlap(k, key) {
			bf.mu.Unlock()

			// Wait for the overlapping fetch to complete, then retry for remaining blocks
			select {
			case <-op.doneCh:
				if op.err != nil {
					return op, op.err
				}
				// Retry - some blocks may now be available
				return bf.FetchBlocksAsync(ctx, startBlock, endBlock)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
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

// GetETA returns the estimated time of completion for the fetch operation.
// The ETA is updated periodically based on the EWMA of download rates.
func (op *fetchOperation) GetETA() time.Time {
	return time.Unix(0, op.etaUnixNano.Load())
}

// GetProgress returns the current download progress (bytes downloaded, total bytes, rate in bytes/sec)
func (op *fetchOperation) GetProgress() (downloaded int64, total int64, rateBytes float64) {
	op.mu.Lock()
	rateBytes = op.rate.Value()
	op.mu.Unlock()
	return op.bytesDownloaded.Load(), op.totalBytes, rateBytes
}

// IsETAStale returns true if the ETA has passed by more than ETAStaleThreshold
func (op *fetchOperation) IsETAStale() bool {
	eta := op.GetETA()
	return time.Now().After(eta.Add(ETAStaleThreshold))
}

// WaitForChunkWithETA waits for a chunk to complete, but gives up if the ETA becomes stale.
// Returns true if the chunk completed, false if ETA became stale (caller should try direct download).
func (bf *BlockFetcherV2) WaitForChunkWithETA(ctx context.Context, op *fetchOperation, chunkIndex int64) (completed bool, err error) {
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
			if op.err != nil {
				return false, op.err
			}
			return true, nil
		case <-op.doneCh:
			// Entire operation completed
			return op.err == nil, op.err
		case <-etaCheckTicker.C:
			// Check if ETA is stale
			if op.IsETAStale() {
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

	// Check if we have active clients
	hasClients := bf.HasActiveClients()

	// If no active clients, this is a prefetch - acquire semaphore
	var prefetchMode bool
	if !hasClients {
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

	// Get a snapshot of the current download bitmap so the BlockWriter can
	// skip already-downloaded blocks (important during auto-repair
	// re-downloads where most blocks are already present).  We use a
	// snapshot (Clone) because the skip check is purely an optimization —
	// writing a block that already exists is harmless but wasteful.
	sharedState, err := bf.storage.GetSharedBlockState(bf.instanceHash)
	if err != nil {
		op.err = errors.Wrap(err, "failed to get block state for fetch")
		bf.notifyAllChunks(op)
		return
	}
	existingBitmap := sharedState.Clone()

	// Create a buffered BlockWriter from the storage layer.  It handles
	// arbitrary write sizes, encrypts at block boundaries, and skips
	// blocks present in existingBitmap.
	storageWriter, err := bf.storage.NewBlockWriter(bf.instanceHash, key.startBlock, existingBitmap, nil)
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
	}
	defer writer.Close()

	// Parse the origin URL and set up the transfer
	sourceURL, err := url.Parse(bf.originURL)
	if err != nil {
		op.err = errors.Wrap(err, "invalid source URL")
		bf.notifyAllChunks(op)
		return
	}
	sourceURL.Scheme = "pelican"
	// Add directread query parameter to bypass cache (we ARE the cache)
	q := sourceURL.Query()
	q.Set("directread", "")
	sourceURL.RawQuery = q.Encode()

	// Build transfer options with a byte range so we only download the
	// blocks we actually need instead of the entire object.
	opts := []client.TransferOption{
		client.WithWriter(writer),
		client.WithByteRange(startOffset, endOffset),
	}
	if bf.token != "" {
		opts = append(opts, client.WithToken(bf.token))
	}

	tj, err := bf.tc.NewTransferJob(ctx, sourceURL, "", false, false, opts...)
	if err != nil {
		op.err = errors.Wrap(err, "failed to create transfer job")
		bf.notifyAllChunks(op)
		return
	}

	if err := bf.tc.Submit(tj); err != nil {
		op.err = errors.Wrap(err, "failed to submit transfer job")
		bf.notifyAllChunks(op)
		return
	}

	// Wait for completion with prefetch timeout handling
	results := bf.tc.Results()
	prefetchTimer := time.NewTimer(bf.prefetchTimeout)
	defer prefetchTimer.Stop()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				// Results channel closed
				return
			}
			if result.ID() == tj.ID() {
				if result.Error != nil {
					op.err = result.Error
				}
				// Notify all remaining waiters (both success and error)
				bf.notifyAllChunks(op)
				return
			}

		case <-prefetchTimer.C:
			// Check if we're in prefetch mode and have no active clients
			if prefetchMode && !bf.HasActiveClients() {
				log.Debugf("Prefetch timeout for %s - cancelling", bf.instanceHash)
				op.cancelFn()
				op.err = errors.New("prefetch cancelled due to no active clients")
				bf.notifyAllChunks(op)
				return
			}
			// Reset timer
			prefetchTimer.Reset(bf.prefetchTimeout)

		case <-ctx.Done():
			op.err = ctx.Err()
			bf.notifyAllChunks(op)
			return
		}
	}
}

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
	if w.prefetchMode && time.Since(w.lastSemRelease) > PrefetchSemaphoreReleaseInterval {
		// Release semaphore
		<-w.bf.prefetchSem

		// Check if we should continue prefetching
		if !w.bf.HasActiveClients() {
			// No active clients - check if we've been idle too long
			// We'll let the main loop handle the timeout
		}

		// Reacquire semaphore
		w.bf.prefetchSem <- struct{}{}
		w.lastSemRelease = time.Now()
	}

	return len(p), nil
}

func (w *blockWriter) Close() error {
	return w.inner.Close()
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
