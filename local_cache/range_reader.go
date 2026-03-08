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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// RangeRequest represents a parsed HTTP Range header
type RangeRequest struct {
	Start int64
	End   int64 // -1 means "to end of file"
}

// ParseRangeHeader parses an HTTP Range header
// Supports: "bytes=start-end", "bytes=start-", "bytes=-suffix"
func ParseRangeHeader(rangeHeader string, contentLength int64) ([]RangeRequest, error) {
	if rangeHeader == "" {
		return nil, nil
	}

	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, errors.New("unsupported range unit")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	var ranges []RangeRequest

	for _, part := range strings.Split(rangeSpec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var r RangeRequest

		if strings.HasPrefix(part, "-") {
			// Suffix range: "-500" means last 500 bytes
			suffix, err := strconv.ParseInt(part[1:], 10, 64)
			if err != nil {
				return nil, errors.Wrap(err, "invalid suffix range")
			}
			if suffix > contentLength {
				suffix = contentLength
			}
			r.Start = contentLength - suffix
			r.End = contentLength - 1
		} else if strings.HasSuffix(part, "-") {
			// Open-ended range: "500-" means from byte 500 to end
			start, err := strconv.ParseInt(part[:len(part)-1], 10, 64)
			if err != nil {
				return nil, errors.Wrap(err, "invalid range start")
			}
			r.Start = start
			r.End = contentLength - 1
		} else {
			// Full range: "500-1000"
			parts := strings.Split(part, "-")
			if len(parts) != 2 {
				return nil, errors.New("invalid range format")
			}

			start, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return nil, errors.Wrap(err, "invalid range start")
			}

			end, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, errors.Wrap(err, "invalid range end")
			}

			r.Start = start
			r.End = end
		}

		// Validate range
		if r.Start < 0 || r.Start >= contentLength {
			return nil, errors.Errorf("range start %d out of bounds (content length: %d)", r.Start, contentLength)
		}
		if r.End >= contentLength {
			r.End = contentLength - 1
		}
		if r.Start > r.End {
			return nil, errors.Errorf("invalid range: start %d > end %d", r.Start, r.End)
		}

		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		return nil, errors.New("no valid ranges in header")
	}

	return ranges, nil
}

// FormatContentRange formats a Content-Range header value
func FormatContentRange(start, end, total int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

// RangeReader implements io.ReadSeeker over a byte range of a cached object.
// It is the primary read-path abstraction that ties the block-level storage
// layer to HTTP response serving.
//
// Callers obtain a RangeReader via PersistentCache.GetRange (for explicit
// byte-range requests) or via PersistentCache.GetSeekableReader (wrapped in
// a SeekableReader so that http.ServeContent can handle Range negotiation).
//
// For normal (cached / cacheable) responses the RangeReader reads encrypted
// blocks from the StorageManager, fetching missing blocks on demand via the
// fetchBlocks callback wired to a BlockFetcherV2 instance.  It also performs
// a single round of transparent auto-repair when AES-GCM authentication
// detects on-disk corruption.
//
// For responses marked Cache-Control: no-store, the origin's body is piped
// directly through the noStoreReader field; the block-storage path is
// bypassed entirely.
type RangeReader struct {
	storage      *StorageManager
	instanceHash InstanceHash
	meta         *CacheMetadata
	start        int64
	end          int64
	position     int64
	blockState   *ObjectBlockState

	// Fetch callback for missing blocks
	fetchBlocks func(ctx context.Context, startBlock, endBlock uint32) error

	// noStoreReader is the read end of an io.Pipe for streaming no-store
	// responses.  When set, Read delegates here and Seek returns an error
	// because a pipe is forward-only.
	noStoreReader io.ReadCloser

	// size is the content length of a no-store response.  It is only valid
	// when noStoreReader is set.
	size int64

	// onClose is called when the reader is closed (e.g., to deregister
	// from the BlockFetcherV2 client tracking).
	onClose func()

	// repairAttempted is set after a repair cycle completes without fixing
	// every corrupt block (i.e. the 32 MB cap was exhausted).  It prevents
	// unbounded re-fetch loops on persistent disk corruption.  After a
	// successful repair pass the flag is cleared so subsequent reads can
	// repair further blocks.
	repairAttempted bool

	mu sync.Mutex
}

// NewRangeReader creates a reader for a range request
// fetchBlocks is called when blocks need to be fetched from origin
func NewRangeReader(
	storage *StorageManager,
	instanceHash InstanceHash,
	start, end int64,
	fetchBlocks func(ctx context.Context, startBlock, endBlock uint32) error,
) (*RangeReader, error) {
	meta, err := storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	// Validate range
	if start < 0 {
		start = 0
	}
	if end < 0 || end >= meta.ContentLength {
		end = meta.ContentLength - 1
	}
	if start > end {
		return nil, errors.New("invalid range")
	}

	// Get shared block state (thread-safe, shared across all readers for this object)
	blockState, err := storage.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	return &RangeReader{
		storage:      storage,
		instanceHash: instanceHash,
		meta:         meta,
		start:        start,
		end:          end,
		position:     start,
		blockState:   blockState,
		fetchBlocks:  fetchBlocks,
	}, nil
}

// Read implements io.Reader with on-demand block fetching
func (rr *RangeReader) Read(p []byte) (n int, err error) {
	return rr.ReadContext(context.Background(), p)
}

// ReadContext reads with context for cancellation
func (rr *RangeReader) ReadContext(ctx context.Context, p []byte) (n int, err error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	// Streaming no-store mode: forward-only pipe from origin
	if rr.noStoreReader != nil {
		return rr.noStoreReader.Read(p)
	}

	if rr.position > rr.end {
		return 0, io.EOF
	}

	// Calculate how much to read
	toRead := int64(len(p))
	remaining := rr.end - rr.position + 1
	if toRead > remaining {
		toRead = remaining
	}

	// For inline storage, we don't need to check blocks - data is complete
	if rr.meta.IsInline() {
		data, err := rr.storage.ReadInline(rr.instanceHash)
		if err != nil {
			return 0, err
		}

		startInData := rr.position
		endInData := rr.position + toRead
		if endInData > int64(len(data)) {
			endInData = int64(len(data))
		}

		n = copy(p, data[startInData:endInData])
		rr.position += int64(n)

		if rr.position > rr.end {
			return n, io.EOF
		}
		return n, nil
	}

	// For disk storage, calculate which blocks we need
	startBlock := ContentOffsetToBlock(rr.position)
	endOffset := rr.position + toRead - 1
	endBlock := ContentOffsetToBlock(endOffset)

	// Ensure all needed blocks are available (fetch missing ones)
	if err := rr.ensureBlocks(ctx, startBlock, endBlock); err != nil {
		return 0, err
	}

	// Read data from disk
	data, err := rr.storage.ReadBlocks(rr.instanceHash, rr.position, int(toRead))
	if err != nil {
		// Attempt auto-repair: identify corrupt blocks, re-download, retry once
		data, err = rr.repairAndRetry(ctx, startBlock, endBlock, int(toRead), err)
		if err != nil {
			return 0, err
		}
	}

	n = copy(p, data)
	rr.position += int64(n)

	if rr.position > rr.end {
		return n, io.EOF
	}

	return n, nil
}

// ensureBlocks checks that all blocks in [startBlock, endBlock] are in the
// shared block state.  If a background download is in progress (indicated by
// ObjectBlockState.downloading), it waits for each block to be written before
// falling back to an on-demand fetch from the origin.
func (rr *RangeReader) ensureBlocks(ctx context.Context, startBlock, endBlock uint32) error {
	for block := startBlock; block <= endBlock; block++ {
		if rr.blockState.Contains(block) {
			continue
		}

		// Try waiting for the background download to produce this block.
		if rr.blockState.WaitForBlock(ctx, block) {
			continue
		}

		// If the context is done, bail out.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Block still not available and no background download in
		// progress — fall back to fetching from origin.
		if rr.fetchBlocks == nil {
			return errors.Errorf("block %d not available and no fetch callback", block)
		}
		// Find contiguous range of missing blocks
		fetchStart := block
		fetchEnd := block
		for fetchEnd < endBlock && !rr.blockState.Contains(fetchEnd+1) {
			fetchEnd++
		}

		log.Debugf("Fetching blocks %d-%d for range read", fetchStart, fetchEnd)
		if err := rr.fetchBlocks(ctx, fetchStart, fetchEnd); err != nil {
			return errors.Wrapf(err, "failed to fetch blocks %d-%d", fetchStart, fetchEnd)
		}

		// The shared block state is updated by the BlockWriter,
		// so we don't need to manually update here.
		block = fetchEnd
	}
	return nil
}

// maxRepairBlocks is the maximum number of blocks repaired in a single
// auto-repair pass (~32 MB of payload data).  For very large objects (e.g.
// 100 GB) the entire block bitmap could be flagged corrupt when the data
// file is missing, and re-fetching all of it in one go would be impractical.
// Instead we cap each pass and clear repairAttempted on success so that
// subsequent Read calls can repair the next batch.
const maxRepairBlocks = 32 * 1024 * 1024 / BlockDataSize // ~8 224

// repairAndRetry is called when ReadBlocks returns a decryption/corruption
// error.  It serializes repair through the shared ObjectBlockState.repairMu
// so that concurrent readers don't race.  After acquiring the lock, it
// re-checks whether the blocks are actually corrupt (another goroutine may
// have already repaired them).
//
// Repair is capped at maxRepairBlocks per invocation.  After a successful
// (partial or full) repair the repairAttempted flag is cleared so later
// reads can heal additional blocks progressively.
func (rr *RangeReader) repairAndRetry(ctx context.Context, startBlock, endBlock uint32, toRead int, origErr error) ([]byte, error) {
	// Circuit breaker: only attempt auto-repair once per reader between
	// successful repairs.  Persistent disk corruption (e.g. a bad sector)
	// would otherwise cause an unbounded re-fetch loop.
	if rr.repairAttempted {
		return nil, errors.Wrap(origErr, "auto-repair already attempted for this reader; refusing to retry")
	}
	rr.repairAttempted = true

	if rr.fetchBlocks == nil {
		log.Warnf("Auto-repair: skipping repair for %s — no fetch callback available", rr.instanceHash)
		return nil, origErr // can't repair without a fetch callback
	}

	// Serialize repair operations for this object.  If another goroutine is
	// already repairing, we wait and then re-try the read — the corruption
	// may have been fixed.
	rr.blockState.LockRepair()
	defer rr.blockState.UnlockRepair()

	// After acquiring repairMu, re-try the read first.  A concurrent repair
	// may have already fixed the blocks while we were waiting.
	data, retryErr := rr.storage.ReadBlocks(rr.instanceHash, rr.position, toRead)
	if retryErr == nil {
		log.Debugf("Auto-repair: blocks %d-%d in %s were fixed by concurrent repair", startBlock, endBlock, rr.instanceHash)
		rr.repairAttempted = false
		return data, nil
	}

	// Still failing — identify exactly which blocks are corrupt
	corrupt, idErr := rr.storage.IdentifyCorruptBlocks(rr.instanceHash, startBlock, endBlock)
	if idErr != nil {
		log.Warnf("Auto-repair: failed to identify corrupt blocks for %s: %v", rr.instanceHash, idErr)
		return nil, origErr
	}
	if len(corrupt) == 0 {
		// IdentifyCorruptBlocks found nothing wrong — the on-disk data
		// decrypts fine.  The original error was likely a stale bitmap entry.
		// Re-try the read with current shared state.
		log.Debugf("Auto-repair: no corrupt blocks found in %s (blocks %d-%d), retrying read",
			rr.instanceHash, startBlock, endBlock)
		data, err := rr.storage.ReadBlocks(rr.instanceHash, rr.position, toRead)
		if err != nil {
			return nil, errors.Wrap(err, "auto-repair: read fails even after corruption check found no issues")
		}
		rr.repairAttempted = false
		return data, nil
	}

	// Cap the number of blocks we repair in one pass.  When the file is
	// missing, IdentifyCorruptBlocks returns EVERY block in the bitmap,
	// which could be millions for a large object.  We limit to ~32 MB so
	// the re-fetch stays bounded and clear the circuit breaker on success
	// so the next Read can heal further blocks.
	capped := false
	if len(corrupt) > maxRepairBlocks {
		log.Warnf("Auto-repair: %d corrupt blocks in %s exceeds per-pass limit of %d; repairing first %d",
			len(corrupt), rr.instanceHash, maxRepairBlocks, maxRepairBlocks)
		corrupt = corrupt[:maxRepairBlocks]
		capped = true
	}

	log.Warnf("Auto-repair: detected %d corrupt block(s) in %s; re-downloading from origin",
		len(corrupt), rr.instanceHash)

	// Clear corrupt blocks from the persistent bitmap so the fetcher
	// treats them as missing
	if err := rr.storage.db.ClearBlocks(rr.instanceHash, corrupt); err != nil {
		log.Warnf("Failed to clear corrupt block state for %s: %v", rr.instanceHash, err)
		return nil, origErr
	}

	// Update the shared block state (visible to all readers immediately)
	rr.blockState.RemoveMany(corrupt)

	// Re-fetch the corrupt blocks.  Expand [startBlock, endBlock] to cover
	// all blocks we just cleared so ensureBlocks can find and fetch them.
	fetchStart := startBlock
	fetchEnd := endBlock
	for _, b := range corrupt {
		if b < fetchStart {
			fetchStart = b
		}
		if b > fetchEnd {
			fetchEnd = b
		}
	}
	if err := rr.ensureBlocks(ctx, fetchStart, fetchEnd); err != nil {
		return nil, errors.Wrap(err, "auto-repair: failed to re-fetch corrupt blocks")
	}

	// Retry the read
	data, err := rr.storage.ReadBlocks(rr.instanceHash, rr.position, toRead)
	if err != nil {
		if capped {
			// More corrupt blocks remain beyond the cap.  The next Read()
			// should be allowed to repair further.
			rr.repairAttempted = false
		}
		return nil, errors.Wrap(err, "auto-repair: read still fails after re-download")
	}

	// Repair succeeded — allow future reads to repair additional blocks if
	// the corrupt set was capped.
	rr.repairAttempted = false
	return data, nil
}

// Close closes the range reader
func (rr *RangeReader) Close() error {
	var err error
	if rr.noStoreReader != nil {
		err = rr.noStoreReader.Close()
	}
	if rr.onClose != nil {
		rr.onClose()
	}
	return err
}

// Seek implements io.Seeker (limited to within the range)
func (rr *RangeReader) Seek(offset int64, whence int) (int64, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	// Streaming no-store mode: cannot seek a pipe
	if rr.noStoreReader != nil {
		return 0, errors.New("seek not supported on streaming no-store response")
	}

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = rr.start + offset
	case io.SeekCurrent:
		newPos = rr.position + offset
	case io.SeekEnd:
		newPos = rr.end + 1 + offset
	default:
		return 0, errors.New("invalid whence")
	}

	if newPos < rr.start {
		newPos = rr.start
	}
	if newPos > rr.end+1 {
		newPos = rr.end + 1
	}

	rr.position = newPos
	return newPos - rr.start, nil
}

// ContentLength returns the length of the range
func (rr *RangeReader) ContentLength() int64 {
	if rr.noStoreReader != nil {
		return rr.size
	}
	return rr.end - rr.start + 1
}

// ContentRange returns the Content-Range header value
func (rr *RangeReader) ContentRange() string {
	return FormatContentRange(rr.start, rr.end, rr.meta.ContentLength)
}

// IsRangeRequest checks if a request contains a Range header
func IsRangeRequest(req *http.Request) bool {
	return req.Header.Get("Range") != ""
}
