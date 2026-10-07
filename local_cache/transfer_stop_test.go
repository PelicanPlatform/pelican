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
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
)

// attempts builds a transfer result's error out of its attempts' errors.
func attempts(errs ...error) error {
	te := client.NewTransferErrors()
	for _, err := range errs {
		te.AddError(err)
	}
	return te
}

// TestDownloadStopKeepsBlocksOnlyForABenignCause checks the keep-or-delete
// decision for a whole-object download that ended early: the blocks it wrote
// are kept only when the cause is known to say nothing against them, and a
// failure a server reported about the transfer condemns them.
func TestDownloadStopKeepsBlocksOnlyForABenignCause(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	pc := &PersistentCache{storage: env.storage}

	reset := error_codes.NewContact_ConnectionResetError(&client.NetworkResetError{})
	// What the client makes of an X-Transfer-Status trailer reporting a
	// failure, such as an upstream cache's own verification failing.
	trailer := func(text string) error {
		var base error = errors.New(text)
		if text == "unexpected EOF" {
			base = &client.UnexpectedEOFError{Err: base}
		}
		return error_codes.NewTransferError(fmt.Errorf("download error after server response started: %w", base))
	}
	notFound := client.StatusCodeError(404)

	keep := map[string]error{
		"idle cancel":                  errAdoptedTransferIdle,
		"no result":                    errAdoptedTransferUnreported,
		"shutdown":                     attempts(error_codes.NewTransferError(context.Canceled)),
		"connection reset":             attempts(reset),
		"reset during the body":        attempts(&client.ConnectionSetupError{Err: &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}}),
		"body cut short":               attempts(error_codes.NewTransferError(io.ErrUnexpectedEOF)),
		"too slow":                     attempts(error_codes.NewTransfer_SlowTransferError(&client.SlowTransferError{})),
		"stalled":                      attempts(error_codes.NewTransfer_StoppedTransferError(&client.StoppedTransferError{})),
		"read timeout":                 attempts(&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}),
		"several attempts, all benign": attempts(reset, error_codes.NewTransferError(io.ErrUnexpectedEOF)),
	}
	for name, err := range keep {
		assert.False(t, pc.adoptedTransferDataIsBad(env.hash, err), "%s: the whole blocks must be kept", name)
	}

	bad := map[string]error{
		"checksum mismatch":         attempts(error_codes.NewTransfer_ChecksumMismatchError(&client.ChecksumMismatchError{})),
		"version changed":           attempts(error_codes.NewTransferError(client.ErrObjectVersionChanged)),
		"trailer failure":           attempts(trailer("500: checksum verification failed")),
		"trailer unexpected EOF":    attempts(trailer("unexpected EOF")),
		"status on a retry":         attempts(reset, &notFound),
		"unrecognised":              errors.New("no space left on device"),
		"benign then trailer error": attempts(reset, trailer("500: upstream failure")),
	}
	for name, err := range bad {
		assert.True(t, pc.adoptedTransferDataIsBad(env.hash, err), "%s: the data must not be kept", name)
	}

	unsized := newTornBlockEnv(t, -1)
	pc = &PersistentCache{storage: unsized.storage}
	assert.True(t, pc.adoptedTransferDataIsBad(unsized.hash, errAdoptedTransferIdle),
		"blocks of an object of unknown size cannot be placed, so they are not kept")
}

// TestFailedDownloadLeavesANewerVersionsMapping checks that dropping a
// download whose data failed leaves the object's latest-version mapping
// alone when it already names a newer version, which a concurrent request
// found in the meantime.
func TestFailedDownloadLeavesANewerVersionsMapping(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	pc := &PersistentCache{storage: env.storage, db: env.db}
	const source = "pelican://example.org/test/object"
	require.NoError(t, env.storage.MergeMetadata(env.hash, &CacheMetadata{SourceURL: source, ETag: `"old"`}))
	objectHash := env.db.ObjectHash(source)
	require.NoError(t, env.db.SetLatestETag(objectHash, `"new"`, time.Now()))

	dl := &persistentDownload{instanceHash: env.hash, objectHash: objectHash, completionDone: make(chan struct{})}
	mismatch := error_codes.NewTransfer_ChecksumMismatchError(&client.ChecksumMismatchError{})
	pc.endAdoptedDownload(dl, attempts(mismatch))

	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the failed version is dropped")
	assert.NotNil(t, dl.completionErr.Load(), "and its readers are told")
	etag, found, err := env.db.GetLatestETag(objectHash)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, `"new"`, etag, "the newer version's mapping must stay")
}
