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

package client

import (
	"context"
	"testing"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMuxTestEngine builds the minimum TransferEngine that runMux touches.
//
// Every mux channel is unbuffered on purpose: a send that completes proves
// runMux has already taken the previous message and finished acting on it,
// since it services them one at a time.
func newMuxTestEngine(ctx context.Context) *TransferEngine {
	return &TransferEngine{
		ctx:           ctx,
		work:          make(chan *clientTransferJob),
		results:       make(chan *clientTransferResults),
		jobLookupDone: make(chan *clientTransferJob),
		notifyChan:    make(chan bool),
		closeChan:     make(chan bool),
		closeDoneChan: make(chan bool, 1),
		resultsMap:    make(map[uuid.UUID]chan *TransferResults),
		workMap:       make(map[uuid.UUID]chan *TransferJob),
		// Long enough that the statistics tick never fires mid-test.
		ewmaTick: time.NewTicker(time.Hour),
		ewma:     ewma.NewMovingAverage(),
	}
}

// TestRunMuxPartialLookupFailureKeepsInFlightResults pins what happens when a
// recursive walk fails after it has already handed files to the workers.
//
// Those transfers are still running and each still owes the client a result.
// Treating the lookup error as the end of the job closes the client's results
// channel while they are in flight, and the next result to arrive is then a
// send on a closed channel -- which takes down the process, not just the
// transfer. A user hits this with `pelican object get -r` on a collection
// holding a large object alongside a subdirectory the origin will not list.
func TestRunMuxPartialLookupFailureKeepsInFlightResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	te := newMuxTestEngine(ctx)

	clientID := uuid.New()
	workChan := make(chan *TransferJob)
	resultsChan := make(chan *TransferResults)
	te.workMap[clientID] = workChan
	te.resultsMap[clientID] = resultsChan

	// runMux's panic would otherwise kill the test binary rather than report.
	muxPanic := make(chan any, 1)
	muxDone := make(chan struct{})
	go func() {
		defer close(muxDone)
		defer func() {
			if r := recover(); r != nil {
				muxPanic <- r
			}
		}()
		_ = te.runMux()
	}()

	job := &TransferJob{uuid: uuid.New(), ctx: ctx}

	// Submit the job, then take it off te.work the way the job handler would.
	// Once received, the job is in the mux's active list.
	workChan <- job
	select {
	case <-te.work:
	case <-ctx.Done():
		t.Fatal("runMux never forwarded the job to the lookup handler")
	}

	// The client closes its submission channel -- the shape every CLI
	// invocation takes, since Shutdown() closes it before waiting for results.
	close(workChan)
	require.Eventually(t, func() bool {
		te.clientLock.RLock()
		defer te.clientLock.RUnlock()
		return te.workMap[clientID] == nil
	}, 10*time.Second, time.Millisecond, "runMux never observed the client's close")

	// The walk submitted two files and then failed listing a subdirectory.
	// Both transfers are in flight and will report back.
	job.activeXfer.Store(2)
	job.lookupErr = errors.New("failed to read remote collection")
	te.jobLookupDone <- &clientTransferJob{uuid: clientID, job: job}

	// The first in-flight transfer finishes.
	te.results <- &clientTransferResults{
		id:      clientID,
		results: TransferResults{JobId: job.uuid, job: job},
	}

	select {
	case r := <-resultsChan:
		// A nil here means the channel was closed rather than delivered on --
		// which is the regression. Fail on it rather than dereferencing, so a
		// broken runMux reports instead of taking down the whole package.
		require.NotNil(t, r, "results channel was closed while a transfer was still in flight")
		assert.Equal(t, job.uuid, r.JobId)
	case p := <-muxPanic:
		t.Fatalf("runMux panicked routing an in-flight result: %v", p)
	case <-ctx.Done():
		t.Fatal("the in-flight result was never delivered to the client")
	}

	// The second finishes, which is what actually completes the job; only then
	// may the client's results channel close.
	te.results <- &clientTransferResults{
		id:      clientID,
		results: TransferResults{JobId: job.uuid, job: job},
	}
	select {
	case r := <-resultsChan:
		require.NotNil(t, r, "results channel was closed before the final result")
		assert.Equal(t, job.uuid, r.JobId)
	case p := <-muxPanic:
		t.Fatalf("runMux panicked routing the final result: %v", p)
	case <-ctx.Done():
		t.Fatal("the final result was never delivered to the client")
	}

	// With every transfer accounted for and the client closed, the results
	// channel is closed so Shutdown() can return.
	select {
	case _, ok := <-resultsChan:
		assert.False(t, ok, "results channel should be closed once the job is done")
	case p := <-muxPanic:
		t.Fatalf("runMux panicked closing out the job: %v", p)
	case <-ctx.Done():
		t.Fatal("results channel never closed; TransferClient.Shutdown would hang here")
	}

	cancel()
	<-muxDone
}

// TestRunMuxEmptyJobClosesResults pins the neighbouring case that the
// completion rule also has to cover: a lookup that produced no transfers at
// all. Nothing will ever arrive to retire such a job, so the lookup
// notification itself has to close the client out -- otherwise Shutdown()
// waits forever on a job that was over before it started.
func TestRunMuxEmptyJobClosesResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	te := newMuxTestEngine(ctx)

	clientID := uuid.New()
	workChan := make(chan *TransferJob)
	resultsChan := make(chan *TransferResults)
	te.workMap[clientID] = workChan
	te.resultsMap[clientID] = resultsChan

	muxDone := make(chan struct{})
	go func() {
		defer close(muxDone)
		_ = te.runMux()
	}()

	job := &TransferJob{uuid: uuid.New(), ctx: ctx}
	workChan <- job
	select {
	case <-te.work:
	case <-ctx.Done():
		t.Fatal("runMux never forwarded the job to the lookup handler")
	}
	close(workChan)
	require.Eventually(t, func() bool {
		te.clientLock.RLock()
		defer te.clientLock.RUnlock()
		return te.workMap[clientID] == nil
	}, 10*time.Second, time.Millisecond)

	// The lookup matched nothing: no transfers, no error.
	te.jobLookupDone <- &clientTransferJob{uuid: clientID, job: job}

	select {
	case _, ok := <-resultsChan:
		assert.False(t, ok, "a job that created no transfers must close the client out")
	case <-ctx.Done():
		t.Fatal("results channel never closed for a job with no transfers")
	}

	cancel()
	<-muxDone
}
