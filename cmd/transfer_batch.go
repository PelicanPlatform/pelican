//go:build client

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

package main

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
)

// submitAndDrain runs every source named on one command line through a single
// transfer client, and returns their results grouped by source position.
//
// The sources are submitted from their own goroutine while this one consumes
// results, because the two have to proceed together.  Submit blocks until the
// engine takes the job, and the engine's pipeline -- a one-job slot in the
// mux, a five-deep work queue, and Client.WorkerCount workers on an unbuffered
// hand-off -- is what decides how many transfers are in flight.  Nothing here
// imposes a limit of its own, and submitting everything up front before
// reading any result would only hold every result in memory until the last job
// was created.
//
// The first failure ends the batch, whether it is a failing result or a source
// that could not be planned or submitted: transfers already running are
// cancelled and sources not yet submitted are never started.  Only that first
// failure is reported; what follows it is the cancellation arriving.
//
// A job whose lookup fails produces no results at all -- there is nothing to
// report per file -- so lookup errors are collected once the stream has ended
// rather than interrupting it.  Such a batch therefore runs to completion
// before reporting, which is the one failure that does not stop the others.
//
// Nothing started here outlives the call: the submitter runs under a context
// this function cancels, and is joined before anything it wrote is read.
//
// failedIdx indexes sources, or is -1 when err is nil.
func submitAndDrain(
	ctx context.Context,
	tc *client.TransferClient,
	sources []string,
	newJob func(ctx context.Context, src string) (*client.TransferJob, error),
) (results [][]client.TransferResults, failedIdx int, err error) {

	results = make([][]client.TransferResults, len(sources))
	failedIdx = -1

	// The submitter's own context.  The caller's would not do: a failing
	// batch has to stop a submitter that is part-way through planning a
	// source -- a director query, a stat -- and nothing cancels the caller's.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// mu guards what both goroutines touch while they both run: the first
	// failure, and the job-to-source index the results are attributed by.
	var mu sync.Mutex
	// Sources are indexed rather than keyed by name: the same object may
	// legitimately be named twice on one command line.
	idxByJob := make(map[string]int, len(sources))
	// Written only by the submitter, and read only once it has been joined.
	jobByIdx := make([]*client.TransferJob, len(sources))

	// fail is the one way the batch ends early.  It records the first failure
	// and cancels everything that could still be running; later failures are
	// that cancellation arriving and are dropped, since they would otherwise
	// mask the cause.
	fail := func(idx int, cause error) {
		mu.Lock()
		if failedIdx < 0 {
			failedIdx, err = idx, cause
		}
		mu.Unlock()
		cancel()
		tc.Cancel()
	}

	submitterDone := make(chan struct{})
	go func() {
		defer close(submitterDone)
		// Closing the client is what ends the results stream, so it has to
		// happen however this goroutine leaves.
		defer tc.Close()
		for idx, src := range sources {
			tj, jobErr := newJob(ctx, src)
			if jobErr == nil {
				mu.Lock()
				idxByJob[tj.ID()] = idx
				mu.Unlock()
				jobByIdx[idx] = tj
				jobErr = tc.Submit(tj)
			}
			if jobErr != nil {
				fail(idx, jobErr)
				return
			}
		}
	}()

	for result := range tc.Results() {
		mu.Lock()
		idx, known := idxByJob[result.ID()]
		mu.Unlock()
		if !known {
			// A result for a job this batch never recorded would be a bug in
			// the engine's routing, not something to attribute to a source.
			log.Warnf("Discarding a transfer result for unknown job %s", result.ID())
			continue
		}
		results[idx] = append(results[idx], result)
		if result.Error != nil {
			fail(idx, result.Error)
			break
		}
	}

	// Join the submitter before reading anything it wrote.  If the stream
	// ended by itself the submitter has already finished -- closing the
	// client is what ended it -- and if the batch failed, fail() cancelled
	// the only two things it can be waiting on: its context, for planning,
	// and the client, for Submit.
	<-submitterDone

	if failedIdx < 0 {
		for idx, tj := range jobByIdx {
			if tj == nil {
				continue
			}
			if done, lookupErr := tj.GetLookupStatus(); done && lookupErr != nil {
				err, failedIdx = lookupErr, idx
				break
			}
		}
	}
	return
}
