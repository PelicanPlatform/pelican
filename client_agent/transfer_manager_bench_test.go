//go:build !windows

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

package client_agent

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// BenchmarkTransferJobThroughput measures how quickly the transfer server's job
// pipeline can accept, schedule, execute, and record a batch of transfer jobs.
//
// It deliberately isolates SERVER overhead from data movement. Each job's
// transfer uses an operation the executor does not handle, so executeTransfer
// returns immediately (no client.DoGet/DoPut/DoCopy — hence no director lookup,
// no network, no disk). What remains — and what this benchmark measures — is the
// per-job machinery the transfer server always pays regardless of the payload:
//
//   - goroutine dispatch through the errgroup (CreateJob -> eg.Go -> executeJob)
//   - the MaxConcurrentJobs semaphore
//   - the TransferManager mutex guarding every job/transfer status transition
//   - the pending -> running -> completed/failed state machine
//
// The job lifecycle is identical for a successful and a failed transfer (only
// the client.DoX call in the middle differs), so the fast-failing payload is a
// faithful stand-in for the server's fixed per-job cost.
//
// The transfer server constructs its TransferManager with a nil store
// (transfer/transfer.go), so nil-store here mirrors production. (Job/transfer
// rows are persisted by the transfer HTTP handlers, not the manager; that DB
// cost and the HTTP layer are out of scope for this manager-level benchmark.)
//
// Sub-benchmarks vary MaxConcurrentJobs to show how throughput scales with the
// worker pool and to surface any serialization on the shared mutex. Run with:
//
//	go test -tags "client,server" -run '^$' -bench BenchmarkTransferJobThroughput ./client_agent/
func BenchmarkTransferJobThroughput(b *testing.B) {
	const jobsPerOp = 100

	// The per-job INFO logging in executeJob would dominate the measurement and
	// flood the output; silence it for the duration of the benchmark.
	prevLevel := log.GetLevel()
	prevOut := log.StandardLogger().Out
	log.SetLevel(log.PanicLevel)
	log.SetOutput(io.Discard)
	b.Cleanup(func() {
		log.SetLevel(prevLevel)
		log.SetOutput(prevOut)
	})

	for _, maxConcurrent := range []int{1, 5, 10, 25, 100} {
		b.Run(fmt.Sprintf("concurrency=%d", maxConcurrent), func(b *testing.B) {
			runJobThroughput(b, maxConcurrent, jobsPerOp)
		})
	}
}

// runJobThroughput submits `jobs` fast-failing jobs to a fresh TransferManager
// bounded to `maxConcurrent` in-flight jobs, waits for every job to reach a
// terminal state, and reports jobs/sec and microseconds/job.
func runJobThroughput(b *testing.B, maxConcurrent, jobs int) {
	b.Helper()

	// One transfer whose operation the executor doesn't recognize, so
	// executeTransfer returns immediately without touching the client stack.
	reqs := []TransferRequest{{
		Operation:   "benchmark-noop",
		Source:      "pelican://benchmark/none",
		Destination: "pelican://benchmark/none",
	}}

	b.ReportAllocs()
	b.ResetTimer()

	var total time.Duration
	for i := 0; i < b.N; i++ {
		tm := NewTransferManager(context.Background(), maxConcurrent, nil)

		submitted := make([]*TransferJob, 0, jobs)
		start := time.Now()
		for j := 0; j < jobs; j++ {
			job, err := tm.CreateJob(reqs, nil)
			if err != nil {
				b.Fatalf("CreateJob: %v", err)
			}
			submitted = append(submitted, job)
		}
		// Wait for every job to finish (executeJob signals wg.Done on exit).
		for _, job := range submitted {
			job.wg.Wait()
		}
		total += time.Since(start)

		_ = tm.Shutdown()
	}

	b.StopTimer()
	if total > 0 {
		completed := float64(b.N * jobs)
		b.ReportMetric(completed/total.Seconds(), "jobs/sec")
		b.ReportMetric(float64(total.Microseconds())/completed, "us/job")
	}
}
