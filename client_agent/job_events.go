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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// wantsEventStream reports whether the client asked for a Server-Sent Events
// response (Accept: text/event-stream).
func wantsEventStream(c *gin.Context) bool {
	return strings.Contains(c.GetHeader("Accept"), "text/event-stream")
}

// sseKeepAliveInterval bounds how long an SSE stream stays silent; a comment
// ping keeps the connection alive through idle proxies during a long transfer.
const sseKeepAliveInterval = 15 * time.Second

// progressEmitInterval throttles per-job progress broadcasts: transfer progress
// callbacks fire per chunk, but subscribers only need a periodic update.
const progressEmitInterval = 250 * time.Millisecond

// Event kinds, delivered as the SSE `event:` field so clients can dispatch.
const (
	jobEventStatus   = "status"
	jobEventProgress = "progress"
)

// JobEvent is a single notification delivered to subscribers of a job. Kind
// selects the SSE event name: a "status" event carries Status (and Error on
// failure); a "progress" event carries the job's aggregate bytes transferred.
type JobEvent struct {
	Kind             string `json:"-"`
	JobID            string `json:"job_id"`
	Status           string `json:"status,omitempty"`
	Error            string `json:"error,omitempty"`
	BytesTransferred int64  `json:"bytes_transferred,omitempty"`
	TotalBytes       int64  `json:"total_bytes,omitempty"`
}

// IsTerminalStatus reports whether a status is a final state (the job will emit
// no further events).
func IsTerminalStatus(status string) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// SubscribeJob registers a subscriber for a job's status changes and returns a
// receive-only channel plus an unsubscribe function the caller MUST invoke when
// done (typically via defer).
//
// Ordering contract for race-free waiting: subscribe FIRST, then read the job's
// current status (GetJob / the durable record). A transition that happens after
// SubscribeJob returns is delivered on the channel; one that already happened is
// visible in the current status. So a caller that emits the current status and
// then streams the channel never misses the terminal event.
//
// The channel is buffered and delivery is best-effort: if a slow subscriber's
// buffer is full, the event is dropped rather than blocking job execution. A
// subscriber therefore should not rely on receiving every intermediate state —
// it must treat the current status (read after subscribing) and any terminal
// event as authoritative. (For a fast reader the buffer never fills.)
func (tm *TransferManager) SubscribeJob(jobID string) (<-chan JobEvent, func()) {
	// Look up the job once (if it is in memory) so we can maintain its
	// lock-free subscriber count, which gates the progress hot path. Done
	// outside subMu to avoid nesting the two locks.
	tm.mu.RLock()
	job := tm.jobs[jobID]
	tm.mu.RUnlock()

	tm.subMu.Lock()
	if tm.subscribers == nil {
		tm.subscribers = make(map[string]map[int]chan JobEvent)
	}
	if tm.subscribers[jobID] == nil {
		tm.subscribers[jobID] = make(map[int]chan JobEvent)
	}
	id := tm.nextSubID
	tm.nextSubID++
	ch := make(chan JobEvent, 8)
	tm.subscribers[jobID][id] = ch
	tm.subMu.Unlock()

	if job != nil {
		job.subscriberCount.Add(1)
	}

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			tm.subMu.Lock()
			if subs := tm.subscribers[jobID]; subs != nil {
				if _, ok := subs[id]; ok {
					delete(subs, id)
					close(ch)
				}
				if len(subs) == 0 {
					delete(tm.subscribers, jobID)
				}
			}
			tm.subMu.Unlock()
			if job != nil {
				job.subscriberCount.Add(-1)
			}
		})
	}
	return ch, unsub
}

// publishJobEvent delivers an event to every current subscriber of the job. It
// holds subMu (serializing with subscribe/unsubscribe, so it never sends on a
// closed channel), and the per-subscriber send is non-blocking.
func (tm *TransferManager) publishJobEvent(ev JobEvent) {
	tm.subMu.Lock()
	defer tm.subMu.Unlock()
	for _, ch := range tm.subscribers[ev.JobID] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// jobEvent builds a status JobEvent snapshot from a job. Caller must hold the
// read lock, since the execution goroutine concurrently mutates Status/Error.
func jobEvent(job *TransferJob) JobEvent {
	ev := JobEvent{Kind: jobEventStatus, JobID: job.ID, Status: job.Status}
	if job.Error != nil {
		ev.Error = job.Error.Error()
	}
	return ev
}

// publishJobProgress broadcasts a job's aggregate transfer progress (summed
// across its transfers) to subscribers. It is called from the per-chunk transfer
// progress callback, so the hot path is deliberately lock-free:
//
//   - if the job has no event-stream watchers it returns after a single atomic
//     load — no shared lock, no aggregation, no publish. A server managing
//     thousands of transfers nobody is watching pays essentially nothing.
//   - otherwise it throttles to one broadcast per progressEmitInterval per job
//     (also lock-free, via CAS), and only then aggregates and publishes.
//
// It takes the job directly (no map lookup) and never touches tm.mu; the only
// lock involved is the events-hub subMu, taken briefly inside publishJobEvent
// and independent of job execution.
func (tm *TransferManager) publishJobProgress(job *TransferJob) {
	if job.subscriberCount.Load() == 0 {
		return
	}

	now := time.Now().UnixNano()
	last := job.lastProgressEmit.Load()
	if now-last < int64(progressEmitInterval) || !job.lastProgressEmit.CompareAndSwap(last, now) {
		return
	}

	// job.Transfers is fixed at creation; the atomics are safe to read here.
	var bytes, total int64
	for _, tr := range job.Transfers {
		bytes += tr.BytesTransferred.Load()
		total += tr.TotalBytes.Load()
	}
	tm.publishJobEvent(JobEvent{Kind: jobEventProgress, JobID: job.ID, BytesTransferred: bytes, TotalBytes: total})
}

// jobEventSnapshot returns the job's current status as a JobEvent, read under
// the manager lock. ok is false if the job is not in the manager's memory.
func (tm *TransferManager) jobEventSnapshot(jobID string) (JobEvent, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	job, ok := tm.jobs[jobID]
	if !ok {
		return JobEvent{}, false
	}
	return jobEvent(job), true
}

// StreamJobEvents streams a job's status to the client as Server-Sent Events
// until the job reaches a terminal state or the request is cancelled. It is the
// push-based, poll-free counterpart to GET /jobs/:id, shared by the transfer
// server and the local client agent.
//
// Each message is `event: status` with a JSON JobEvent payload. The first
// message is always the job's current status (so a caller can persist the job
// ID and, if the stream drops, reconnect to the same endpoint); subsequent
// messages are transitions, ending with the terminal one.
//
// The caller must have already verified the job exists (and, for a multi-user
// server, that it belongs to the requester). fallbackStatus is used only when
// the job is no longer in the manager's memory (e.g. after a restart, when its
// terminal state lives only in a durable record) — pass "" if not applicable.
//
// It follows the SubscribeJob ordering contract: subscribe, THEN read the
// current status, so the terminal transition is never missed.
func (tm *TransferManager) StreamJobEvents(c *gin.Context, jobID, fallbackStatus string) {
	events, unsub := tm.SubscribeJob(jobID)
	defer unsub()

	current := JobEvent{Kind: jobEventStatus, JobID: jobID, Status: fallbackStatus}
	if ev, ok := tm.jobEventSnapshot(jobID); ok {
		current = ev
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	c.Writer.WriteHeader(http.StatusOK)
	flusher, _ := c.Writer.(http.Flusher)

	writeEvent := func(ev JobEvent) {
		kind := ev.Kind
		if kind == "" {
			kind = jobEventStatus
		}
		data, _ := json.Marshal(ev)
		_, _ = fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", kind, data)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// Emit the current status first. If it is already terminal, we are done —
	// this covers a job that finished before (or during) subscription.
	writeEvent(current)
	if IsTerminalStatus(current.Status) {
		return
	}

	keepAlive := time.NewTicker(sseKeepAliveInterval)
	defer keepAlive.Stop()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			writeEvent(ev)
			if IsTerminalStatus(ev.Status) {
				return
			}
		case <-keepAlive.C:
			_, _ = fmt.Fprint(c.Writer, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		case <-c.Request.Context().Done():
			return
		}
	}
}
