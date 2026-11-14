//go:build client || server

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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/transfer"
)

// jobWaitDeadline bounds how long a test waits for a --wait call to return.
// It only matters when the property under test is broken, in which case the
// call would otherwise never return and hang the package.
const jobWaitDeadline = 30 * time.Second

// newTestJobClient points a transferJobClient at a test server, with its own
// output buffer so that nothing in the test touches process-wide state (in
// particular the `outputJSON` global the cobra commands read).
func newTestJobClient(t *testing.T, srv *httptest.Server, jsonOut bool) (*transferJobClient, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &transferJobClient{
		httpClient: srv.Client(),
		serverURL:  srv.URL,
		token:      "test-token",
		out:        out,
		jsonOut:    jsonOut,
	}, out
}

// runWithDeadline runs fn on its own goroutine and returns its error, failing
// the test rather than hanging if fn never returns.
func runWithDeadline(t *testing.T, fn func() error) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- fn() }()

	var result error
	var got bool
	require.Eventually(t, func() bool {
		select {
		case result = <-errCh:
			got = true
			return true
		default:
			return false
		}
	}, jobWaitDeadline, 10*time.Millisecond, "call did not return")
	require.True(t, got)
	return result
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	require.NoError(t, err)
	return parsed
}

// writeJSON is the happy-path reply helper for the stub transfer server.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}

// writeSSE streams a sequence of job events, flushing each one, the way the
// transfer server's /events endpoint does.
func writeSSE(t *testing.T, w http.ResponseWriter, events []map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	require.True(t, ok, "test server response must be flushable")
	for _, ev := range events {
		data, err := json.Marshal(ev)
		require.NoError(t, err)
		_, err = w.Write([]byte("event: status\ndata: " + string(data) + "\n\n"))
		require.NoError(t, err)
		flusher.Flush()
	}
}

func TestTransferJobList(t *testing.T) {
	completed := mustTime(t, "2026-01-02T03:04:05Z")
	listResp := transfer.TransferJobListResponse{
		Jobs: []transfer.TransferJobStatus{
			{
				JobID:       "job-running",
				Status:      "running",
				CreatedAt:   mustTime(t, "2026-01-02T03:00:00Z"),
				CompletedAt: nil,
			},
			{
				JobID:       "job-done",
				Status:      "completed",
				CreatedAt:   mustTime(t, "2026-01-01T00:00:00Z"),
				CompletedAt: &completed,
			},
		},
		Total:  5,
		Limit:  2,
		Offset: 0,
	}

	var gotQuery string
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1.0/transfer/jobs", r.URL.Path)
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		writeJSON(t, w, http.StatusOK, listResp)
	}))
	defer srv.Close()

	t.Run("human-readable", func(t *testing.T) {
		client, out := newTestJobClient(t, srv, false)
		require.NoError(t, client.runTransferJobList(context.Background(), "running", 2, 0))

		text := out.String()
		assert.Contains(t, text, "JOB ID")
		assert.Contains(t, text, "job-running")
		assert.Contains(t, text, "job-done")
		assert.Contains(t, text, "2026-01-02T03:04:05Z")
		// A running job has no completion time; the column must still be filled.
		assert.Contains(t, text, "-")
		// The server said there were more jobs than this page carried.
		assert.Contains(t, text, "Showing 1-2 of 5 jobs.")

		// The filter and paging options have to reach the server, since it is
		// the server that applies them.
		assert.Contains(t, gotQuery, "status=running")
		assert.Contains(t, gotQuery, "limit=2")
		assert.Contains(t, gotQuery, "offset=0")
		assert.Equal(t, "Bearer test-token", gotAuth)
	})

	t.Run("json", func(t *testing.T) {
		client, out := newTestJobClient(t, srv, true)
		require.NoError(t, client.runTransferJobList(context.Background(), "", 10, 0))

		var decoded transfer.TransferJobListResponse
		require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
		require.Len(t, decoded.Jobs, 2)
		assert.Equal(t, "job-running", decoded.Jobs[0].JobID)
		assert.Equal(t, 5, decoded.Total)
		// No human-readable decoration may leak into --json output.
		assert.NotContains(t, out.String(), "JOB ID")
	})
}

func TestTransferJobListEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, transfer.TransferJobListResponse{
			Jobs: []transfer.TransferJobStatus{}, Total: 0, Limit: 10, Offset: 0,
		})
	}))
	defer srv.Close()

	client, out := newTestJobClient(t, srv, false)
	require.NoError(t, client.runTransferJobList(context.Background(), "", 10, 0))
	assert.Contains(t, out.String(), "No transfer jobs found.")
}

func TestTransferJobStatus(t *testing.T) {
	completed := mustTime(t, "2026-03-04T05:06:07Z")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1.0/transfer/jobs/job-abc", r.URL.Path)
		writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{
			JobID:              "job-abc",
			Status:             "completed",
			CreatedAt:          mustTime(t, "2026-03-04T05:00:00Z"),
			CompletedAt:        &completed,
			SourceCredentialID: "cred-src",
			DestCredentialID:   "cred-dst",
		})
	}))
	defer srv.Close()

	client, out := newTestJobClient(t, srv, false)
	require.NoError(t, client.runTransferJobStatus(context.Background(), "job-abc", false))

	text := out.String()
	assert.Contains(t, text, "Job ID:    job-abc")
	assert.Contains(t, text, "Status:    completed")
	assert.Contains(t, text, "2026-03-04T05:06:07Z")
	assert.Contains(t, text, "cred-src")
	assert.Contains(t, text, "cred-dst")
}

// A job ID is user input: it must land in exactly one path segment rather than
// being able to steer the request at a different endpoint.
func TestTransferJobIDIsEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{JobID: "x", Status: "completed"})
	}))
	defer srv.Close()

	client, _ := newTestJobClient(t, srv, false)
	require.NoError(t, client.runTransferJobStatus(context.Background(), "../credentials", false))
	assert.Equal(t, "/api/v1.0/transfer/jobs/..%2Fcredentials", gotPath)
}

func TestTransferJobStatusNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusNotFound, transfer.ErrorResponse{
			Code: "NOT_FOUND", Error: "Transfer job not found",
		})
	}))
	defer srv.Close()

	client, _ := newTestJobClient(t, srv, false)
	err := client.runTransferJobStatus(context.Background(), "nope", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOT_FOUND")
	assert.Contains(t, err.Error(), "Transfer job not found")
}

// An unknown job must fail fast even under --wait: without the pre-flight GET
// the wait would fall through to polling an endpoint that never answers.
func TestTransferJobStatusWaitRejectsUnknownJob(t *testing.T) {
	var sawEvents bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events") {
			sawEvents = true
		}
		writeJSON(t, w, http.StatusNotFound, transfer.ErrorResponse{
			Code: "NOT_FOUND", Error: "Transfer job not found",
		})
	}))
	defer srv.Close()

	client, _ := newTestJobClient(t, srv, false)
	err := runWithDeadline(t, func() error {
		return client.runTransferJobStatus(context.Background(), "nope", true)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOT_FOUND")
	assert.False(t, sawEvents, "should not have opened an event stream for an unknown job")
}

// A job that is already finished must be reported straight away rather than
// waited on.
func TestTransferJobStatusWaitOnTerminalJob(t *testing.T) {
	cases := []struct {
		name      string
		status    string
		jobErr    string
		expectErr string
	}{
		{name: "completed", status: "completed"},
		{name: "failed", status: "failed", jobErr: "origin refused", expectErr: "origin refused"},
		{name: "error", status: "error", jobErr: "boom", expectErr: "boom"},
		{name: "cancelled", status: "cancelled", expectErr: "was cancelled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sawEvents bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/events") {
					sawEvents = true
				}
				writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{
					JobID: "job-1", Status: tc.status, Error: tc.jobErr,
				})
			}))
			defer srv.Close()

			client, out := newTestJobClient(t, srv, false)
			err := runWithDeadline(t, func() error {
				return client.runTransferJobStatus(context.Background(), "job-1", true)
			})
			if tc.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErr)
			}
			assert.Contains(t, out.String(), "Status:    "+tc.status)
			assert.False(t, sawEvents, "a terminal job should not be waited on")
		})
	}
}

// --wait on a job still in flight follows the server's event stream through to
// the terminal event.
func TestTransferJobStatusWaitFollowsEventStream(t *testing.T) {
	cases := []struct {
		name      string
		terminal  map[string]any
		expectErr string
	}{
		{
			name:     "completed",
			terminal: map[string]any{"status": "completed", "job_id": "job-1"},
		},
		{
			name:      "failed",
			terminal:  map[string]any{"status": "failed", "job_id": "job-1", "error": "disk full"},
			expectErr: "disk full",
		},
		{
			name:      "cancelled",
			terminal:  map[string]any{"status": "cancelled", "job_id": "job-1"},
			expectErr: "was cancelled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sawEvents bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/events") {
					mu.Lock()
					sawEvents = true
					mu.Unlock()
					writeSSE(t, w, []map[string]any{
						{"status": "running", "job_id": "job-1"},
						tc.terminal,
					})
					return
				}
				writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{
					JobID: "job-1", Status: "running",
				})
			}))
			defer srv.Close()

			client, out := newTestJobClient(t, srv, false)
			err := runWithDeadline(t, func() error {
				return client.runTransferJobStatus(context.Background(), "job-1", true)
			})
			if tc.expectErr == "" {
				require.NoError(t, err)
				assert.Contains(t, out.String(), "completed successfully")
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErr)
			}
			mu.Lock()
			defer mu.Unlock()
			assert.True(t, sawEvents, "should have consumed the event stream")
		})
	}
}

// A server that cannot serve the event stream must be detected as such, so the
// caller falls back to polling instead of treating it as a terminal answer.
func TestTransferJobWatchSSEUnavailable(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "not found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "wrong content type",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, http.StatusOK, map[string]string{"status": "running"})
			},
		},
		{
			name: "stream ends without a terminal event",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeSSE(t, w, []map[string]any{{"status": "running", "job_id": "job-1"}})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			client, _ := newTestJobClient(t, srv, false)
			err := runWithDeadline(t, func() error {
				return client.watchJobSSE(context.Background(), "job-1")
			})
			assert.ErrorIs(t, err, errSSEUnavailable)
		})
	}
}

// A cancelled context ends a wait promptly, through whichever path the wait
// took, rather than leaving the command hanging on the server.
func TestTransferJobWaitHonorsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never answers: only the context can end this wait.
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, _ := newTestJobClient(t, srv, false)
	err := runWithDeadline(t, func() error {
		return client.waitForJob(ctx, "job-1")
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, errSSEUnavailable)
}

func TestTransferJobCancel(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		writeJSON(t, w, http.StatusOK, map[string]string{
			"job_id": "job-abc", "message": "Job cancelled",
		})
	}))
	defer srv.Close()

	t.Run("human-readable", func(t *testing.T) {
		client, out := newTestJobClient(t, srv, false)
		require.NoError(t, client.runTransferJobCancel(context.Background(), "job-abc"))
		assert.Equal(t, http.MethodDelete, gotMethod)
		assert.Equal(t, "/api/v1.0/transfer/jobs/job-abc", gotPath)
		assert.Contains(t, out.String(), "Transfer job job-abc cancelled.")
	})

	t.Run("json", func(t *testing.T) {
		client, out := newTestJobClient(t, srv, true)
		require.NoError(t, client.runTransferJobCancel(context.Background(), "job-abc"))
		var decoded map[string]string
		require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
		assert.Equal(t, "job-abc", decoded["job_id"])
	})
}

func TestTransferJobCancelError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusNotFound, transfer.ErrorResponse{
			Code: "NOT_FOUND", Error: "Transfer job not found",
		})
	}))
	defer srv.Close()

	client, _ := newTestJobClient(t, srv, false)
	err := client.runTransferJobCancel(context.Background(), "job-abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOT_FOUND")
}

// The new commands have to hang off `pelican transfer`, where they inherit the
// server and token flags -- and must not have been grafted onto the unrelated
// local-job tree.
func TestTransferJobCommandWiring(t *testing.T) {
	var jobCommand *cobra.Command
	for _, sub := range transferCmd.Commands() {
		if sub.Name() == "job" {
			jobCommand = sub
		}
	}
	require.NotNil(t, jobCommand, "`transfer job` should be registered under `transfer`")

	names := make([]string, 0, len(jobCommand.Commands()))
	for _, sub := range jobCommand.Commands() {
		names = append(names, sub.Name())
	}
	assert.ElementsMatch(t, []string{"list", "status", "cancel"}, names)

	// --server/-s and --token/-t come from the parent; a subcommand must not
	// redefine either, or it would shadow the inherited flag.
	for _, sub := range jobCommand.Commands() {
		assert.Nil(t, sub.Flags().ShorthandLookup("s"), sub.Name()+" must not shadow -s/--server")
		assert.Nil(t, sub.Flags().ShorthandLookup("t"), sub.Name()+" must not shadow -t/--token")
	}
	require.NotNil(t, transferCmd.PersistentFlags().Lookup("server"))
	require.NotNil(t, transferCmd.PersistentFlags().Lookup("token"))

	// The help has to tell the two job trees apart, since `pelican job` means
	// something else entirely.
	assert.Contains(t, jobCommand.Long, "pelican job")
}

// progressOf builds a JobProgress the way the server's GetJobProgress would.
func progressOf(bytesTransferred, totalBytes int64, percentage float64) *client_agent.JobProgress {
	return &client_agent.JobProgress{
		BytesTransferred:   bytesTransferred,
		TotalBytes:         totalBytes,
		Percentage:         percentage,
		TransfersCompleted: 1,
		TransfersTotal:     2,
	}
}

func TestFormatTransferProgress(t *testing.T) {
	// A total of zero is the server saying it does not know how big the job
	// is; a percentage against it would be invented.
	assert.Equal(t, "1.0 KiB (total size unknown)", formatTransferProgress(1024, 0))
	assert.Equal(t, "0 B (total size unknown)", formatTransferProgress(0, 0))

	assert.Contains(t, formatTransferProgress(512, 1024), "50.0%")
	assert.NotContains(t, formatTransferProgress(1024, 0), "%")
}

func TestProgressCell(t *testing.T) {
	// Nil is "the server cannot know", which must not read as zero bytes.
	assert.Equal(t, "unknown", progressCell(nil))
	assert.NotContains(t, progressCell(nil), "0")

	assert.Contains(t, progressCell(progressOf(512, 1024, 50)), "50%")
	// No total: report what moved, invent no percentage.
	noTotal := progressCell(progressOf(2048, 0, 0))
	assert.Contains(t, noTotal, "2.0 KiB")
	assert.NotContains(t, noTotal, "%")
}

func TestTransferJobListShowsProgress(t *testing.T) {
	completed := mustTime(t, "2026-01-02T03:04:05Z")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, transfer.TransferJobListResponse{
			Jobs: []transfer.TransferJobStatus{
				{
					JobID:     "job-live",
					Status:    "running",
					CreatedAt: mustTime(t, "2026-01-02T03:00:00Z"),
					Progress:  progressOf(512, 1024, 50),
				},
				{
					JobID:       "job-evicted",
					Status:      "completed",
					CreatedAt:   mustTime(t, "2026-01-01T00:00:00Z"),
					CompletedAt: &completed,
					// No Progress: the server no longer holds the counters.
				},
			},
			Total: 2, Limit: 10, Offset: 0,
		})
	}))
	defer srv.Close()

	client, out := newTestJobClient(t, srv, false)
	require.NoError(t, client.runTransferJobList(context.Background(), "", 10, 0))

	text := out.String()
	assert.Contains(t, text, "PROGRESS")
	assert.Contains(t, text, "50%")
	assert.Contains(t, text, "unknown")
}

func TestTransferJobStatusShowsProgress(t *testing.T) {
	cases := []struct {
		name     string
		progress *client_agent.JobProgress
		contains []string
		absent   []string
	}{
		{
			name:     "known total",
			progress: progressOf(512, 1024, 50),
			contains: []string{"Progress:", "50.0%", "Transfers: 1/2 completed"},
		},
		{
			name:     "unknown total",
			progress: progressOf(2048, 0, 0),
			contains: []string{"2.0 KiB", "total size unknown"},
			absent:   []string{"%"},
		},
		{
			name:     "no bytes yet",
			progress: progressOf(0, 4096, 0),
			contains: []string{"0 B", "0.0%"},
			// A real zero must not be reported as unknowable.
			absent: []string{"unknown"},
		},
		{
			name:     "evicted job",
			progress: nil,
			contains: []string{"Progress:  unknown"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{
					JobID: "job-1", Status: "running", Progress: tc.progress,
				})
			}))
			defer srv.Close()

			client, out := newTestJobClient(t, srv, false)
			require.NoError(t, client.runTransferJobStatus(context.Background(), "job-1", false))
			for _, want := range tc.contains {
				assert.Contains(t, out.String(), want)
			}
			for _, unwanted := range tc.absent {
				assert.NotContains(t, out.String(), unwanted)
			}
		})
	}
}

// progressStreamServer serves a job that is running, then streams several
// progress frames before the terminal one.
func progressStreamServer(t *testing.T, frames int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/events") {
			writeJSON(t, w, http.StatusOK, transfer.TransferJobStatus{
				JobID: "job-1", Status: "running", Progress: progressOf(0, 1024, 0),
			})
			return
		}
		events := make([]map[string]any, 0, frames+1)
		for i := 1; i <= frames; i++ {
			events = append(events, map[string]any{
				"job_id":            "job-1",
				"bytes_transferred": int64(i) * 256,
				"total_bytes":       int64(1024),
			})
		}
		events = append(events, map[string]any{"job_id": "job-1", "status": "completed"})
		writeSSE(t, w, events)
	}))
}

// --wait feeds the job's progress to the same progress bars the rest of the
// client draws, rather than printing lines of its own.
func TestTransferJobWaitDrivesProgressBars(t *testing.T) {
	srv := progressStreamServer(t, 3)
	defer srv.Close()

	client, out := newTestJobClient(t, srv, false)
	// Attach a bar display's bookkeeping without launching its renderer: the
	// frames-to-callback wiring is what matters here, not what mpb paints.
	bars := newProgressBar()
	client.progress = bars

	require.NoError(t, runWithDeadline(t, func() error {
		return client.runTransferJobStatus(context.Background(), "job-1", true)
	}))

	bars.lock.RLock()
	defer bars.lock.RUnlock()
	// One job, one aggregate count, so one bar keyed by the job ID.
	require.Len(t, bars.status, 1)
	status, ok := bars.status["job-1"]
	require.True(t, ok, "the bar must be keyed by job ID")
	assert.Equal(t, int64(768), status.xfer, "the last frame's byte count must reach the bar")
	assert.Equal(t, int64(1024), status.size)
	assert.True(t, status.completed, "the bar must be retired when the job ends")

	// Nothing is hand-printed around the bar; only the command's own messages.
	assert.NotContains(t, out.String(), "Transferred ")
	assert.Contains(t, out.String(), "completed successfully")
}

// Whether a wait draws bars at all is the configuration's decision plus
// --json, never the wait's own idea of what a terminal is.
func TestTransferJobWantsProgressBars(t *testing.T) {
	cases := []struct {
		name         string
		showProgress bool
		jsonOut      bool
		want         bool
	}{
		{name: "enabled", showProgress: true, want: true},
		{name: "config says no", showProgress: false, want: false},
		// The object commands have no --json, so the shared gate cannot know
		// about it; a wait that honors it keeps --json output parseable.
		{name: "json suppresses", showProgress: true, jsonOut: true, want: false},
		{name: "json and config", showProgress: false, jsonOut: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &transferJobClient{showProgress: tc.showProgress, jsonOut: tc.jsonOut}
			assert.Equal(t, tc.want, client.wantsProgressBars())
		})
	}
}

// A wait that may not draw bars must not create a display at all, and must
// leave --json output as nothing but the server's body.
func TestTransferJobWaitSuppressesProgressBars(t *testing.T) {
	t.Run("config disabled", func(t *testing.T) {
		srv := progressStreamServer(t, 3)
		defer srv.Close()

		client, _ := newTestJobClient(t, srv, false)
		client.showProgress = false
		require.NoError(t, runWithDeadline(t, func() error {
			return client.waitForJob(context.Background(), "job-1")
		}))
		assert.Nil(t, client.progress, "no bar display may be created when bars are off")
	})

	t.Run("json", func(t *testing.T) {
		srv := progressStreamServer(t, 3)
		defer srv.Close()

		client, out := newTestJobClient(t, srv, true)
		client.showProgress = true
		require.NoError(t, runWithDeadline(t, func() error {
			return client.runTransferJobStatus(context.Background(), "job-1", true)
		}))
		assert.Nil(t, client.progress, "--json must not start a bar display")

		// --json promises the server's own body and nothing else.
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
		assert.Equal(t, "completed", decoded["status"])
	})
}

// `object copy --transfer-server --wait` waits through this very constructor,
// so whatever it decides is what both paths do.
func TestNewTransferJobClientForSharesWaitRendering(t *testing.T) {
	srv := progressStreamServer(t, 2)
	defer srv.Close()

	client := newTransferJobClientFor(srv.Client(), srv.URL, "tok")
	require.NotNil(t, client)
	assert.Equal(t, srv.URL, client.serverURL)
	assert.Equal(t, "tok", client.token)
	assert.Equal(t, outputJSON, client.jsonOut)
	// The same gate every object command uses, not a private notion of one.
	assert.Equal(t, shouldDisplayProgressBars(), client.showProgress)

	// Redirect its output and confirm the shared wait path is the one that
	// feeds the bars, so object copy's --wait gets them for free.
	out := &bytes.Buffer{}
	client.out = out
	bars := newProgressBar()
	client.progress = bars
	require.NoError(t, runWithDeadline(t, func() error {
		return client.waitForJob(context.Background(), "job-1")
	}))

	bars.lock.RLock()
	defer bars.lock.RUnlock()
	require.Contains(t, bars.status, "job-1")
	assert.Equal(t, int64(512), bars.status["job-1"].xfer)
	assert.Contains(t, out.String(), "completed successfully")
}
