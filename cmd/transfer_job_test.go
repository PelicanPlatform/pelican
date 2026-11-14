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
