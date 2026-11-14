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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/transfer"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	transferJobCmd = &cobra.Command{
		Use:   "job",
		Short: "Manage transfer jobs running on a remote transfer server",
		Long: `Manage the transfer jobs that run on a remote Pelican transfer server.

These are the jobs created by "pelican object copy --transfer-server URL ..."
(or "--dest-origin URL"): the transfer server moves the data on the user's
behalf, so a job outlives the client that submitted it.  Without "--wait" that
copy prints a job ID and returns, and these commands are how that ID is
followed up afterwards.

This is NOT the same thing as "pelican job", which manages the local
client-agent jobs created by "pelican object copy --async".  Those run on this
machine; these run on the transfer server named by "--server".

The transfer server and the bearer token used to authenticate with it come
from the "--server" and "--token" flags of the parent "pelican transfer"
command.`,
		SilenceUsage: true,
	}

	transferJobListCmd = &cobra.Command{
		Use:   "list",
		Short: "List the transfer jobs owned by the caller",
		Long: `List the transfer jobs on the transfer server that belong to the
authenticated caller, most recently created first.  The server never returns
another user's jobs.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         transferJobListMain,
	}

	transferJobStatusCmd = &cobra.Command{
		Use:   "status {job_id}",
		Short: "Show the status of one transfer job",
		Long: `Show the status of a single transfer job on the transfer server.

With "--wait" the command does not return until the job reaches a terminal
state (completed, failed, or cancelled), following the server's event stream
and falling back to polling where that stream is unavailable.  A job that has
already finished is reported immediately.  The exit status is non-zero if the
job failed or was cancelled.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE:         transferJobStatusMain,
	}

	transferJobCancelCmd = &cobra.Command{
		Use:   "cancel {job_id}",
		Short: "Cancel a transfer job",
		Long: `Cancel a transfer job on the transfer server.  Transfers that have
already completed are unaffected; those still in flight are stopped.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE:         transferJobCancelMain,
	}

	transferJobListStatus string
	transferJobListLimit  int
	transferJobListOffset int
	transferJobStatusWait bool
)

func init() {
	transferCmd.AddCommand(transferJobCmd)
	transferJobCmd.AddCommand(transferJobListCmd)
	transferJobCmd.AddCommand(transferJobStatusCmd)
	transferJobCmd.AddCommand(transferJobCancelCmd)

	// No shorthands here: the parent command has already claimed -s for
	// --server and -t for --token, and a subcommand that redefined either
	// would shadow it for its own invocations only.
	transferJobListCmd.Flags().StringVar(&transferJobListStatus, "status", "", "Only show jobs in this state (pending, running, completed, failed, cancelled)")
	transferJobListCmd.Flags().IntVar(&transferJobListLimit, "limit", 10, "Maximum number of jobs to return (the server caps this at 100)")
	transferJobListCmd.Flags().IntVar(&transferJobListOffset, "offset", 0, "Number of jobs to skip, for paging through a long list")

	transferJobStatusCmd.Flags().BoolVar(&transferJobStatusWait, "wait", false, "Wait for the job to reach a terminal state before returning")
}

// transferJobClient issues job-management calls against one transfer server.
//
// Collecting the server URL, bearer token, and output settings in one place is
// what keeps every job endpoint reachable from a single spelling: callers name
// a job by its ID and never build a URL or set an Authorization header of their
// own, so a path or header can't be got wrong in one caller and right in
// another.
type transferJobClient struct {
	httpClient *http.Client
	serverURL  string
	token      string
	out        io.Writer
	jsonOut    bool
	// showProgress is the configuration's answer to whether progress bars may
	// be drawn on this run (see shouldDisplayProgressBars).
	showProgress bool
	// progress is the bar display for the duration of a wait, created by
	// waitForJob and nil at every other time.
	progress *progressBars
}

// newTransferJobClientFor builds a job client that writes to this process's
// standard output. Both the `transfer job` commands and `object copy
// --transfer-server` go through here, so the two render a job's progress the
// same way and neither has to work out for itself whether --json is set or
// whether stdout is a terminal.
func newTransferJobClientFor(httpClient *http.Client, serverURL, token string) *transferJobClient {
	return &transferJobClient{
		httpClient:   httpClient,
		serverURL:    serverURL,
		token:        token,
		out:          os.Stdout,
		jsonOut:      outputJSON,
		showProgress: shouldDisplayProgressBars(),
	}
}

// newTransferJobClient resolves the transfer server and token from the flags
// inherited from the parent `transfer` command.
func newTransferJobClient() (*transferJobClient, error) {
	httpClient, serverURL, tokenValue, err := newTransferHTTPClient()
	if err != nil {
		return nil, err
	}
	return newTransferJobClientFor(httpClient, serverURL, tokenValue), nil
}

// jobsURL builds the URL of the jobs collection, or of one job when a job ID
// is given.  The ID is escaped: it reaches us from a user and has no business
// introducing path segments or a query string.
func (c *transferJobClient) jobsURL(jobID string, suffix ...string) string {
	u := c.serverURL + "/api/v1.0/transfer/jobs"
	if jobID != "" {
		u += "/" + url.PathEscape(jobID)
		for _, s := range suffix {
			u += "/" + s
		}
	}
	return u
}

// getJob fetches one job's status, returning both the decoded status and the
// raw body so that --json can echo exactly what the server said.
func (c *transferJobClient) getJob(ctx context.Context, jobID string) (*transfer.TransferJobStatus, []byte, error) {
	body, _, err := doTransferRequest(ctx, c.httpClient, http.MethodGet, c.jobsURL(jobID), c.token, nil)
	if err != nil {
		return nil, nil, err
	}
	var status transfer.TransferJobStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, body, errors.Wrap(err, "failed to parse transfer server response")
	}
	return &status, body, nil
}

// listJobs fetches a page of the caller's jobs.
func (c *transferJobClient) listJobs(ctx context.Context, status string, limit, offset int) (*transfer.TransferJobListResponse, []byte, error) {
	query := url.Values{}
	if status != "" {
		query.Set("status", status)
	}
	query.Set("limit", fmt.Sprint(limit))
	query.Set("offset", fmt.Sprint(offset))

	body, _, err := doTransferRequest(ctx, c.httpClient, http.MethodGet,
		c.jobsURL("")+"?"+query.Encode(), c.token, nil)
	if err != nil {
		return nil, nil, err
	}
	var resp transfer.TransferJobListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, body, errors.Wrap(err, "failed to parse transfer server response")
	}
	return &resp, body, nil
}

// cancelJob asks the server to cancel a job.
func (c *transferJobClient) cancelJob(ctx context.Context, jobID string) ([]byte, error) {
	body, _, err := doTransferRequest(ctx, c.httpClient, http.MethodDelete, c.jobsURL(jobID), c.token, nil)
	return body, err
}

// formatTransferProgress renders a job's byte counts for a human.
//
// The server reports a total of zero when it does not yet know how big the job
// is (nothing has been stat'ed, or the sources do not advertise a size). A
// percentage computed against that would be invented, so it is left out rather
// than shown as 0% or 100%.
func formatTransferProgress(bytesTransferred, totalBytes int64) string {
	if totalBytes > 0 {
		return fmt.Sprintf("%s / %s (%.1f%%)",
			utils.HumanBytes(bytesTransferred), utils.HumanBytes(totalBytes),
			float64(bytesTransferred)/float64(totalBytes)*100)
	}
	return fmt.Sprintf("%s (total size unknown)", utils.HumanBytes(bytesTransferred))
}

// progressCell renders a job's progress for one cell of the list table. A nil
// progress is the server saying it cannot know (see
// transfer.TransferJobStatus), which is not the same as nothing having moved.
func progressCell(progress *client_agent.JobProgress) string {
	if progress == nil {
		return "unknown"
	}
	if progress.TotalBytes > 0 {
		return fmt.Sprintf("%s / %s (%.0f%%)",
			utils.HumanBytes(progress.BytesTransferred),
			utils.HumanBytes(progress.TotalBytes), progress.Percentage)
	}
	return utils.HumanBytes(progress.BytesTransferred)
}

// wantsProgressBars reports whether a wait should draw progress bars. The
// configuration decides (shouldDisplayProgressBars); --json additionally
// forbids them, since its contract is the server's own body on stdout and
// nothing else, and the object commands have no --json for that gate to know
// about.
func (c *transferJobClient) wantsProgressBars() bool {
	return c.showProgress && !c.jsonOut
}

// recordProgress feeds one `event: progress` frame to the progress bar
// display. A job's progress is a single aggregate count, so it drives a single
// bar keyed -- and labelled -- by the job ID.
//
// A totalBytes of zero is the server saying it does not know the size yet. The
// bar is created with no total and only takes one once a real size arrives, so
// until then it shows its byte counter climbing rather than a bar stuck at 0%.
func (c *transferJobClient) recordProgress(jobID string, bytesTransferred, totalBytes int64, completed bool) {
	if c.progress == nil {
		return
	}
	c.progress.callback(jobID, bytesTransferred, totalBytes, completed)
}

// errSSEUnavailable signals that the server-sent-events stream could not be used
// (server too old, a buffering proxy, or a mid-stream drop) and the caller
// should fall back to polling.
var errSSEUnavailable = errors.New("transfer event stream unavailable")

// waitForJob waits for a job to reach a terminal state, preferring the
// server's push-based event stream (no polling) and falling back to polling when
// the stream is unavailable.
func (c *transferJobClient) waitForJob(ctx context.Context, jobID string) error {
	// The job's progress is drawn with the same bars the rest of the client
	// uses, so a wait here looks like any other transfer in progress.
	if c.progress == nil && c.wantsProgressBars() {
		progress := newProgressBar()
		progress.launchDisplay(ctx)
		defer progress.shutdown()
		c.progress = progress
		defer func() { c.progress = nil }()
	}

	if err := c.watchJobSSE(ctx, jobID); err != errSSEUnavailable {
		return err // terminal result (nil / failed / cancelled) or ctx error
	}
	log.Debug("Transfer event stream unavailable; falling back to polling")
	return c.pollJob(ctx, jobID)
}

// watchJobSSE waits for a job by consuming the server's SSE status
// stream. It returns nil on success, a descriptive error on failure/cancel, or
// errSSEUnavailable if the stream can't be established or drops before a
// terminal event (so the caller can fall back to polling).
func (c *transferJobClient) watchJobSSE(ctx context.Context, jobID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jobsURL(jobID, "events"), nil)
	if err != nil {
		return errSSEUnavailable
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errSSEUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return errSSEUnavailable
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Last counts seen, so the bar can be retired as complete rather than
	// simply vanishing when the job ends.
	var lastBytes, lastTotal int64
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue // event:/comment/blank lines
		}
		var ev struct {
			Status           string `json:"status"`
			Error            string `json:"error"`
			BytesTransferred int64  `json:"bytes_transferred"`
			TotalBytes       int64  `json:"total_bytes"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		// A frame carrying no status is a progress update: the server
		// publishes those as `event: progress` between status transitions
		// while the job runs. Feeding them to the bar is the difference
		// between a wait that looks hung and one that is visibly moving.
		if ev.Status == "" {
			lastBytes, lastTotal = ev.BytesTransferred, ev.TotalBytes
			c.recordProgress(jobID, ev.BytesTransferred, ev.TotalBytes, false)
			continue
		}
		switch ev.Status {
		case "completed":
			c.recordProgress(jobID, lastBytes, lastTotal, true)
			if c.jsonOut {
				fmt.Fprintln(c.out, data)
			} else {
				fmt.Fprintf(c.out, "Transfer job %s completed successfully.\n", jobID)
			}
			return nil
		case "failed", "error":
			c.recordProgress(jobID, lastBytes, lastTotal, true)
			return fmt.Errorf("transfer job %s failed: %s", jobID, ev.Error)
		case "cancelled":
			c.recordProgress(jobID, lastBytes, lastTotal, true)
			return fmt.Errorf("transfer job %s was cancelled", jobID)
		}
	}
	// However this stream ended, the bar must stop tracking a job nothing is
	// watching any more.
	c.recordProgress(jobID, lastBytes, lastTotal, true)
	// Stream ended without a terminal event (dropped, or ctx cancelled). If the
	// context is done, surface that; otherwise fall back to polling.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errSSEUnavailable
}

// pollJob polls the transfer server for the status of a job until
// it reaches a terminal state (completed, error, or cancelled).
func (c *transferJobClient) pollJob(ctx context.Context, jobID string) error {
	pollURL := c.jobsURL(jobID)
	pollInterval := 2 * time.Second
	maxInterval := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return errors.Wrap(err, "failed to create poll request")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			log.Warnf("Poll request failed: %v; retrying...", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Warnf("Poll returned %d: %s; retrying...", resp.StatusCode, string(body))
			continue
		}

		var status map[string]any
		if err := json.Unmarshal(body, &status); err != nil {
			log.Warnf("Failed to parse poll response: %v; retrying...", err)
			continue
		}

		jobStatus, _ := status["status"].(string)
		switch jobStatus {
		case "completed":
			if c.jsonOut {
				fmt.Fprintln(c.out, string(body))
			} else {
				fmt.Fprintf(c.out, "Transfer job %s completed successfully.\n", jobID)
			}
			return nil
		case "error", "failed":
			if c.jsonOut {
				fmt.Fprintln(c.out, string(body))
			}
			errMsg, _ := status["error"].(string)
			return fmt.Errorf("transfer job %s failed: %s", jobID, errMsg)
		case "cancelled":
			if c.jsonOut {
				fmt.Fprintln(c.out, string(body))
			}
			return fmt.Errorf("transfer job %s was cancelled", jobID)
		default:
			// Still in progress — increase interval with backoff
			if pollInterval < maxInterval {
				pollInterval = pollInterval * 3 / 2
				if pollInterval > maxInterval {
					pollInterval = maxInterval
				}
			}
		}
	}
}

// isTerminalTransferJobStatus reports whether a job status means the server is
// done with the job.  The server spells a failure both ways ("failed" from the
// transfer manager, "error" from a derived status), so both appear here.
func isTerminalTransferJobStatus(status string) bool {
	switch status {
	case "completed", "failed", "error", "cancelled":
		return true
	}
	return false
}

// runTransferJobList prints a page of the caller's jobs.
func (c *transferJobClient) runTransferJobList(ctx context.Context, status string, limit, offset int) error {
	resp, body, err := c.listJobs(ctx, status, limit, offset)
	if err != nil {
		return err
	}

	if c.jsonOut {
		fmt.Fprintln(c.out, string(body))
		return nil
	}

	if len(resp.Jobs) == 0 {
		fmt.Fprintln(c.out, "No transfer jobs found.")
		return nil
	}

	w := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "JOB ID\tSTATUS\tCREATED\tCOMPLETED\tPROGRESS")
	for _, job := range resp.Jobs {
		completed := "-"
		if job.CompletedAt != nil {
			completed = job.CompletedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", job.JobID, job.Status,
			job.CreatedAt.UTC().Format(time.RFC3339), completed, progressCell(job.Progress))
	}
	if err := w.Flush(); err != nil {
		return errors.Wrap(err, "failed to write job list")
	}

	if resp.Total > len(resp.Jobs) {
		fmt.Fprintf(c.out, "\nShowing %d-%d of %d jobs.\n",
			resp.Offset+1, resp.Offset+len(resp.Jobs), resp.Total)
	}
	return nil
}

// runTransferJobStatus prints one job's status, optionally following it to a
// terminal state.
//
// The job is always fetched once before any waiting: that turns an unknown or
// someone else's job ID into the server's own 404 right away, instead of a
// wait that silently degrades to polling an endpoint that will never answer.
func (c *transferJobClient) runTransferJobStatus(ctx context.Context, jobID string, wait bool) error {
	status, body, err := c.getJob(ctx, jobID)
	if err != nil {
		return err
	}

	if !wait || isTerminalTransferJobStatus(status.Status) {
		c.printJobStatus(status, body)
		if wait {
			return terminalTransferJobError(jobID, status)
		}
		return nil
	}

	if !c.jsonOut {
		fmt.Fprintf(c.out, "Transfer job %s is %s — waiting for completion...\n", jobID, status.Status)
	}
	return c.waitForJob(ctx, jobID)
}

// terminalTransferJobError turns an already-terminal job into the exit status
// a caller that asked to wait for it expects: nil for success, an error
// otherwise, matching what waitForJob reports for a job that finishes while
// being watched.
func terminalTransferJobError(jobID string, status *transfer.TransferJobStatus) error {
	switch status.Status {
	case "failed", "error":
		return fmt.Errorf("transfer job %s failed: %s", jobID, status.Error)
	case "cancelled":
		return fmt.Errorf("transfer job %s was cancelled", jobID)
	}
	return nil
}

// printJobStatus renders one job for a human, or echoes the server's own JSON.
func (c *transferJobClient) printJobStatus(status *transfer.TransferJobStatus, body []byte) {
	if c.jsonOut {
		fmt.Fprintln(c.out, string(body))
		return
	}
	fmt.Fprintf(c.out, "Job ID:    %s\n", status.JobID)
	fmt.Fprintf(c.out, "Status:    %s\n", status.Status)
	fmt.Fprintf(c.out, "Created:   %s\n", status.CreatedAt.UTC().Format(time.RFC3339))
	if status.CompletedAt != nil {
		fmt.Fprintf(c.out, "Completed: %s\n", status.CompletedAt.UTC().Format(time.RFC3339))
	}
	if status.SourceCredentialID != "" {
		fmt.Fprintf(c.out, "Source credential: %s\n", status.SourceCredentialID)
	}
	if status.DestCredentialID != "" {
		fmt.Fprintf(c.out, "Dest credential:   %s\n", status.DestCredentialID)
	}
	// An absent progress is not "nothing moved": the server drops a finished
	// job from memory and rebuilds its status from a durable record that
	// carries no byte counts, so say so rather than printing a zero.
	if status.Progress == nil {
		fmt.Fprintln(c.out, "Progress:  unknown (the server no longer holds this job's counters)")
	} else {
		progress := status.Progress
		fmt.Fprintf(c.out, "Progress:  %s\n",
			formatTransferProgress(progress.BytesTransferred, progress.TotalBytes))
		fmt.Fprintf(c.out, "Transfers: %d/%d completed",
			progress.TransfersCompleted, progress.TransfersTotal)
		if progress.TransfersFailed > 0 {
			fmt.Fprintf(c.out, " (%d failed)", progress.TransfersFailed)
		}
		fmt.Fprintln(c.out)
		if progress.TransferRateMbps > 0 {
			fmt.Fprintf(c.out, "Rate:      %.2f Mbps\n", progress.TransferRateMbps)
		}
	}
	if status.Error != "" {
		fmt.Fprintf(c.out, "Error:     %s\n", status.Error)
	}
}

// runTransferJobCancel cancels a job and reports the outcome.
func (c *transferJobClient) runTransferJobCancel(ctx context.Context, jobID string) error {
	body, err := c.cancelJob(ctx, jobID)
	if err != nil {
		return err
	}
	if c.jsonOut {
		if len(body) > 0 {
			fmt.Fprintln(c.out, string(body))
		} else {
			result, _ := json.Marshal(map[string]string{"job_id": jobID, "status": "cancelled"})
			fmt.Fprintln(c.out, string(result))
		}
	} else {
		fmt.Fprintf(c.out, "Transfer job %s cancelled.\n", jobID)
	}
	return nil
}

func transferJobListMain(cmd *cobra.Command, args []string) error {
	client, err := newTransferJobClient()
	if err != nil {
		return err
	}
	return client.runTransferJobList(cmd.Context(), transferJobListStatus, transferJobListLimit, transferJobListOffset)
}

func transferJobStatusMain(cmd *cobra.Command, args []string) error {
	client, err := newTransferJobClient()
	if err != nil {
		return err
	}
	return client.runTransferJobStatus(cmd.Context(), args[0], transferJobStatusWait)
}

func transferJobCancelMain(cmd *cobra.Command, args []string) error {
	client, err := newTransferJobClient()
	if err != nil {
		return err
	}
	return client.runTransferJobCancel(cmd.Context(), args[0])
}
