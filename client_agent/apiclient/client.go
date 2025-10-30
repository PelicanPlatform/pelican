/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/param"
)

// APIClient provides a client interface to the Pelican Client API Server
type APIClient struct {
	socketPath string
	httpClient *http.Client
	baseURL    string
}

// NewAPIClient creates a new API client connected to the Unix socket
func NewAPIClient(socketPath string) (*APIClient, error) {
	if socketPath == "" {
		// Check if parameter is set via environment or config
		if paramSocket := param.ClientAgent_Socket.GetString(); paramSocket != "" {
			socketPath = paramSocket
		} else {
			// Use default socket path
			expandedPath, err := expandPath(client_agent.DefaultSocketPath)
			if err != nil {
				return nil, errors.Wrap(err, "failed to expand default socket path")
			}
			socketPath = expandedPath
		}
	}

	if socketPath != "" {
		expandedPath, err := expandPath(socketPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to expand socket path")
		}
		socketPath = expandedPath
	}

	// Create HTTP client with Unix socket transport
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	return &APIClient{
		socketPath: socketPath,
		httpClient: httpClient,
		baseURL:    "http://localhost/api/v1/xfer",
	}, nil
}

// IsServerRunning checks if the API server is accessible
func (c *APIClient) IsServerRunning(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/health", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// CreateJob creates a new transfer job and returns the job ID
func (c *APIClient) CreateJob(ctx context.Context, transfers []client_agent.TransferRequest, options client_agent.TransferOptions) (string, error) {
	jobReq := client_agent.JobRequest{
		Transfers: transfers,
		Options:   options,
	}

	body, err := json.Marshal(jobReq)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal job request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/jobs", bytes.NewBuffer(body))
	if err != nil {
		return "", errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var jobResp client_agent.JobResponse
	if err := json.NewDecoder(resp.Body).Decode(&jobResp); err != nil {
		return "", errors.Wrap(err, "failed to decode response")
	}

	return jobResp.JobID, nil
}

// GetJobStatus retrieves the current status of a job
func (c *APIClient) GetJobStatus(ctx context.Context, jobID string) (*client_agent.JobStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/jobs/"+jobID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var jobStatus client_agent.JobStatus
	if err := json.NewDecoder(resp.Body).Decode(&jobStatus); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return &jobStatus, nil
}

// WaitForJob polls until the job completes or the timeout is reached
func (c *APIClient) WaitForJob(ctx context.Context, jobID string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := c.GetJobStatus(ctx, jobID)
			if err != nil {
				return err
			}

			switch status.Status {
			case client_agent.StatusCompleted:
				return nil
			case client_agent.StatusFailed:
				return errors.Errorf("job failed: %s", status.Error)
			case client_agent.StatusCancelled:
				return errors.New("job was cancelled")
			}
		}
	}
}

// CancelJob cancels a running job
func (c *APIClient) CancelJob(ctx context.Context, jobID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/jobs/"+jobID, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListJobs lists all jobs with optional filtering
func (c *APIClient) ListJobs(ctx context.Context, status string, limit, offset int) (*client_agent.JobListResponse, error) {
	url := fmt.Sprintf("%s/jobs?limit=%d&offset=%d", c.baseURL, limit, offset)
	if status != "" {
		url += "&status=" + status
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var listResp client_agent.JobListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return &listResp, nil
}

// Stat retrieves metadata about a remote object
func (c *APIClient) Stat(ctx context.Context, url string, options client_agent.TransferOptions) (*client_agent.StatResponse, error) {
	statReq := client_agent.StatRequest{
		URL:     url,
		Options: options,
	}

	body, err := json.Marshal(statReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal stat request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/stat", bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var statResp client_agent.StatResponse
	if err := json.NewDecoder(resp.Body).Decode(&statResp); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return &statResp, nil
}

// List retrieves directory listing
func (c *APIClient) List(ctx context.Context, url string, options client_agent.TransferOptions) (*client_agent.ListResponse, error) {
	listReq := client_agent.ListRequest{
		URL:     url,
		Options: options,
	}

	body, err := json.Marshal(listReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal list request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/list", bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var listResp client_agent.ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return &listResp, nil
}

// Delete deletes a remote object
func (c *APIClient) Delete(ctx context.Context, url string, recursive bool, options client_agent.TransferOptions) error {
	deleteReq := client_agent.DeleteRequest{
		URL:       url,
		Recursive: recursive,
		Options:   options,
	}

	body, err := json.Marshal(deleteReq)
	if err != nil {
		return errors.Wrap(err, "failed to marshal delete request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/delete", bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return errors.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// expandPath expands ~ to home directory (duplicated from server.go for package independence)
func expandPath(path string) (string, error) {
	// Implementation is same as in server.go but kept separate for independence
	return client_agent.ExpandPath(path)
}
