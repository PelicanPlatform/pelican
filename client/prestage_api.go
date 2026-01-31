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
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

// Check if a cache endpoint supports the Pelican prestage API
// Returns true if the API is supported, false otherwise
func checkPrestageAPISupport(ctx context.Context, cacheUrl *url.URL, token *tokenGenerator) bool {
	// Test for API support by invoking without the path parameter
	// Should return 400 if supported, 404 if not
	testUrl := *cacheUrl
	testUrl.Path = "/pelican/api/v1.0/prestage"

	req, err := http.NewRequestWithContext(ctx, "GET", testUrl.String(), nil)
	if err != nil {
		log.Debugf("Failed to create request to test prestage API support for %s: %v", cacheUrl.Host, err)
		return false
	}

	// Add authentication if available
	if token != nil {
		if tokenStr, err := token.Get(); err == nil && tokenStr != "" {
			req.Header.Set("Authorization", "Bearer "+tokenStr)
		}
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: config.GetTransport().Clone(),
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Debugf("Failed to test prestage API support for %s: %v", cacheUrl.Host, err)
		return false
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	// If we get a 400, the API is supported (missing required path parameter)
	// If we get a 404, the API is not supported (endpoint doesn't exist)
	if resp.StatusCode == http.StatusBadRequest {
		log.Debugf("Cache %s supports the Pelican prestage API", cacheUrl.Host)
		return true
	}

	log.Debugf("Cache %s does not support the Pelican prestage API (status: %d)", cacheUrl.Host, resp.StatusCode)
	return false
}

// Invoke the Pelican prestage API for a file
// Returns the transfer results or an error
func invokePrestageAPI(ctx context.Context, cacheUrl *url.URL, remotePath string, token *tokenGenerator, callback TransferCallbackFunc) (bytesTransferred int64, err error) {
	apiUrl := *cacheUrl
	apiUrl.Path = "/pelican/api/v1.0/prestage"

	// Add the path query parameter
	q := apiUrl.Query()
	q.Set("path", remotePath)
	apiUrl.RawQuery = q.Encode()

	log.Debugf("Invoking prestage API at %s for path %s", cacheUrl.Host, remotePath)

	req, err := http.NewRequestWithContext(ctx, "GET", apiUrl.String(), nil)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create prestage API request")
	}

	// Add authentication if available
	if token != nil {
		if tokenStr, err := token.Get(); err == nil && tokenStr != "" {
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			log.Debugf("Set Authorization header for prestage API request (token length: %d)", len(tokenStr))
		} else {
			log.Debugf("Token available but could not get token string: %v", err)
		}
	} else {
		log.Debug("No token available for prestage API request")
	}

	client := &http.Client{
		Transport: config.GetTransport().Clone(),
	}

	// Use a context with timeout for the initial response
	initialCtx, initialCancel := context.WithTimeout(ctx, 20*time.Second)
	defer initialCancel()

	req = req.WithContext(initialCtx)
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "failed to invoke prestage API")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, errors.Errorf("prestage API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read the chunked response and parse progress updates
	// Track progress to ensure we're getting updates within 20s windows
	scanner := bufio.NewScanner(resp.Body)
	var lastOffset int64 = 0
	var fileSize int64 = -1
	lastProgressTime := time.Now()
	progressTimeout := 20 * time.Second

	// Channel to signal scanner completion
	scanDone := make(chan struct{})
	var scanErr error

	go func() {
		defer close(scanDone)
		for scanner.Scan() {
			line := scanner.Text()
			log.Debugf("Prestage API response: %s", line)

			// Parse status updates
			if strings.HasPrefix(line, "status: queued") {
				// Request is queued - reset progress timer
				lastProgressTime = time.Now()
				continue
			} else if strings.HasPrefix(line, "status: active") {
				// Parse offset from "status: active,offset=<bytes>"
				parts := strings.Split(line, ",")
				if len(parts) == 2 {
					offsetPart := strings.TrimPrefix(parts[1], "offset=")
					if offset, err := strconv.ParseInt(offsetPart, 10, 64); err == nil {
						// Only reset timer if we're making progress
						if offset > lastOffset {
							lastProgressTime = time.Now()
							bytesTransferred = offset
							if callback != nil && fileSize > 0 {
								callback(remotePath, offset, fileSize, false)
							}
							lastOffset = offset
						}
					}
				}
			} else if strings.HasPrefix(line, "success: ok") {
				// Prestage completed successfully
				if callback != nil && fileSize > 0 {
					callback(remotePath, fileSize, fileSize, true)
				}
				// If we didn't get any offset updates, the file was likely already cached
				if lastOffset == 0 && fileSize > 0 {
					bytesTransferred = fileSize
				} else if lastOffset > 0 {
					bytesTransferred = lastOffset
				}
				return
			} else if strings.HasPrefix(line, "failure: ") {
				// Parse failure message
				scanErr = errors.Errorf("prestage failed: %s", strings.TrimPrefix(line, "failure: "))
				return
			}
		}

		if err := scanner.Err(); err != nil {
			scanErr = errors.Wrap(err, "error reading prestage API response")
		}
	}()

	// Monitor for progress timeout
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-scanDone:
			if scanErr != nil {
				return bytesTransferred, scanErr
			}
			return bytesTransferred, nil
		case <-ticker.C:
			if time.Since(lastProgressTime) > progressTimeout {
				// Close the response body to unblock the scanner goroutine
				resp.Body.Close()
				// Wait for goroutine to exit
				<-scanDone
				return bytesTransferred, errors.Errorf("prestage timed out: no progress for %v (last offset: %d)", progressTimeout, lastOffset)
			}
		case <-ctx.Done():
			// Close the response body to unblock the scanner goroutine
			resp.Body.Close()
			// Wait for goroutine to exit
			<-scanDone
			return bytesTransferred, errors.Wrap(ctx.Err(), "prestage cancelled")
		}
	}
}
