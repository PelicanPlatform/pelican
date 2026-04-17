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

package origin_serve

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/version"
)

// tpcProgressWriter wraps an io.Writer and tracks bytes written and
// transfer rate using an exponentially weighted moving average, mirroring
// the approach used by the client's progressWriter.
type tpcProgressWriter struct {
	writer         io.Writer
	bytesWritten   atomic.Int64
	firstByteTime  time.Time
	bytesPerSecond atomic.Int64
	lastRateSample time.Time
}

func (pw *tpcProgressWriter) Write(p []byte) (n int, err error) {
	if pw.firstByteTime.IsZero() && len(p) > 0 {
		pw.firstByteTime = time.Now()
	}
	now := time.Now()
	startupTime := now.Sub(pw.firstByteTime)
	startupTimeUS := startupTime.Microseconds()
	if startupTime < 5*time.Second && startupTimeUS > 0 {
		pw.bytesPerSecond.Store(1000000 * pw.bytesWritten.Load() / startupTimeUS)
		pw.lastRateSample = now
	} else {
		elapsed := now.Sub(pw.lastRateSample)
		pw.lastRateSample = now
		elapsedUS := elapsed.Microseconds()
		if elapsedUS > 0 {
			oldBPS := pw.bytesPerSecond.Load()
			alpha := math.Exp(-1 * float64(elapsed) / float64(10*time.Second))
			recentRate := 1000000 * int64(len(p)) / elapsedUS
			pw.bytesPerSecond.Store(int64(float64(oldBPS)*alpha + float64(recentRate)*(1-alpha)))
		}
	}
	n, err = pw.writer.Write(p)
	pw.bytesWritten.Add(int64(n))
	return n, err
}

func (pw *tpcProgressWriter) BytesComplete() int64 {
	return pw.bytesWritten.Load()
}

func (pw *tpcProgressWriter) BytesPerSecond() int64 {
	return pw.bytesPerSecond.Load()
}

// handleCopyTPC implements HTTP third-party copy (TPC) in "pull" mode,
// as described in the WLCG HTTP TPC specification:
//
//	https://twiki.cern.ch/twiki/bin/view/LCG/HttpTpc
//
// The client sends an HTTP COPY request to the destination origin with:
//   - Source header: URL of the source object
//   - Authorization header: bearer token authorising writes on this destination
//   - TransferHeader* headers: any header prefixed with "TransferHeader" is
//     forwarded to the source GET with the prefix stripped (e.g.
//     TransferHeaderAuthorization becomes Authorization).  Hop-by-hop and
//     framing headers (Host, Content-Length, Transfer-Encoding, …) are
//     excluded for safety.
//
// The handler GETs the object from the source, writes it to the local
// backend filesystem, and streams WLCG HTTP-TPC performance markers back
// to the client so it can monitor progress.
//
// Performance marker format (one or more):
//
//	Perf Marker
//	Stripe Index: 0
//	Stripe Bytes Transferred: <N>
//	Total Stripe Count: 1
//	End
//
// Followed, on success, by:
//
//	success: Created
//
// Or on failure:
//
//	failure: <error description>
func handleCopyTPC(c *gin.Context, backend server_utils.OriginBackend) {
	sourceHeader := c.GetHeader("Source")
	if sourceHeader == "" {
		c.String(http.StatusBadRequest, "Missing required Source header for third-party copy")
		return
	}

	// Validate the Source URL
	sourceURL, err := url.Parse(sourceHeader)
	if err != nil || (sourceURL.Scheme != "http" && sourceURL.Scheme != "https") {
		c.String(http.StatusBadRequest, "Invalid Source URL: must be an http or https URL")
		return
	}

	destPath := c.Param("path")
	if destPath == "" {
		c.String(http.StatusBadRequest, "Missing destination path")
		return
	}

	fields := log.Fields{
		"component": "origin",
		"method":    "COPY",
		"source":    sourceHeader,
		"dest":      destPath,
		"client":    c.ClientIP(),
	}
	log.WithFields(fields).Info("Starting third-party copy")

	// Build the GET request to pull the object from the source.
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceHeader, nil)
	if err != nil {
		log.WithFields(fields).Errorf("Failed to create GET request to source: %v", err)
		c.String(http.StatusInternalServerError, "Failed to create request to source")
		return
	}

	// Forward any TransferHeader* headers to the GET request.
	// Per the WLCG HTTP-TPC spec (and XRootD convention), a request
	// header of the form "TransferHeaderFoo: bar" is forwarded to the
	// source as "Foo: bar".  Certain hop-by-hop or unsafe headers are
	// excluded to prevent request smuggling or corruption.
	forwardTransferHeaders(c.Request.Header, getReq)
	getReq.Header.Set("User-Agent", "pelican-origin/"+version.GetVersion())

	// Propagate Pelican tracing headers to the source request
	getReq = server_utils.StashPelicanHeaders(getReq)

	client := &http.Client{
		Transport: config.GetSSRFHttpTransport(),
	}

	getResp, err := client.Do(getReq)
	if err != nil {
		log.WithFields(fields).Errorf("Failed to GET from source: %v", err)
		c.String(http.StatusBadGateway, "Failed to fetch object from source: %s", err.Error())
		return
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK && getResp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
		log.WithFields(fields).Errorf("Source returned HTTP %d: %s", getResp.StatusCode, string(body))
		c.String(http.StatusBadGateway, "Source returned HTTP %d", getResp.StatusCode)
		return
	}

	totalSize := getResp.ContentLength // may be -1 if unknown

	// Open the destination file for writing via the backend's WebDAV filesystem
	fs := backend.FileSystem()
	destFile, err := fs.OpenFile(c.Request.Context(), destPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.WithFields(fields).Errorf("Failed to open destination file: %v", err)
		if os.IsNotExist(err) {
			c.String(http.StatusConflict, "Parent directory does not exist")
		} else if os.IsPermission(err) {
			c.String(http.StatusForbidden, "Permission denied writing to destination")
		} else {
			c.String(http.StatusInternalServerError, "Failed to open destination: %s", err.Error())
		}
		return
	}

	// Start streaming the response — 201 Created with performance markers
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(http.StatusCreated)
	c.Writer.Flush()

	// Copy data from source to destination, monitoring progress with
	// the same timeout mechanisms used by the client's downloadHTTP:
	//   - Stopped transfer timeout: cancel if no bytes flow for too long
	//   - Slow transfer ramp-up: grace period before enforcing minimum speed
	//   - Slow transfer window: cancel if speed stays below limit after ramp-up
	stoppedTransferTimeout := param.Client_StoppedTransferTimeout.GetDuration()
	slowTransferRampupTime := param.Client_SlowTransferRampupTime.GetDuration()
	slowTransferWindow := param.Client_SlowTransferWindow.GetDuration()
	downloadLimit := int64(param.Client_MinimumDownloadSpeed.GetInt())

	log.WithFields(fields).Debugf("TPC timeout config: stopped=%s, ramp-up=%s, slow window=%s, min speed=%d B/s",
		stoppedTransferTimeout, slowTransferRampupTime, slowTransferWindow, downloadLimit)

	pw := &tpcProgressWriter{writer: destFile}

	// Run the copy in a background goroutine so the main goroutine can
	// monitor progress and enforce timeouts.  Cancelling `ctx` (via
	// cancel()) will cause the response body read to return an error,
	// terminating the goroutine.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(pw, getResp.Body)
		done <- err
		close(done)
	}()

	// Ticker for checking transfer speed and stopped-transfer (every 500ms)
	speedTicker := time.NewTicker(500 * time.Millisecond)
	defer speedTicker.Stop()

	// Ticker for emitting performance markers (every ~2 seconds)
	markerTicker := time.NewTicker(2 * time.Second)
	defer markerTicker.Stop()

	copyStart := time.Now()
	var lastBytesComplete int64
	var noProgressStartTime time.Time
	startBelowLimit := time.Time{}
	var lastMarkerBytes int64

	var copyErr error
Loop:
	for {
		select {
		case <-markerTicker.C:
			current := pw.BytesComplete()
			if current != lastMarkerBytes {
				writePerfMarker(c.Writer, current)
				lastMarkerBytes = current
			}

		case <-speedTicker.C:
			currentDownloaded := pw.BytesComplete()

			// --- Stopped transfer check ---
			if currentDownloaded == lastBytesComplete {
				if noProgressStartTime.IsZero() {
					noProgressStartTime = time.Now()
				} else if time.Since(noProgressStartTime) > stoppedTransferTimeout {
					copyErr = fmt.Errorf("transfer stalled: no bytes received for %s (transferred %d bytes)",
						time.Since(noProgressStartTime).Round(time.Second), currentDownloaded)
					log.WithFields(fields).Error(copyErr)
					cancel()
					<-done
					break Loop
				}
			} else {
				noProgressStartTime = time.Time{}
			}
			lastBytesComplete = currentDownloaded

			// --- Slow transfer check ---
			transferRate := pw.BytesPerSecond()
			if downloadLimit > 0 && transferRate < downloadLimit {
				if time.Since(copyStart) < slowTransferRampupTime {
					continue
				} else if startBelowLimit.IsZero() {
					log.WithFields(fields).Warnf("TPC transfer speed %d B/s is below minimum %d B/s; will cancel if it persists for %s",
						transferRate, downloadLimit, slowTransferWindow)
					startBelowLimit = time.Now()
					continue
				} else if time.Since(startBelowLimit) < slowTransferWindow {
					continue
				}
				copyErr = fmt.Errorf("transfer too slow: %d B/s is below minimum %d B/s (persisted for %s, transferred %d bytes)",
					transferRate, downloadLimit, time.Since(startBelowLimit).Round(time.Second), currentDownloaded)
				log.WithFields(fields).Error(copyErr)
				cancel()
				<-done
				break Loop
			} else {
				startBelowLimit = time.Time{}
			}

		case readErr := <-done:
			if readErr != nil {
				copyErr = fmt.Errorf("read from source failed: %w", readErr)
			}
			break Loop

		case <-ctx.Done():
			copyErr = ctx.Err()
			break Loop
		}
	}

	totalCopied := pw.BytesComplete()

	// Close the destination file; surface any deferred write/sync errors
	if closeErr := destFile.Close(); closeErr != nil && copyErr == nil {
		copyErr = fmt.Errorf("close destination file failed: %w", closeErr)
	}

	if copyErr != nil {
		log.WithFields(fields).Errorf("Third-party copy failed: %v", copyErr)
		fmt.Fprintf(c.Writer, "failure: %s\n", copyErr.Error())
		c.Writer.Flush()
		// Clean up the partial destination file on failure
		if removeErr := fs.RemoveAll(c.Request.Context(), destPath); removeErr != nil {
			log.WithFields(fields).Warningf("Failed to clean up partial destination file after copy failure: %v", removeErr)
		}
		return
	}

	// Sanity-check: if the source told us the size, make sure we got it all
	if totalSize >= 0 && totalCopied != totalSize {
		msg := fmt.Sprintf("size mismatch: expected %d bytes from source but wrote %d", totalSize, totalCopied)
		log.WithFields(fields).Error(msg)
		fmt.Fprintf(c.Writer, "failure: %s\n", msg)
		c.Writer.Flush()
		// Clean up the incomplete destination file
		if removeErr := fs.RemoveAll(c.Request.Context(), destPath); removeErr != nil {
			log.WithFields(fields).Warningf("Failed to clean up incomplete destination file: %v", removeErr)
		}
		return
	}

	// Emit a final performance marker (in case the file was smaller
	// than markerInterval, or to report the final total) and then
	// the success line.
	writePerfMarker(c.Writer, totalCopied)
	fmt.Fprint(c.Writer, "success: Created\n")
	c.Writer.Flush()

	log.WithFields(fields).Infof("Third-party copy completed: %d bytes", totalCopied)
}

// writePerfMarker writes a single WLCG HTTP-TPC performance marker to the
// response body and flushes it so the client can see progress immediately.
func writePerfMarker(w gin.ResponseWriter, bytesTransferred int64) {
	fmt.Fprint(w, "Perf Marker\n")
	fmt.Fprint(w, "Stripe Index: 0\n")
	fmt.Fprintf(w, "Stripe Bytes Transferred: %d\n", bytesTransferred)
	fmt.Fprint(w, "Total Stripe Count: 1\n")
	fmt.Fprint(w, "End\n")
	w.Flush()
}

// isTPCRequest returns true when a COPY request carries a Source
// header, indicating a third-party copy (as opposed to a WebDAV
// same-server COPY).
func isTPCRequest(r *http.Request) bool {
	return r.Method == "COPY" && strings.TrimSpace(r.Header.Get("Source")) != ""
}

// transferHeaderPrefix is the case-insensitive prefix that the WLCG
// HTTP-TPC spec uses to carry headers intended for the source GET.
const transferHeaderPrefix = "Transferheader"

// transferHeaderDenyList contains header names (canonical form) that
// must NOT be forwarded even when sent with the TransferHeader prefix.
// These are hop-by-hop, framing, or security-sensitive headers whose
// override could break the HTTP exchange or enable request smuggling.
var transferHeaderDenyList = map[string]bool{
	"Content-Length":    true,
	"Host":              true,
	"Transfer-Encoding": true,
	"Connection":        true,
	"Keep-Alive":        true,
	"Te":                true,
	"Trailer":           true,
	"Upgrade":           true,
}

// maxTransferHeaders is the maximum number of TransferHeader* headers
// that will be forwarded to the source GET request.  This prevents a
// malicious or misconfigured client from inflating the outgoing request.
const maxTransferHeaders = 50

// forwardTransferHeaders scans inbound for headers whose name starts
// with "TransferHeader" (case-insensitive) and copies them onto dst
// with the prefix stripped.  For example, "TransferHeaderAuthorization:
// Bearer X" becomes "Authorization: Bearer X" on dst.
//
// Headers in the deny-list are silently skipped.  At most
// maxTransferHeaders headers are forwarded; any beyond that limit are
// silently dropped.
func forwardTransferHeaders(inbound http.Header, dst *http.Request) {
	prefixLen := len(transferHeaderPrefix)
	forwarded := 0
	for name, values := range inbound {
		// http.Header keys are already in canonical form, but the
		// prefix comparison needs to be case-insensitive because
		// the canonical form of "Transferheaderacceptranges" has a
		// lowercase 'h' after "Transfer".
		if len(name) <= prefixLen {
			continue
		}
		if !strings.EqualFold(name[:prefixLen], transferHeaderPrefix) {
			continue
		}
		stripped := name[prefixLen:]
		if stripped == "" {
			continue
		}
		canonical := http.CanonicalHeaderKey(stripped)
		if transferHeaderDenyList[canonical] {
			log.Debugf("TPC: skipping denied TransferHeader override for %s", canonical)
			continue
		}
		if forwarded >= maxTransferHeaders {
			log.Warningf("TPC: reached maximum of %d forwarded TransferHeaders; dropping %s", maxTransferHeaders, canonical)
			continue
		}
		// Override any existing header values on dst, but preserve
		// all values provided on the inbound request.
		dst.Header.Del(canonical)
		for _, v := range values {
			dst.Header.Add(canonical, v)
		}
		forwarded++
	}
}
