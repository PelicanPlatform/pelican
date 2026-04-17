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

package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
)

// tpcStatus represents a status update from a third-party-copy transfer
type tpcStatus struct {
	err     error
	done    bool
	xferred uint64
}

// copyHTTP uses the WebDAV COPY verb to perform a third-party-copy transfer.
// Implements WLCG pull-mode TPC: a COPY is issued to the destination with a
// Source header so the destination pulls data from the source.
func copyHTTP(xfer *transferFile) (transferResults TransferResults, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in HTTP copy code:", r)
			err = errors.Errorf("unrecoverable error (panic) occurred in copyHTTP: %v", r)
		}
	}()
	if len(xfer.attempts) == 0 {
		log.Errorln("No source URLs specified; cannot copy")
		err = errors.New("no source URLs specified")
		return
	}
	if len(xfer.job.dirResp.ObjectServers) == 0 {
		log.Errorln("No resolved destination servers available; cannot copy")
		err = errors.New("no resolved destination servers available")
		return
	}
	resolvedDestUrl := *xfer.job.dirResp.ObjectServers[0]
	resolvedDestUrl.Path = computeUploadDestPath(xfer.remoteURL.Path, resolvedDestUrl.Path)
	resolvedDestUrl.RawQuery = xfer.remoteURL.RawQuery

	log.Debugln("Copying object from", xfer.attempts[0].Url.String(), "to", resolvedDestUrl.String())
	transferResults = newTransferResults(xfer.job)

	// In dry-run mode, log what would be copied and return success
	if xfer.job != nil && xfer.job.dryRun {
		fmt.Printf("COPY: %s -> %s\n", xfer.attempts[0].Url.String(), resolvedDestUrl.String())
		return transferResults, nil
	}

	lastUpdate := time.Now()
	if xfer.callback != nil {
		xfer.callback(xfer.remoteURL.String(), 0, 0, false)
	}
	downloaded := int64(-1)
	totalSize := int64(-1)
	transferStartTime := time.Now()
	transferResults.TransferStartTime = transferStartTime
	attempt := TransferResult{
		CacheAge: -1,
		Number:   0,
		Endpoint: resolvedDestUrl.Host,
	}

	defer func() {
		endTime := time.Now()
		attempt.TransferEndTime = endTime
		attempt.TransferTime = endTime.Sub(transferStartTime)
		attempt.TransferFileBytes = totalSize
		transferResults.Attempts = []TransferResult{attempt}

		if xfer.callback != nil {
			finalSize := int64(0)
			if totalSize >= 0 {
				finalSize = totalSize
			}
			xfer.callback(xfer.remoteURL.String(), downloaded, finalSize, true)
		}
		if xfer.engine != nil {
			xfer.engine.ewmaCtr.Add(int64(time.Since(lastUpdate)))
		}
	}()

	client := http.Client{
		Transport: config.GetTransport(),
	}

	ctx, cancel := context.WithCancel(xfer.ctx)
	defer cancel()

	// HEAD request to get source size
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, xfer.attempts[0].Url.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "failed to get size of the source object %s", xfer.attempts[0].Url.String())
		return
	}

	if xfer.srcToken != nil {
		srcTkn, tErr := xfer.srcToken.Get()
		if tErr == nil && srcTkn != "" {
			req.Header.Set("Authorization", "Bearer "+srcTkn)
		}
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	// If checksums were requested, add Want-Digest to the HEAD so we can compare after the COPY
	if len(xfer.requestedChecksums) > 0 {
		val := ""
		for i, cksum := range xfer.requestedChecksums {
			if i > 0 {
				val += ","
			}
			val += HttpDigestFromChecksum(cksum)
		}
		req.Header.Set("Want-Digest", val)
	}
	log.Debugln("Starting the HEAD request to the HTTP Third Party Copy source...")
	resp, err := client.Do(req)
	if err != nil {
		err = error_codes.NewContactError(
			errors.Wrapf(err, "failed to execute the HEAD request to third-party-copy source %s", xfer.attempts[0].Url.String()),
		)
		log.Errorln(err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		httpErr := &HttpErrResp{resp.StatusCode, fmt.Sprintf("HEAD request to source failed (HTTP status %d)", resp.StatusCode),
			wrapErrorByStatusCode(resp.StatusCode, fmt.Errorf("source HEAD returned HTTP %d", resp.StatusCode))}
		err = httpErr
		return
	}
	totalSize = resp.ContentLength
	if resp.ContentLength < 0 {
		log.Warningln("Third-party-copy source", xfer.attempts[0].Url.String(), "is of unknown size; download statistics may be incorrect")
	}
	attempt.ServerVersion = resp.Header.Get("Server")

	// Parse source checksums from the HEAD response Digest header
	var sourceChecksums []ChecksumInfo
	if len(xfer.requestedChecksums) > 0 {
		sourceChecksums = parseDigestHeader(resp.Header, nil)
		if len(sourceChecksums) > 0 {
			transferResults.ServerChecksums = sourceChecksums
			log.Debugln("Source checksums retrieved for TPC verification:", len(sourceChecksums), "checksum(s)")
		} else {
			log.Debugln("Source did not return any Digest headers for TPC checksum verification")
		}
	}

	// Send early metadata from the HEAD response if a channel was provided
	if xfer.metadataChan != nil {
		metadata := TransferMetadata{
			ContentLength: totalSize,
			ObjectSize:    totalSize,
			ETag:          resp.Header.Get("ETag"),
			ContentType:   resp.Header.Get("Content-Type"),
			CacheControl:  resp.Header.Get("Cache-Control"),
		}
		if lmStr := resp.Header.Get("Last-Modified"); lmStr != "" {
			if lm, parseErr := http.ParseTime(lmStr); parseErr == nil {
				metadata.LastModified = lm
			}
		}
		select {
		case xfer.metadataChan <- metadata:
		default:
			log.Debugln("Metadata channel full, skipping early metadata send for TPC")
		}
	}

	// COPY request to the destination
	req, err = http.NewRequestWithContext(ctx, "COPY", resolvedDestUrl.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "unable to create request for third-party-copy to %s", xfer.remoteURL.String())
		return
	}

	if tkn, tErr := xfer.token.Get(); tErr == nil && tkn != "" {
		req.Header.Set("Authorization", "Bearer "+tkn)
	}
	if xfer.srcToken != nil {
		if srcTkn, tErr := xfer.srcToken.Get(); tErr == nil && srcTkn != "" {
			req.Header.Set("TransferHeaderAuthorization", "Bearer "+srcTkn)
		}
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	req.Header.Set("Source", xfer.attempts[0].Url.String())

	log.Debugln("Starting the HTTP Third Party Copy transfer...")
	resp, err = client.Do(req)

	if err != nil {
		log.Errorf("Failed to execute the third-party-copy to %s: %s", xfer.remoteURL.String(), err.Error())
		err = error_codes.NewContactError(
			errors.Wrapf(err, "failed to execute the third-party-copy to %s", xfer.remoteURL.String()),
		)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var respBytes []byte
		respBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("TPC COPY to %s failed (HTTP status %d); additionally, reading the response body failed: %s", resolvedDestUrl.String(), resp.StatusCode, err.Error())
		} else {
			statusErr := wrapErrorByStatusCode(resp.StatusCode, fmt.Errorf("destination COPY returned HTTP %d", resp.StatusCode))
			if resp.StatusCode == http.StatusOK {
				log.Errorf("TPC COPY to %s returned HTTP 200 instead of 201 Created; the destination server does not have the TPC module loaded: %s",
					resolvedDestUrl.String(), string(respBytes))
				err = &HttpErrResp{Code: resp.StatusCode, Str: fmt.Sprintf("TPC COPY to %s failed: the destination server does not have the TPC module loaded (HTTP 200 instead of 201)",
					resolvedDestUrl.String()), Err: statusErr}
			} else if resp.StatusCode > 200 && resp.StatusCode < 300 {
				log.Errorf("TPC COPY to %s returned HTTP %d instead of 201 Created; the destination server may not support HTTP third-party-copy (ensure the TPC module is loaded): %s",
					resolvedDestUrl.String(), resp.StatusCode, string(respBytes))
				err = &HttpErrResp{Code: resp.StatusCode, Str: fmt.Sprintf("TPC COPY failed (HTTP status %d)",
					resp.StatusCode), Err: statusErr}
			} else {
				log.Errorf("TPC COPY to %s failed (HTTP status %d): %s", resolvedDestUrl.String(), resp.StatusCode, string(respBytes))
				err = &HttpErrResp{Code: resp.StatusCode, Str: fmt.Sprintf("TPC COPY failed (HTTP status %d)",
					resp.StatusCode), Err: statusErr}
			}
		}
		return
	}

	serverMessages := make(chan tpcStatus, 10)

	xfer.engine.egrp.Go(func() error { return monitorTPC(ctx, serverMessages, resp.Body) })

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	gotFirstByte := false
MessageHandler:
	for {
		select {
		case msg, ok := <-serverMessages:
			if !ok {
				break MessageHandler
			}
			if msg.err != nil || msg.done {
				err = msg.err
				break MessageHandler
			}
			downloaded = int64(msg.xferred)
			if !gotFirstByte && downloaded > 0 {
				gotFirstByte = true
				attempt.TimeToFirstByte = time.Since(transferStartTime)
			}
		case <-ticker.C:
			if totalSize < downloaded {
				totalSize = downloaded
				attempt.TransferFileBytes = totalSize
			}
			if xfer.callback != nil {
				log.Infof("Transfer %s->%s has downloaded %d bytes", xfer.attempts[0].Url.String(), xfer.remoteURL.String(), downloaded)
				xfer.callback(xfer.remoteURL.String(), downloaded, totalSize, false)
			}
		case <-ctx.Done():
			err = ctx.Err()
			break MessageHandler
		}
	}

	if err == nil {
		if totalSize >= 0 {
			transferResults.TransferredBytes = totalSize
		} else {
			// When totalSize is unknown (e.g., HEAD Content-Length < 0), fall back to the
			// final downloaded count so callers still get accurate transfer statistics.
			transferResults.TransferredBytes = downloaded
		}
	}

	// After a successful TPC, verify checksums if requested
	if err == nil && len(sourceChecksums) > 0 {
		destTkn := ""
		if tkn, tErr := xfer.token.Get(); tErr == nil {
			destTkn = tkn
		}
		destChecksums, cErr := fetchChecksum(ctx, xfer.requestedChecksums, &resolvedDestUrl, destTkn, xfer.project)
		if cErr != nil {
			log.Warningln("Could not retrieve destination checksums for TPC verification:", cErr)
		} else {
			transferResults.ClientChecksums = destChecksums
			// Compare: for each source checksum, see if the destination has a matching algorithm+value
			for _, srcCksum := range sourceChecksums {
				for _, destCksum := range destChecksums {
					if srcCksum.Algorithm == destCksum.Algorithm {
						if !bytes.Equal(srcCksum.Value, destCksum.Value) {
							log.Errorf("TPC checksum mismatch for %s: source %x != destination %x",
								HttpDigestFromChecksum(srcCksum.Algorithm), srcCksum.Value, destCksum.Value)
							if xfer.requireChecksum {
								err = &ChecksumMismatchError{
									Info:        srcCksum,
									ServerValue: destCksum.Value,
								}
								return
							}
						} else {
							log.Debugln("TPC checksum verified for", HttpDigestFromChecksum(srcCksum.Algorithm))
						}
						break
					}
				}
			}
		}
	}

	return
}

// monitorTPC reads periodic updates from the HTTP TPC response body,
// parses performance markers, and writes them to the channel.
//
// The performance marker format is defined by the WLCG HTTP TPC specification:
//   https://twiki.cern.ch/twiki/bin/view/LCG/HttpTpc
//
// This is guaranteed to close the channel before exiting.
func monitorTPC(ctx context.Context, messages chan tpcStatus, body io.Reader) error {
	defer close(messages)
	scanner := bufio.NewScanner(body)
	perfMarker := false
	stripes := make(map[int]uint64)
	xferred := uint64(0)
	curStripe := 0
	curStripeBytes := uint64(0)
	var err error
Listener:
	for scanner.Scan() {
		text := scanner.Text()
		if text == "Perf Marker" {
			perfMarker = true
		} else if text == "End" {
			if !perfMarker {
				log.Warning("Client received an end-of-performance marker but no beginning")
			}
			stripes[curStripe] = curStripeBytes
			perfMarker = false
			sum := uint64(0)
			for _, val := range stripes {
				sum += val
			}
			select {
			case messages <- tpcStatus{
				xferred: sum,
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
			xferred = sum
		} else { // All other messages have the format "key: value"
			info := strings.SplitN(text, ":", 2)
			if len(info) != 2 {
				log.Warningln("Invalid line in the TPC update:", text)
				continue
			}
			key := strings.TrimSpace(info[0])
			value := strings.TrimSpace(info[1])
			switch key {
			case "failure":
				err = errors.Errorf("TPC copy failed: %s", value)
				break Listener
			case "success":
				break Listener
			case "Stripe Index":
				idx, pErr := strconv.Atoi(value)
				if pErr == nil {
					curStripe = idx
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Index': %s (%s)", pErr.Error(), value)
				}
			case "Stripe Bytes Transferred":
				parsedBytes, pErr := strconv.ParseUint(value, 10, 64)
				if pErr == nil {
					curStripeBytes = parsedBytes
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Bytes Transferred': %s (%s)", pErr.Error(), value)
				}
			case "Total Stripe Count":
				// Ignored
			case "RemoteConnections":
				// Ignored
			default:
				log.Debugln("Received performance marker with unknown key:", key)
			}
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	select {
	case messages <- tpcStatus{
		err:     err,
		done:    true,
		xferred: xferred,
	}:
	case <-ctx.Done():
	}
	return nil
}

// Depending on the synchronization policy, decide if a TPC copy should be skipped.
// This stats the destination remote path using the destination's collections URL
// to check if the object already exists.
// sourceInfo is the fs.FileInfo from the source WebDAV listing.
// destCollClient is a WebDAV client pointed at the destination's collections URL.
func skipCopy(syncLevel SyncLevel, sourceInfo fs.FileInfo, destPath string, destCollClient *gowebdav.Client) bool {
	if syncLevel == SyncNone {
		return false
	}

	// Stat the destination to see if it already exists
	var destInfo fs.FileInfo
	err := retryWebDavOperation("Stat", func() error {
		var statErr error
		destInfo, statErr = destCollClient.Stat(destPath)
		return statErr
	})
	if err != nil {
		// If stat fails (e.g., 404), the destination doesn't exist; don't skip
		return false
	}

	switch syncLevel {
	case SyncExist:
		return true
	case SyncSize:
		return sourceInfo.Size() == destInfo.Size()
	}
	return false
}

// walkDirCopy walks the remote source directory and emits individual TPC copy jobs
// for each file found. This is used for recursive third-party-copy operations.
func (te *TransferEngine) walkDirCopy(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, srcUrl *url.URL) error {
	// Use the source director response to get the collections URL for listing
	collUrl := job.job.srcDirResp.XPelNsHdr.CollectionsUrl
	if collUrl == nil {
		return errors.New("collections URL not found in source director response for recursive copy")
	}
	log.Debugln("Trying source collections URL for TPC walk: ", collUrl.String())

	srcClient := createWebDavClient(collUrl, job.job.srcToken, job.job.project)

	// Create a destination WebDAV client for sync skip checks (stat destination)
	var destClient *gowebdav.Client
	if job.job.syncLevel != SyncNone {
		destCollUrl := job.job.dirResp.XPelNsHdr.CollectionsUrl
		if destCollUrl == nil {
			log.Warnln("Destination collections URL not found; sync skip checks will be disabled for TPC copy")
		} else {
			log.Debugln("Trying destination collections URL for TPC sync skip: ", destCollUrl.String())
			destClient = createWebDavClient(destCollUrl, job.job.token, job.job.project)
		}
	}

	return te.walkDirCopyHelper(job, transfers, files, srcUrl.Path, srcClient, destClient)
}

// walkDirCopyHelper recursively walks the remote source directory and emits individual
// TPC copy transfer files. For each file found, it creates a copy job where the source
// server URLs point to the individual file and the destination (via dirResp.ObjectServers)
// is also adjusted to the corresponding destination path.
// destWebDavClient may be nil if sync skip is disabled; used to stat destination files.
func (te *TransferEngine) walkDirCopyHelper(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, remotePath string, webdavClient *gowebdav.Client, destWebDavClient *gowebdav.Client) error {
	// Check for cancellation
	if err := job.job.ctx.Err(); err != nil {
		return err
	}

	var infos []fs.FileInfo
	err := retryWebDavOperation("ReadDir", func() error {
		var err error
		infos, err = webdavClient.ReadDir(remotePath)
		return err
	})
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return error_codes.NewSpecification_FileNotFoundError(errors.New("404: source object not found"))
		} else if gowebdav.IsErrCode(err, http.StatusInternalServerError) {
			// XRootD workaround: a directory listing on a file path returns 500.
			// Stat the path; if it is a file, emit a single copy job.
			var info fs.FileInfo
			err := retryWebDavOperation("Stat", func() error {
				var err error
				info, err = webdavClient.Stat(remotePath)
				return err
			})
			if err != nil {
				return errors.Wrap(err, "failed to stat source path for copy")
			}
			if !info.IsDir() {
				return te.emitCopyJob(job, transfers, files, remotePath, info, destWebDavClient)
			}
			return nil
		}
		return errors.Wrap(err, "failed to read source collection for copy")
	}

	for _, info := range infos {
		newPath := path.Join(remotePath, info.Name())
		if info.IsDir() {
			err := te.walkDirCopyHelper(job, transfers, files, newPath, webdavClient, destWebDavClient)
			if err != nil {
				return err
			}
		} else {
			if err := te.emitCopyJob(job, transfers, files, newPath, info, destWebDavClient); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitCopyJob creates and emits a single TPC copy job for a file at the given source path.
// It adjusts the source server URLs (in transfers/attempts) and the destination remote URL
// to point at the individual file, computing the relative path within the source directory.
// sourceInfo is the fs.FileInfo for the source file, used for sync skip checks.
// destCollClient may be nil if sync skip is disabled; used to stat the destination file.
func (te *TransferEngine) emitCopyJob(job *clientTransferJob, transfers []transferAttemptDetails, files chan *clientTransferFile, srcFilePath string, sourceInfo fs.FileInfo, destCollClient *gowebdav.Client) error {
	// Compute relative path of this file within the source directory
	relPath := strings.TrimPrefix(srcFilePath, job.job.srcURL.Path)
	relPath = strings.TrimPrefix(relPath, "/")

	// Build the destination path: the base destination + the relative path from source
	destPath := path.Join(job.job.remoteURL.Path, relPath)

	// Check if this copy should be skipped based on sync policy
	if destCollClient != nil && skipCopy(job.job.syncLevel, sourceInfo, destPath, destCollClient) {
		log.Infoln("Skipping copy of object", srcFilePath, "as it already exists at destination", destPath)
		return nil
	}

	// Build source server attempts for this individual file.
	// Each attempt in `transfers` has the source server URL with the source directory path;
	// we need to replace that path with the individual file path.
	srcAttempts := make([]transferAttemptDetails, len(transfers))
	for i, attempt := range transfers {
		srcAttempts[i] = attempt
		// The attempt URL path is currently set to the source directory path.
		// Compute the base by stripping the original source path, then append the file path.
		attemptPath := attempt.Url.Path
		if attemptPath != "" && !strings.HasSuffix(attemptPath, "/") {
			attemptPath += "/"
		}
		srcBasePath := job.job.srcURL.Path
		if srcBasePath != "" && !strings.HasSuffix(srcBasePath, "/") {
			srcBasePath += "/"
		}
		transferBase := strings.TrimSuffix(attemptPath, srcBasePath)
		fileURL := &url.URL{
			Scheme:   attempt.Url.Scheme,
			Host:     attempt.Url.Host,
			Path:     path.Join(transferBase, srcFilePath),
			RawQuery: attempt.Url.RawQuery,
		}
		srcAttempts[i].Url = fileURL
		log.Debugln("Constructed source attempt URL for TPC copy:", fileURL.String(), "file:", srcFilePath)
	}

	job.job.activeXfer.Add(1)
	select {
	case <-job.job.ctx.Done():
		return job.job.ctx.Err()
	case files <- &clientTransferFile{
		uuid:  job.uuid,
		jobId: job.job.uuid,
		file: &transferFile{
			ctx:      job.job.ctx,
			callback: job.job.callback,
			job:      job.job,
			engine:   te,
			remoteURL: &url.URL{
				Scheme: job.job.remoteURL.Scheme,
				Host:   job.job.remoteURL.Host,
				Path:   destPath,
			},
			xferType: job.job.xferType,
			token:    job.job.token,
			srcToken: job.job.srcToken,
			attempts: srcAttempts,
		},
	}:
		job.job.totalXfer += 1
	}
	return nil
}
