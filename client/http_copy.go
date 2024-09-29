/***************************************************************
 *
 * Copyright (C) 2024, Morgridge Institute for Research
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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	tpcStatus struct {
		done    bool
		xferred uint64
		err     error
	}
)

// Invoke a third-party-copy between two HTTPS endpoints
//
// Uses the WebDAV COPY verb to actually move the data.  Only implements the "push" mode
// where the destination side is the active side performing the transfer
func copyHTTP(xfer *transferFile) (transferResults TransferResults, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in HTTP copy code:", r)
			err = errors.Errorf("Unrecoverable error (panic) occurred in copyHTTP: %v", r)
		}
	}()
	if len(xfer.attempts) == 0 {
		log.Errorln("No source URLs specified; cannot copy")
		err = errors.New("No source URLs specified")
		return
	}
	resolvedDestUrl := *xfer.job.dirResp.ObjectServers[0]
	resolvedDestUrl.RawQuery = xfer.job.remoteURL.RawQuery

	log.Debugln("Copying object from", resolvedDestUrl.String(), "to", xfer.attempts[0].Url.String())
	transferResults = newTransferResults(xfer.job)

	lastUpdate := time.Now()
	if xfer.job.callback != nil {
		xfer.job.callback(xfer.remoteURL.String(), 0, 0, false)
	}
	downloaded := int64(-1)
	totalSize := int64(-1)
	transferStartTime := time.Now()
	transferResults.TransferStartTime = transferStartTime
	attempt := TransferResult{
		CacheAge: -1,
		Number:   0,
		Endpoint: xfer.remoteURL.String(),
	}

	defer func() {
		endTime := time.Now()
		attempt.TransferEndTime = endTime
		attempt.TransferTime = endTime.Sub(transferStartTime)
		attempt.TransferFileBytes = totalSize
		transferResults.Attempts = []TransferResult{attempt}

		if xfer.job.callback != nil {
			finalSize := int64(0)
			if totalSize >= 0 {
				finalSize = totalSize
			}
			xfer.job.callback(xfer.remoteURL.String(), downloaded, finalSize, true)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, xfer.attempts[0].Url.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "Failed to get size of the source object %s", xfer.attempts[0].Url.String())
		return
	}

	srcTkn, err := xfer.srcToken.get()
	if err == nil && srcTkn != "" {
		req.Header.Set("Authorization", "Bearer "+srcTkn)
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	log.Debugln("Starting the HEAD request to the HTTP Third Party Copy source...")
	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "failed to execute the HEAD request to third-party-copy source %s: %s", resolvedDestUrl.String(), err.Error())
		log.Errorln(err)
		return
	}
	resp.Body.Close() // HEAD requests shouldn't have anything in the body; just ignore it.
	totalSize = resp.ContentLength
	if resp.ContentLength < 0 {
		log.Warningln("Third-party-copy source", xfer.srcURL.String(), "is of unknown size; download statistics may be incorrect")
	}
	attempt.ServerVersion = resp.Header.Get("Server")

	req, err = http.NewRequestWithContext(ctx, "COPY", resolvedDestUrl.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "Unable to create request for third-party-copy to %s", xfer.remoteURL.String())
		return
	}

	if tkn, err := xfer.token.get(); err == nil && tkn != "" {
		req.Header.Set("Authorization", "Bearer "+tkn)
	}
	if srcTkn != "" {
		req.Header.Set("TransferHeaderAuthorization", "Bearer "+srcTkn)
	}
	req.Header.Set("User-Agent", getUserAgent(xfer.project))
	req.Header.Set("Source", xfer.attempts[0].Url.String())

	log.Debugln("Starting the HTTP Third Party Copy transfer...")
	resp, err = client.Do(req)

	if err != nil {
		log.Errorf("Failed to execute the third-party-copy to %s: %s", xfer.remoteURL.String(), err.Error())
		err = errors.Wrapf(err, "Failed to execute the third-party-copy to %s", xfer.remoteURL.String())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var respBytes []byte
		respBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("TPC request was not successful (status code %d); when reading the error message, a further issue occurred: %s", resp.StatusCode, err.Error())
		} else {
			log.Errorf("TPC request was not successful (status code %d): %s", resp.StatusCode, string(respBytes))
			err = &HttpErrResp{resp.StatusCode, fmt.Sprintf("Request failed (HTTP status %d)",
				resp.StatusCode)}
		}
		return
	}

	serverMessages := make(chan tpcStatus)

	xfer.engine.egrp.Go(func() error { return monitorTPC(serverMessages, resp.Body) })

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
				resp.Body.Close()
				break
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
			log.Infof("Transfer %s->%s has downloaded %d bytes", xfer.srcURL.String(), xfer.remoteURL.String(), downloaded)
			xfer.job.callback(xfer.remoteURL.String(), downloaded, totalSize, false)
		case <-ctx.Done():
			err = ctx.Err()
			resp.Body.Close()
		}
	}

	return
}

// Helper function to read periodic updates from the HTTP TPC resp body,
// parse them, and write them to the channel.
//
// This is guaranteed to close the channel before exiting.
func monitorTPC(messages chan tpcStatus, body io.Reader) error {
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
			messages <- tpcStatus{
				xferred: sum,
			}
			xferred = sum
		} else { // All other messages have the format "key: value"
			info := strings.SplitN(text, ":", 2)
			if len(info) != 2 {
				log.Warningln("Invalid line in the TPC update: ", text)
				continue
			}
			switch info[0] {
			case "failure":
				err = errors.Errorf("TPC copy failed: %s", info[1])
				break Listener
			case "success":
				break Listener
			case "Stripe Index":
				idx, err := strconv.Atoi(info[1])
				if err == nil {
					curStripe = idx
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Index': %s (%s)", err.Error(), info[1])
				}
			case "Stripe Bytes Transferred":
				bytes, err := strconv.Atoi(info[1])
				if err == nil {
					curStripeBytes = uint64(bytes)
				} else {
					log.Warningf("Invalid integer in performance marker's 'Stripe Bytes Transferred': %s (%s)", err.Error(), info[1])
				}
			case "Total Stripe Count":
				break
			case "RemoteConnections":
				break
			default:
				log.Debugln("Received performance marker with unknown key:", info[0])
			}
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	messages <- tpcStatus{
		err:     err,
		done:    true,
		xferred: xferred,
	}
	return nil
}
