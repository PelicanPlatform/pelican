/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package broker

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

type (
	reversalRequest struct {
		CallbackUrl string `json:"callback_url,omitempty"`
		PrivateKey  string `json:"private_key,omitempty"`
		RequestId   string `json:"request_id,omitempty"`
		Prefix      string `json:"prefix,omitempty"`
		OriginName  string `json:"origin,omitempty"`
	}

	requestInfo struct {
		channel chan reversalRequest
		prefix  string
	}

	requestKey struct {
		origin string
		prefix string
	}
)

var (
	errRetrieveTimeout error                      = errors.New("retrieve request timed out")
	errRequestTimeout  error                      = errors.New("reverse request timed out")
	requestsLock       sync.Mutex                 = sync.Mutex{}
	requests           map[requestKey]requestInfo = make(map[requestKey]requestInfo)
)

func getOriginQueue(prefix, origin string) chan reversalRequest {
	requestsLock.Lock()
	defer requestsLock.Unlock()
	if req, ok := requests[requestKey{origin: origin, prefix: prefix}]; ok {
		return req.channel
	} else {
		newChan := make(chan reversalRequest)
		requests[requestKey{origin: origin, prefix: prefix}] = requestInfo{channel: newChan, prefix: prefix}
		return newChan
	}
}

// Send a request to a given origin's queue.
// Return a requestTimeout error if no origin retrieved the request before the context timed out.
func handleRequest(ctx context.Context, origin string, req reversalRequest, timeout time.Duration) (err error) {
	queue := getOriginQueue(req.Prefix, origin)
	maxTime := timeout - 500*time.Millisecond - time.Duration(rand.Intn(500))*time.Millisecond
	if maxTime <= 0 {
		maxTime = time.Millisecond
	}
	tick := time.NewTicker(maxTime)
	defer tick.Stop()

	select {
	case queue <- req:
		break
	case <-tick.C:
		err = errRequestTimeout
		break
	case <-ctx.Done():
		err = errRequestTimeout
		break
	}
	return
}

// Handle the origin's request to retrieve any pending reversals.
func handleRetrieve(appCtx context.Context, ginCtx context.Context, prefix, origin string, timeout time.Duration) (req reversalRequest, err error) {
	// Return randomly short of the timeout.
	maxTime := timeout - 500*time.Millisecond - time.Duration(rand.Intn(500))*time.Millisecond
	if maxTime <= 0 {
		maxTime = time.Millisecond
	}
	tick := time.NewTicker(maxTime)
	defer tick.Stop()
	select {
	case req = <-getOriginQueue(prefix, origin):
		break
	case <-tick.C:
		err = errRetrieveTimeout
	case <-ginCtx.Done():
		err = errRetrieveTimeout
	case <-appCtx.Done():
		err = errRetrieveTimeout
	}
	return
}
