/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	objectMetadata struct {
		ServerAd      ServerAd
		Checksum      string
		ContentLength int64
	}

	timeoutError struct {
		Message string
	}

	notFoundError struct {
		Message string
	}

	cancelledError struct {
		Message string
	}
)

func (e timeoutError) Error() string {
	return e.Message
}

func (e notFoundError) Error() string {
	return e.Message
}

func (e cancelledError) Error() string {
	return e.Message
}

func (meta objectMetadata) String() string {
	return fmt.Sprintf("Object Meatadata: From server %q at %q.\nContent-length:%d\nChecksum: %s\n",
		meta.ServerAd.Name,
		meta.ServerAd.URL.String(),
		meta.ContentLength,
		meta.Checksum,
	)
}

func sendHeadReqToOrigin(objectName string, originAd ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
	xrootdUrl := originAd.URL
	client := http.Client{Transport: config.GetTransport(), Timeout: timeout}
	reqUrl := xrootdUrl.JoinPath(objectName)
	req, err := http.NewRequestWithContext(maxCancelCtx, "HEAD", reqUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating request")
	}
	res, err := client.Do(req)
	if err != nil {
		urlErr, ok := err.(*url.Error)
		if !ok {
			return nil, errors.Wrap(err, "Unknown request error")
		} else {
			if urlErr.Err == context.Canceled {
				return nil, cancelledError{"Request was cancelled by context"}
			}
			if urlErr.Timeout() {
				return nil, cancelledError{"Request timeout"}
			}
		}
	}
	if res.StatusCode != 200 {
		// TODO: handle 404 (if that's what xrootd returns)
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read error response body")
		}
		return nil, errors.New(fmt.Sprintf("Unknown origin response with status code %d and message: %s", res.StatusCode, string(resBody)))
	} else {
		return &objectMetadata{}, nil
	}
}

// TODOs:
// 1. Config values
//
// 2. Check objectName, ?how to ensure it's an object not a directory?
// find prefix matched namespaces and their serverAds, Origins only
//
// 3. For a list of serverAds,
// [] helper function to create token and setup request itself
//
// 4. Add new command line argument

func QueryOriginsForObject(objectName string, cancelContext context.Context) ([]*objectMetadata, error) {
	_, originAds, _ := GetAdsForPath(objectName)
	minReq := param.Director_MinStatResponse.GetInt()
	maxReq := param.Director_MaxStatResponse.GetInt()
	timeout := param.Director_StatTimeout.GetDuration()
	positiveReqChan := make(chan *objectMetadata)
	negitiveReqChan := make(chan error)
	maxCancelCtx, maxCancel := context.WithCancel(context.Background())
	numTotalReq := 0
	successResult := make([]*objectMetadata, 0)

	for _, originAd := range originAds {
		originUtil, ok := originStatUtils[originAd]
		if !ok {
			log.Warningf("Origin %q is missing data for stat call, skip querying...", originAd.Name)
			continue
		}
		// Have to use a anonymous func to wrap the egrp call to pass loop variable safely
		// to goroutine
		func(intOriginAd ServerAd) {
			originUtil.Errgroup.Go(func() error {
				metadata, err := sendHeadReqToOrigin(objectName, intOriginAd, timeout, maxCancelCtx)

				if err != nil {
					switch e := err.(type) {
					case timeoutError:
						fmt.Println("Timeout error:", e)
						negitiveReqChan <- err
						return nil
					case notFoundError:
						fmt.Println("Not found error:", e)
						negitiveReqChan <- err
						return nil
					case cancelledError:
						// Don't send to negitiveReqChan as cancellation won't count towards total requests
						return nil
					default:
						negitiveReqChan <- err
						return err
					}
				} else {
					positiveReqChan <- metadata
				}
				return nil
			})
		}(originAd)
	}

	for {
		select {
		case <-negitiveReqChan:
			numTotalReq += 1
		case metaRes := <-positiveReqChan:
			numTotalReq += 1
			successResult = append(successResult, metaRes)
			if len(successResult) > maxReq {
				maxCancel()
				// Reach the max
				return successResult, nil
			}
		case <-cancelContext.Done():
			maxCancel()
			return successResult, nil
		default:
			// All requests finished
			if numTotalReq == len(originAds) {
				maxCancel()
				if len(successResult) < minReq {
					return successResult, errors.New(fmt.Sprintf("Number of success response: %d is less than MinStatResponse (%d) required.", len(successResult), minReq))
				}
				return successResult, nil
			}
		}
	}
}
