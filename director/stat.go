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
	"strconv"
	"time"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	objectMetadata struct {
		ServerAd      common.ServerAd `json:"server_ad"`
		Checksum      string          `json:"checksum"`
		ContentLength int             `json:"content_length"`
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

	// A struct to implement `object stat`, by querying against origins with namespaces match the prefix of an object name
	// and return origins that have the object
	ObjectStat struct {
		ReqHandler func(objectName string, originAd common.ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error)
		Query      func(objectName string, cancelContext context.Context, mininum, maximum int) ([]*objectMetadata, string, error)
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

// Initialize a new stat instance and set default method implementations
func NewObjectStat() *ObjectStat {
	stat := &ObjectStat{}
	stat.ReqHandler = stat.sendHeadReqToOrigin
	stat.Query = stat.queryOriginsForObject
	return stat
}

// Implementation of sending a HEAD request to an origin for an object
func (stat *ObjectStat) sendHeadReqToOrigin(objectName string, originAd common.ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
	tokenConf := utils.TokenConfig{
		Lifetime:     time.Minute,
		TokenProfile: utils.WLCG,
		Audience:     []string{originAd.URL.String()},
		Subject:      originAd.URL.String(),
		// Federation as the issuer
		Issuer: param.Server_ExternalWebUrl.GetString(),
	}
	tokenConf.AddRawScope("storage.read:/")
	token, err := tokenConf.CreateToken()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create token")
	}

	client := http.Client{Transport: config.GetTransport(), Timeout: timeout}
	reqUrl := originAd.URL.JoinPath(objectName)
	req, err := http.NewRequestWithContext(maxCancelCtx, "HEAD", reqUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating request")
	}
	req.Header.Set("Authorization", "Bearer "+token)

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
				return nil, timeoutError{fmt.Sprintf("Request timeout after %dms", timeout.Milliseconds())}
			}
		}
	}
	if res.StatusCode == 404 {
		return nil, notFoundError{"File not found on the server " + originAd.URL.String()}
	} else if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read error response body")
		}
		return nil, errors.New(fmt.Sprintf("Unknown origin response with status code %d and message: %s", res.StatusCode, string(resBody)))
	} else {
		cLenStr := res.Header.Get("Content-Length")
		clen, err := strconv.Atoi(cLenStr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error parsing content-length header from response. Header was: %s", cLenStr))
		}
		return &objectMetadata{ContentLength: clen, ServerAd: originAd}, nil
	}
}

// Implementation of querying origins for their availability of an object.
// It blocks until max successful requests has been received, all potential origins responded (or timeout), or cancelContext was closed
func (stat *ObjectStat) queryOriginsForObject(objectName string, cancelContext context.Context, minimum, maximum int) ([]*objectMetadata, string, error) {
	_, originAds, _ := GetAdsForPath(objectName)
	minReq := param.Director_MinStatResponse.GetInt()
	maxReq := param.Director_MaxStatResponse.GetInt()
	if minimum > 0 {
		minReq = minimum
	}
	if maximum > 0 {
		maxReq = maximum
	}
	if maxReq < minReq {
		return nil, "", errors.New(fmt.Sprintf("Invalid parameter, maximum (%d) must be larger than minimum (%d)", maxReq, minReq))
	}
	timeout := param.Director_StatTimeout.GetDuration()
	positiveReqChan := make(chan *objectMetadata)
	negitiveReqChan := make(chan error)
	maxCancelCtx, maxCancel := context.WithCancel(context.Background())
	numTotalReq := 0
	successResult := make([]*objectMetadata, 0)

	if len(originAds) < 1 {
		maxCancel()
		return nil, "", errors.New("No namespace prefixes match found.")
	}

	for _, originAd := range originAds {
		originUtil, ok := originStatUtils[originAd]
		if !ok {
			numTotalReq += 1
			log.Warningf("Origin %q is missing data for stat call, skip querying...", originAd.Name)
			continue
		}
		// Have to use an anonymous func to wrap the egrp call to pass loop variable safely
		// to goroutine
		func(intOriginAd common.ServerAd) {
			originUtil.Errgroup.Go(func() error {
				metadata, err := stat.ReqHandler(objectName, intOriginAd, timeout, maxCancelCtx)

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
			if len(successResult) >= maxReq {
				maxCancel()
				// Reach the max
				return successResult, "Maximum responses reached for stat. Return result and cancel ongoing requests.", nil
			}
		case <-cancelContext.Done():
			maxCancel()
			return successResult, fmt.Sprintf("Director stat for object %q is cancelled", objectName), nil
		default:
			// All requests finished
			if numTotalReq == len(originAds) {
				maxCancel()
				if len(successResult) < minReq {
					return successResult, "", errors.New(fmt.Sprintf("Number of success response: %d is less than MinStatResponse (%d) required.", len(successResult), minReq))
				}
				return successResult, "", nil
			}
		}
	}
}
