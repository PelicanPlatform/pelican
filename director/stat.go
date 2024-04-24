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

package director

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	objectMetadata struct {
		URL           url.URL `json:"url"` // The object URL
		Checksum      string  `json:"checksum"`
		ContentLength int     `json:"content_length"`
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
		ReqHandler func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, timeout time.Duration) (*objectMetadata, error)                   // Handle the request to test if an object exists on a server
		Query      func(cancelContext context.Context, objectName string, sType config.ServerType, mininum, maximum int) ([]*objectMetadata, string, error) // Manage a `stat` request to origin servers given an objectName
	}
)

var (
	ParameterError       = errors.New("Invalid parameter, max_responses must be larger than min_responses")
	NoPrefixMatchError   = errors.New("No namespace prefixes match found")
	InsufficientResError = errors.New("Number of success responses is less than MinStatResponse required.")
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
	return fmt.Sprintf("Object Meatadata: File URL %q\nContent-length:%d\nChecksum: %s\n",
		meta.URL.String(),
		meta.ContentLength,
		meta.Checksum,
	)
}

// Initialize a new stat instance and set default method implementations
func NewObjectStat() *ObjectStat {
	stat := &ObjectStat{}
	stat.ReqHandler = stat.sendHeadReq
	stat.Query = stat.queryServersForObject
	return stat
}

// Implementation of sending a HEAD request to an origin for an object
func (stat *ObjectStat) sendHeadReq(ctx context.Context, objectName string, dataUrl url.URL, timeout time.Duration) (*objectMetadata, error) {
	tokenConf := token.NewWLCGToken()
	tokenConf.Lifetime = time.Minute
	tokenConf.AddAudiences(dataUrl.String())
	tokenConf.Subject = dataUrl.String()
	// Federation as the issuer
	tokenConf.Issuer = param.Server_ExternalWebUrl.GetString()
	tokenConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"))
	token, err := tokenConf.CreateToken()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create token")
	}

	client := http.Client{Transport: config.GetTransport(), Timeout: timeout}
	reqUrl := dataUrl.JoinPath(objectName)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// Request checksum
	req.Header.Set("Want-Digest", "crc32c")

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
		return nil, notFoundError{"File not found on the server " + dataUrl.String()}
	} else if res.StatusCode == 403 {
		return nil, errors.New(fmt.Sprintf("Query was forbidden for origin %s. Can only query public namespace.", dataUrl.String()))
	} else if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read error response body")
		}
		return nil, errors.New(fmt.Sprintf("Unknown origin response with status code %d and message: %s", res.StatusCode, string(resBody)))
	} else {
		cLenStr := res.Header.Get("Content-Length")
		checksumStr := res.Header.Get("Digest")
		clen, err := strconv.Atoi(cLenStr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error parsing content-length header from response. Header was: %s", cLenStr))
		}
		return &objectMetadata{ContentLength: clen, Checksum: checksumStr, URL: *dataUrl.JoinPath(objectName)}, nil
	}
}

// Implementation of querying origins/cache servers for their availability of an object.
// It blocks until max successful requests has been received, all potential origins/caches responded (or timeout), or cancelContext was closed.
// sType can be config.OriginType, config.CacheType, or both.
//
// Returns the object metadata with available urls, a message indicating the stat result, and error if any.
func (stat *ObjectStat) queryServersForObject(cancelContext context.Context, objectName string, sType config.ServerType, minimum, maximum int) ([]*objectMetadata, string, error) {
	ads := []server_structs.ServerAd{}
	_, originAds, cacheAds := getAdsForPath(objectName)
	if sType.IsEnabled(config.OriginType) {
		ads = append(ads, originAds...)
	}
	if sType.IsEnabled(config.CacheType) {
		ads = append(ads, cacheAds...)
	}
	minReq := param.Director_MinStatResponse.GetInt()
	maxReq := param.Director_MaxStatResponse.GetInt()
	if minimum > 0 {
		minReq = minimum
	}
	if maximum > 0 {
		maxReq = maximum
	}
	if maxReq < minReq {
		return nil, "", ParameterError
	}
	timeout := param.Director_StatTimeout.GetDuration()
	positiveReqChan := make(chan *objectMetadata)
	negativeReqChan := make(chan error)
	maxCancelCtx, maxCancel := context.WithCancel(context.Background())
	numTotalReq := 0
	successResult := make([]*objectMetadata, 0)

	if len(ads) < 1 {
		maxCancel()
		return nil, "", NoPrefixMatchError
	}

	originStatUtilsMutex.RLock()
	defer originStatUtilsMutex.RUnlock()

	for _, originAd := range ads {
		originUtil, ok := originStatUtils[originAd.URL]
		if !ok {
			numTotalReq += 1
			log.Warningf("Origin %q is missing data for stat call, skip querying...", originAd.Name)
			continue
		}
		// Have to use an anonymous func to wrap the egrp call to pass loop variable safely
		// to goroutine
		func(intOriginAd server_structs.ServerAd) {
			originUtil.Errgroup.Go(func() error {
				metadata, err := stat.ReqHandler(maxCancelCtx, objectName, intOriginAd.URL, timeout)

				if err != nil {
					switch e := err.(type) {
					case timeoutError:
						log.Warningf("Timeout error when issue stat to origin %s for object %s after %d: %s", intOriginAd.URL.String(), objectName, timeout, e.Message)
						negativeReqChan <- err
						return nil
					case notFoundError:
						log.Warningf("Object %s not found at origin %s: %s", objectName, intOriginAd.URL.String(), e.Message)
						fmt.Println("Not found error:", e.Message)
						negativeReqChan <- err
						return nil
					case cancelledError:
						// Don't send to negativeReqChan as cancellation won't count towards total requests
						return nil
					default:
						negativeReqChan <- err
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
		case <-negativeReqChan:
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
			if numTotalReq == len(ads) {
				maxCancel()
				if len(successResult) < minReq {
					return successResult, fmt.Sprintf("Number of success response: %d is less than MinStatResponse (%d) required.", len(successResult), minReq), InsufficientResError
				}
				return successResult, "", nil
			}
		}
	}
}
