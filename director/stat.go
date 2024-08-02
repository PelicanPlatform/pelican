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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	queryConfig struct {
		originAds         []server_structs.ServerAd
		cacheAds          []server_structs.ServerAd
		token             string
		protected         bool
		originAdsProvided bool // Explicitly mark the originAds are provided, not based on the length of the array
		cacheAdsProvided  bool // Explicitly mark the cacheAds are provided, not based on the length of the array
	}

	queryOption    func(*queryConfig)
	objectMetadata struct {
		URL           url.URL `json:"url"` // The URL to the object
		Checksum      string  `json:"checksum"`
		ContentLength int     `json:"contentLength"`
	}

	queryStatus    string
	queryErrorType string

	queryResult struct {
		Status    queryStatus       `json:"status"`
		ErrorType queryErrorType    `json:"errorType,omitempty"` // Available when status==failure
		Msg       string            `json:"msg,omitempty"`       // General description of the error/success
		Objects   []*objectMetadata `json:"objects,omitempty"`   // Available when status==success
		// Available when status==failure. The values are AuthURLs from servers with 403 responses
		// The AuthURLs are for obtaining a token and retry the query.
		DeniedServers []string `json:"deniedServers,omitempty"`
	}

	// A struct to implement `object stat`, by querying against origins/caches with namespaces match the prefix of an object name
	// and return origins that have the object.
	//
	// **Note**: Currently it only returns successful result when the file is under a public namespace.
	ObjectStat struct {
		// Handle the request to test if an object exists on a server
		//
		// dataUrl: the base url to access data on the server. This is usually the url pointed at the XRootD instance on the server
		//
		// digest: requst digest for object checkusm. XRootD responds with 403 if digest feature is turned off on the server
		//
		// token: a bearer token to be used when issuing the request
		ReqHandler func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error)
		// Manage a `stat` request to origin servers given an objectName
		Query func(cancelContext context.Context, objectName string, sType config.ServerType, mininum, maximum int, options ...queryOption) queryResult
	}
)

// Errors returned by sendHeadRequest
type (
	headReqTimeoutErr struct {
		Message string
	}

	headReqNotFoundErr struct {
		Message string
	}

	headReqForbiddenErr struct {
		Message   string
		IssuerUrl string
	}

	headReqCancelledErr struct {
		Message string
	}
)

const (
	queryFailed     queryStatus = "error"
	querySuccessful queryStatus = "success"
)

const (
	queryParameterErr       queryErrorType = "ParameterError"
	queryNoPrefixMatchErr   queryErrorType = "NoPrefixMatchError"
	queryInsufficientResErr queryErrorType = "InsufficientResError"
	queryCancelledErr       queryErrorType = "CancelledError"
)

func (e *headReqTimeoutErr) Error() string {
	return e.Message
}

func (e *headReqNotFoundErr) Error() string {
	return e.Message
}

func (e *headReqForbiddenErr) Error() string {
	return e.Message
}

func (e *headReqCancelledErr) Error() string {
	return e.Message
}

func (meta objectMetadata) String() string {
	return fmt.Sprintf("Object URL: %q; Content-length:%d; Checksum: %s",
		meta.URL.String(),
		meta.ContentLength,
		meta.Checksum,
	)
}

func (m *objectMetadata) MarshalJSON() ([]byte, error) {
	type Alias objectMetadata
	return json.Marshal(&struct {
		URL string `json:"url"`
		*Alias
	}{
		URL:   m.URL.String(),
		Alias: (*Alias)(m),
	})
}

func (q queryResult) String() string {
	if q.Status == querySuccessful {
		res := fmt.Sprintf("Query is successful: %s Servers with the object: %d. Servers return denial: %d. Top-3 servers: ", q.Msg, len(q.Objects), len(q.DeniedServers))
		for idx, obj := range q.Objects {
			res += obj.String() + " "
			if idx >= 2 {
				break
			}
		}
		return res
	} else {
		if len(q.DeniedServers) == 0 {
			return fmt.Sprintf("Query failed with error %s: %s", q.ErrorType, q.Msg)
		} else {
			return fmt.Sprintf("Query failed with error %s: %s %d servers require authentication to access the object", q.ErrorType, q.Msg, len(q.DeniedServers))
		}
	}
}

// Initialize a new stat instance and set default method implementations
func NewObjectStat() *ObjectStat {
	stat := &ObjectStat{}
	stat.ReqHandler = stat.sendHeadReq
	stat.Query = stat.queryServersForObject
	return stat
}

// Implementation of sending a HEAD request to an origin for an object
func (stat *ObjectStat) sendHeadReq(ctx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error) {
	client := http.Client{Transport: config.GetTransport(), Timeout: timeout}
	reqUrl := dataUrl.JoinPath(objectName)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if digest {
		// Request checksum
		req.Header.Set("Want-Digest", "crc32c")
	}

	res, err := client.Do(req)
	if err != nil {
		urlErr, ok := err.(*url.Error)
		if !ok {
			return nil, errors.Wrap(err, "unknown request error")
		} else {
			if urlErr.Err == context.Canceled {
				return nil, &headReqCancelledErr{"request was cancelled by context"}
			}
			if urlErr.Timeout() {
				return nil, &headReqTimeoutErr{fmt.Sprintf("request timeout after %dms", timeout.Milliseconds())}
			}
			return nil, errors.Wrap(err, "unknown request error")
		}
	}
	if res.StatusCode == 404 {
		return nil, &headReqNotFoundErr{"file not found on the server " + dataUrl.String()}
	} else if res.StatusCode == 403 {
		return nil, &headReqForbiddenErr{fmt.Sprintf("authorization failed for the server at %s. Token is required", dataUrl.String()), ""}
	} else if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read error response body")
		}
		return nil, errors.New(fmt.Sprintf("unknown origin response with status code %d and message: %s", res.StatusCode, string(resBody)))
	} else {
		cLenStr := res.Header.Get("Content-Length")
		checksumStr := res.Header.Get("Digest")
		clen, err := strconv.Atoi(cLenStr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("error parsing content-length header from response. Header was: %s", cLenStr))
		}
		return &objectMetadata{ContentLength: clen, Checksum: checksumStr, URL: *dataUrl.JoinPath(objectName)}, nil
	}
}

// For internal use only
func withOriginAds(ads []server_structs.ServerAd) queryOption {
	return func(c *queryConfig) {
		c.originAds = ads
		c.originAdsProvided = true
	}
}

// For internal use only
func withCacheAds(ads []server_structs.ServerAd) queryOption {
	return func(c *queryConfig) {
		c.cacheAds = ads
		c.cacheAdsProvided = true
	}
}

// For internal use only. Use to specify if the object is protected based on
// namespace capability
func withAuth(auth bool) queryOption {
	return func(c *queryConfig) {
		c.protected = auth
	}
}

// Issue the stat call with a token
func WithToken(tk string) queryOption {
	return func(c *queryConfig) {
		c.token = tk
	}
}

// Implementation of querying origins/cache servers for their availability of an object.
// It blocks until max successful requests has been received, all potential origins/caches responded (or timeout), or cancelContext was closed.
//
// sType can be config.OriginType, config.CacheType, or both.
//
// Returns the object metadata with available urls, a message indicating the stat result, and error if any.
func (stat *ObjectStat) queryServersForObject(ctx context.Context, objectName string, sType config.ServerType, minimum, maximum int, options ...queryOption) (qResult queryResult) {
	cfg := queryConfig{}
	for _, option := range options {
		option(&cfg)
	}

	ads := []server_structs.ServerAd{}

	// Only fetch origin/cacheAds if it's not provided AND the sType has the corresponding server type
	if sType.IsEnabled(config.OriginType) {
		if !cfg.originAdsProvided {
			_, originAds, _ := getAdsForPath(objectName)
			ads = append(ads, originAds...)
		} else {
			ads = append(ads, cfg.originAds...)
		}
	}
	if sType.IsEnabled(config.CacheType) {
		if !cfg.cacheAdsProvided {
			_, _, cacheAds := getAdsForPath(objectName)
			ads = append(ads, cacheAds...)
		} else {
			ads = append(ads, cfg.cacheAds...)
		}
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
		qResult.Status = queryFailed
		qResult.ErrorType = queryParameterErr
		qResult.Msg = "Invalid parameter, max_responses must be larger than min_responses"
		return
	}
	timeout := param.Director_StatTimeout.GetDuration()
	positiveReqChan := make(chan *objectMetadata)
	negativeReqChan := make(chan error)
	deniedReqChan := make(chan *headReqForbiddenErr) // Requests with 403 response
	// Cancel the rest of the requests when requests received >= max required
	maxCancelCtx, maxCancel := context.WithCancel(ctx)
	numTotalReq := 0
	successResult := make([]*objectMetadata, 0)
	deniedResult := make([]*headReqForbiddenErr, 0)

	if len(ads) < 1 {
		maxCancel()
		qResult.Status = queryFailed
		qResult.ErrorType = queryNoPrefixMatchErr
		qResult.Msg = fmt.Sprintf("No namespace prefixes match found for the object %s", objectName)
		return
	}

	// Use RLock to allolw multiple queries
	statUtilsMutex.RLock()
	defer statUtilsMutex.RUnlock()

	for _, adExt := range ads {
		statUtil, ok := statUtils[adExt.URL.String()]
		if !ok {
			numTotalReq += 1
			log.Debugf("Server %q is missing data for stat call, skip querying...", adExt.Name)
			continue
		}
		if statUtil.Context.Err() != nil {
			numTotalReq += 1
			log.Debugf("Server %q is evicted from the cache, context has been cancelled, skip querying...", adExt.Name)
			continue
		}
		// Use an anonymous func to pass variable safely to the goroutine
		func(serverAd server_structs.ServerAd) {
			statUtil.Errgroup.Go(func() error {
				baseUrl := serverAd.URL

				// For the topology server, if the server does not support public read,
				// or the token is provided, or the object is protected, then it's safe to assume this request goes to authenticated endpoint
				// For Pelican server, we don't populate authURL and only use server URL as the base URL
				if serverAd.FromTopology && (!serverAd.Caps.PublicReads || cfg.protected || cfg.token != "") && serverAd.AuthURL.String() != "" {
					baseUrl = serverAd.AuthURL
				}

				activeLabels := prometheus.Labels{
					"server_name": serverAd.Name,
					"server_url":  baseUrl.String(),
					"server_type": string(serverAd.Type),
				}
				metrics.PelicanDirectorStatActive.With(activeLabels).Inc()
				defer metrics.PelicanDirectorStatActive.With(activeLabels).Dec()

				metadata, err := stat.ReqHandler(maxCancelCtx, objectName, baseUrl, true, cfg.token, timeout)

				cancelErr := &headReqCancelledErr{}
				if err != nil && !errors.As(err, &cancelErr) { // Skip additional requests if the previous one is cancelled
					// If the request returns 403 or 500, it could be because we request a digest and xrootd
					// does not have this turned on, or had trouble calculating the checksum
					// Retry without digest
					metadata, err = stat.ReqHandler(maxCancelCtx, objectName, baseUrl, false, cfg.token, timeout)
				}

				totalLabels := prometheus.Labels{
					"server_name": serverAd.Name,
					"server_url":  baseUrl.String(),
					"server_type": string(serverAd.Type),
					"result":      "",
				}
				if err != nil {
					switch e := err.(type) {
					case *headReqTimeoutErr:
						log.Debugf("Timeout querying %s server %s for object %s after %s: %s", serverAd.Type, baseUrl.String(), objectName, timeout.String(), e.Message)
						negativeReqChan <- err
						totalLabels["result"] = string(metrics.StatTimeout)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					case *headReqNotFoundErr:
						log.Debugf("Object %s not found at %s server %s: %s", objectName, serverAd.Type, baseUrl.String(), e.Message)
						negativeReqChan <- err
						totalLabels["result"] = string(metrics.StatNotFound)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					case *headReqForbiddenErr:
						fErr := err.(*headReqForbiddenErr)
						fErr.IssuerUrl = serverAd.AuthURL.String()
						log.Debugf("Access denied for object %s at %s server %s: %s", objectName, serverAd.Type, baseUrl.String(), e.Message)
						deniedReqChan <- fErr
						totalLabels["result"] = string(metrics.StatForbidden)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					case *headReqCancelledErr:
						// Don't send to negativeReqChan as cancellation won't count towards total requests
						totalLabels["result"] = string(metrics.StatCancelled)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					default:
						negativeReqChan <- err
						totalLabels["result"] = string(metrics.StatUnkownErr)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					}
				} else {
					totalLabels["result"] = string(metrics.StatSucceeded)
					metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
					positiveReqChan <- metadata
				}
				return nil
			})
		}(adExt)
	}

	for {
		select {
		case deErr := <-deniedReqChan:
			numTotalReq += 1
			deniedResult = append(deniedResult, deErr)
		case <-negativeReqChan:
			numTotalReq += 1
		case metaRes := <-positiveReqChan:
			numTotalReq += 1
			successResult = append(successResult, metaRes)
			if len(successResult) >= maxReq {
				maxCancel()
				// Reach the max
				qResult.Status = querySuccessful
				qResult.Objects = successResult
				qResult.Msg = "Maximum responses reached for stat. Return result and cancel ongoing requests."
				return
			}
		case <-ctx.Done():
			maxCancel()
			qResult.Status = queryFailed
			qResult.ErrorType = queryCancelledErr
			qResult.Msg = fmt.Sprintf("Director stat for object %q is cancelled", objectName)
			return
		default:
			// All requests finished
			if numTotalReq == len(ads) {
				maxCancel()
				if len(successResult) < minReq {
					qResult.Status = queryFailed
					qResult.ErrorType = queryInsufficientResErr
					qResult.Msg = fmt.Sprintf("Number of success response: %d is less than MinStatResponse (%d) required.", len(successResult), minReq)
					serverIssuers := []string{}
					for _, dErr := range deniedResult {
						serverIssuers = append(serverIssuers, dErr.IssuerUrl)
					}
					qResult.DeniedServers = serverIssuers
					return
				}
				qResult.Status = querySuccessful
				qResult.Msg = "Stat finished with required number of responses."
				qResult.Objects = successResult
				return
			}
		}
	}
}
