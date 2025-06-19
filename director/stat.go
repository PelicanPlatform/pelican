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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
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
		// Set when status==failure.  The values are AuthURLs from servers with 404 responses
		NotFoundServers []string `json:"notFoundServers,omitempty"`
		// Set when status==failure.  The values are AuthURLs that returned an error that is neither 403 nor 404.
		OtherErrorServers []string `json:"errorServers,omitempty"`
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
		// digest: request digest for object checksum. XRootD responds with 403 if digest feature is turned off on the server
		//
		// token: a bearer token to be used when issuing the request
		ReqHandler func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error)
		// Manage a `stat` request to origin servers given an objectName
		Query func(cancelContext context.Context, objectName string, sType server_structs.ServerType, minimum, maximum int, options ...queryOption) queryResult
	}
)

// Errors returned by sendHeadRequest
type (
	headReqTimeoutErr struct {
		Message string
	}

	headReqNotFoundErr struct {
		Message   string
		ServerUrl string
	}

	headReqForbiddenErr struct {
		Message   string
		IssuerUrl string
	}

	headReqOtherErr struct {
		Message   string
		ServerUrl string
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
	queryNoSourcesErr       queryErrorType = "NoSources"
	queryCancelledErr       queryErrorType = "CancelledError"
)

func (e *headReqTimeoutErr) Error() string {
	return e.Message
}

func (e *headReqNotFoundErr) Error() string {
	return e.Message
}

func (*headReqNotFoundErr) Is(target error) bool {
	_, ok := target.(*headReqNotFoundErr)
	return ok
}

func (e *headReqForbiddenErr) Error() string {
	return e.Message
}

func (e *headReqOtherErr) Error() string {
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
	defer res.Body.Close()
	if res.StatusCode == 404 {
		if _, err := io.ReadAll(res.Body); err != nil {
			log.Debugln("Failed to read 404 response body:", err)
		}
		return nil, &headReqNotFoundErr{"file not found on the server " + dataUrl.String(), dataUrl.String()}
	} else if res.StatusCode == 403 {
		if _, err := io.ReadAll(res.Body); err != nil {
			log.Debugln("Failed to read 403 response body:", err)
		}
		return nil, &headReqForbiddenErr{fmt.Sprintf("authorization failed for the server at %s. Token is required", dataUrl.String()), ""}
	} else if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read error response body")
		}
		return nil, &headReqOtherErr{fmt.Sprintf("unknown origin response with status code %d and message: %s", res.StatusCode, string(resBody)), dataUrl.String()}
	} else {
		cLenStr := res.Header.Get("Content-Length")
		checksumStr := res.Header.Get("Digest")
		cLen, err := strconv.Atoi(cLenStr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("error parsing content-length header from response. Header was: %s", cLenStr))
		}
		return &objectMetadata{ContentLength: cLen, Checksum: checksumStr, URL: *dataUrl.JoinPath(objectName)}, nil
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

func getStatUtils(ads []server_structs.ServerAd) map[string]*serverStatUtil {
	statUtilsMutex.RLock()
	defer statUtilsMutex.RUnlock()

	result := make(map[string]*serverStatUtil, len(ads))
	for _, ad := range ads {
		url := ad.URL.String()
		statUtil, ok := statUtils[url]
		if ok {
			result[url] = statUtil
		}
	}
	return result
}

// Implementation of querying origins/cache servers for their availability of an object.
// It blocks until max successful requests has been received, all potential origins/caches responded (or timeout), or cancelContext was closed.
//
// sType can be server_structs.OriginType, server_structs.CacheType, or both.
//
// Returns the object metadata with available urls, a message indicating the stat result, and error if any.
func (stat *ObjectStat) queryServersForObject(ctx context.Context, objectName string, sType server_structs.ServerType, minimum, maximum int, options ...queryOption) (qResult queryResult) {
	cfg := queryConfig{}
	for _, option := range options {
		option(&cfg)
	}

	ads := []server_structs.ServerAd{}

	// Use the provided originAds and cacheAds if available
	if sType.IsEnabled(server_structs.OriginType) && cfg.originAdsProvided {
		ads = append(ads, cfg.originAds...)
	}
	if sType.IsEnabled(server_structs.CacheType) && cfg.cacheAdsProvided {
		ads = append(ads, cfg.cacheAds...)
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
	// Note there is a small buffer in each channel; in the case of a cache hit, we write
	// to the channel from within this goroutine.
	positiveReqChan := make(chan *objectMetadata, 5)
	negativeReqChan := make(chan error, 5)
	deniedReqChan := make(chan *headReqForbiddenErr, 5) // Requests with 403 response
	// Cancel the rest of the requests when requests received >= max required
	maxCancelCtx, maxCancel := context.WithCancel(ctx)
	numTotalReq := 0
	// Track the number of responses we got received indicating "file not found"
	numFileNotFound := 0
	successResult := make([]*objectMetadata, 0)
	deniedResult := make([]*headReqForbiddenErr, 0)
	notFoundResult := make([]*headReqNotFoundErr, 0)
	otherErrResult := make([]*headReqOtherErr, 0)

	if len(ads) < 1 {
		maxCancel()
		qResult.Status = queryFailed
		qResult.ErrorType = queryNoPrefixMatchErr
		qResult.Msg = fmt.Sprintf("No namespace prefixes match found for the object %s", objectName)
		return
	}

	utils := getStatUtils(ads)
	for _, adExt := range ads {
		statUtil, ok := utils[adExt.URL.String()]
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

			baseUrl := serverAd.URL
			// For the topology server, if the server does not support public read,
			// or the token is provided, or the object is protected, then it's safe to assume this request goes to authenticated endpoint
			// For Pelican server, we don't populate authURL and only use server URL as the base URL
			if serverAd.FromTopology && (!serverAd.Caps.PublicReads || cfg.protected || cfg.token != "") && serverAd.AuthURL.String() != "" {
				baseUrl = serverAd.AuthURL
			}

			totalLabels := prometheus.Labels{
				"server_name":   serverAd.Name,
				"server_url":    baseUrl.String(),
				"server_type":   string(serverAd.Type),
				"cached_result": "false",
				"result":        "",
			}

			queryFunc := func() (metadata *objectMetadata, err error) {

				activeLabels := prometheus.Labels{
					"server_name": serverAd.Name,
					"server_url":  baseUrl.String(),
					"server_type": string(serverAd.Type),
				}
				metrics.PelicanDirectorStatActive.With(activeLabels).Inc()
				defer metrics.PelicanDirectorStatActive.With(activeLabels).Dec()

				metadata, err = stat.ReqHandler(maxCancelCtx, objectName, baseUrl, true, cfg.token, timeout)

				var reqNotFound *headReqNotFoundErr
				cancelErr := &headReqCancelledErr{}
				if err != nil && !errors.As(err, &cancelErr) && !errors.As(err, &reqNotFound) {
					// If the request returns 403 or 500, it could be because we request a digest and xrootd
					// does not have this turned on, or had trouble calculating the checksum
					// Retry without digest
					metadata, err = stat.ReqHandler(maxCancelCtx, objectName, baseUrl, false, cfg.token, timeout)
				}

				// If get a 404, record it in the cache.
				if errors.As(err, &reqNotFound) {
					statUtil.ResultCache.Set(objectName, nil, ttlcache.DefaultTTL)
				} else if err == nil {
					statUtil.ResultCache.Set(objectName, metadata, ttlcache.DefaultTTL)
				}

				return
			}

			lookupFunc := func() error {

				metadata, err := queryFunc()
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
						totalLabels["result"] = string(metrics.StatUnknownErr)
						metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
						return nil
					}
				} else {
					totalLabels["result"] = string(metrics.StatSucceeded)
					metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
					positiveReqChan <- metadata
				}
				return nil
			}

			if item := statUtil.ResultCache.Get(objectName); item != nil {
				// If we get a cache hit -- but the cache item is going to expire in the next 10 seconds,
				// then we assume this is a "hot" object and we'll benefit from the preemptively refreshing
				// the ttlcache.  If we can, asynchronously query the service.
				if time.Until(item.ExpiresAt()) < 10*time.Second {
					statUtil.Errgroup.TryGo(func() error { _, _ = queryFunc(); return nil })
				}
				totalLabels["cached_result"] = "true"
				if metadata := item.Value(); metadata != nil {
					totalLabels["result"] = string(metrics.StatSucceeded)
					metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
					positiveReqChan <- metadata
				} else {
					log.Debugf("Object %s not found at %s server %s: (cached result)", objectName, serverAd.Type, baseUrl.String())
					negativeReqChan <- &headReqNotFoundErr{}
					totalLabels["result"] = string(metrics.StatNotFound)
					metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
				}
				metrics.PelicanDirectorStatTotal.With(totalLabels).Inc()
			} else {
				statUtil.Errgroup.TryGoUntil(ctx, lookupFunc)
			}
		}(adExt)
	}

	for {
		if numTotalReq == len(ads) {
			maxCancel()
			if len(successResult) == 0 && numFileNotFound > 0 && numFileNotFound >= minReq && numTotalReq == numFileNotFound {
				// In this case, we had a quorum of origins indicating this object didn't exist, no servers
				// showing an unknown status (HTTP 500, HTTP 403, etc).  We're fairly sure the object doesn't exist.
				qResult.Status = queryFailed
				qResult.ErrorType = queryNoSourcesErr
				qResult.Msg = "Object does not exist."
				return
			} else if len(successResult) < minReq {
				qResult.Status = queryFailed
				qResult.ErrorType = queryInsufficientResErr
				qResult.Msg = fmt.Sprintf("Number of success response: %d is less than MinStatResponse (%d) required.", len(successResult), minReq)
				serverIssuers := make([]string, len(deniedResult))
				for idx, dErr := range deniedResult {
					serverIssuers[idx] = dErr.IssuerUrl
				}
				qResult.DeniedServers = serverIssuers
				serverIssuers = make([]string, len(notFoundResult))
				for idx, nErr := range notFoundResult {
					serverIssuers[idx] = nErr.ServerUrl
				}
				qResult.NotFoundServers = serverIssuers
				serverIssuers = make([]string, len(otherErrResult))
				for idx, oErr := range otherErrResult {
					serverIssuers[idx] = oErr.ServerUrl
				}
				qResult.OtherErrorServers = serverIssuers
				return
			}
			qResult.Status = querySuccessful
			qResult.Msg = "Stat finished with required number of responses."
			qResult.Objects = successResult
			return
		}
		select {
		case deErr := <-deniedReqChan:
			numTotalReq += 1
			deniedResult = append(deniedResult, deErr)
		case negErr := <-negativeReqChan:
			if errors.Is(negErr, &headReqNotFoundErr{}) {
				numFileNotFound += 1
				notFoundResult = append(notFoundResult, negErr.(*headReqNotFoundErr))
			}
			var otherErr *headReqOtherErr
			if errors.As(negErr, &otherErr) {
				otherErrResult = append(otherErrResult, otherErr)
			}
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
		}
	}
}

// Helper function to check whether we should stat caches when generating availability maps
func shouldStatCaches(ctx *gin.Context, cAds, oAds []server_structs.ServerAd, bestNSAd server_structs.NamespaceAdV2) bool {
	reqParams := getRequestParameters(ctx.Request)
	if reqParams.Has(pelican_url.QuerySkipStat) || // The client indicates they want to avoid stats
		!param.Director_CheckCachePresence.GetBool() || // The Director is configured to not to stat caches
		len(cAds) == 0 || // There are no caches to stat
		ctx.Request.Method == http.MethodPut || ctx.Request.Method == http.MethodDelete || ctx.Request.Method == "PROPFIND" || // The request is of a type where stats are irrelevant
		!bestNSAd.Caps.PublicReads && reqParams.Get("authz") == "" || // We lack auth to succeed in stating caches
		(isOriginRequest(ctx) && !requiresCacheChaining(ctx, oAds)) { // The request is an origin request and we don't need to chain caches
		return false
	}

	return true
}

// Helper function to check whether we should stat origins when generating availability maps
func shouldStatOrigins(ctx *gin.Context, cAds, oAds []server_structs.ServerAd, bestNSAd server_structs.NamespaceAdV2) bool {
	reqParams := getRequestParameters(ctx.Request)
	if reqParams.Has(pelican_url.QuerySkipStat) || // The client indicates they want to avoid stats
		!param.Director_CheckOriginPresence.GetBool() || // The Director is configured to not to stat origins
		len(oAds) == 0 || // There are no origins to stat
		ctx.Request.Method == http.MethodPut || ctx.Request.Method == http.MethodDelete || ctx.Request.Method == "PROPFIND" || // The request is of a type where stats are irrelevant
		param.Director_AssumePresenceAtSingleOrigin.GetBool() && len(oAds) == 1 || // The Director is configured to assume presence at a single origin
		!bestNSAd.Caps.PublicReads && reqParams.Get("authz") == "" || // We lack auth to succeed in stating origins
		(isCacheRequest(ctx) && len(cAds) > 0) { // The incoming request is for a cache, and we won't need to fall back to origins because of missing caches
		return false
	}

	return true
}

// Generate the availability maps for origins and caches based on the stat query results. Used in redirection sorting.
// The function should determine whether it needs to stat the origins and caches based on the request parameters.
// If stat checks are skipped for both origins and caches, assume all are available.
func generateAvailabilityMaps(ctx *gin.Context, origins, caches []server_structs.ServerAd, bestNSAd server_structs.NamespaceAdV2, requestId uuid.UUID) (map[string]bool, map[string]bool, error) {
	reqPath := getObjectPathFromRequest(ctx)
	reqParams := getRequestParameters(ctx.Request)

	originAvailabilityMap := make(map[string]bool, len(origins))
	cacheAvailabilityMap := make(map[string]bool, len(caches))

	// Determine whether to skip stat for origins and caches
	// shouldStatOrigins := !reqParams.Has(pelican_url.QuerySkipStat) && param.Director_CheckOriginPresence.GetBool()
	// shouldStatCaches := (!reqParams.Has(pelican_url.QuerySkipStat) && param.Director_CheckCachePresence.GetBool()) || requiresCacheChaining(ctx, origins)
	statOrigins := shouldStatOrigins(ctx, caches, origins, bestNSAd)
	statCaches := shouldStatCaches(ctx, caches, origins, bestNSAd)
	if statOrigins {
		log.Tracef("Request %s will trigger a stat against origins: %+v", requestId, origins)
	} else {
		log.Tracef("Request %s will skip origin stats", requestId)
	}
	if statCaches {
		log.Tracef("Request %s will trigger a stat against caches: %+v", requestId, caches)
	} else {
		log.Tracef("Request %s will skip cache stats", requestId)
	}

	// If stat checks are skipped for both origins and caches, assume all are available
	if !statOrigins {
		for _, origin := range origins {
			originAvailabilityMap[origin.URL.String()] = true
		}
	}
	if !statCaches {
		for _, cache := range caches {
			cacheAvailabilityMap[cache.URL.String()] = true
		}
	}
	if !statOrigins && !statCaches {
		return originAvailabilityMap, cacheAvailabilityMap, nil
	}

	// Perform stat query
	q := NewObjectStat()
	st := server_structs.NewServerType()

	sTypes := []server_structs.ServerType{}
	if statOrigins {
		sTypes = append(sTypes, server_structs.OriginType)
	}
	if statCaches {
		sTypes = append(sTypes, server_structs.CacheType)
	}
	st.SetList(sTypes)

	// Filter the ads to include only the relevant types
	oAdsToQuery := origins
	cAdsToQuery := caches
	if !statOrigins {
		oAdsToQuery = nil
	}
	if !statCaches {
		cAdsToQuery = nil
	}

	qr := q.Query(context.Background(), reqPath, st, 1, len(oAdsToQuery)+len(cAdsToQuery),
		withOriginAds(oAdsToQuery), withCacheAds(cAdsToQuery), WithToken(reqParams.Get("authz")))

	if qr.Status == queryFailed {
		if qr.ErrorType != queryNoSourcesErr && qr.ErrorType != queryInsufficientResErr {
			return nil, nil, errors.Errorf("stat query failed: %s", qr.Msg)
		}
	}

	// Populate availability maps based on stat results
	for _, obj := range qr.Objects {
		serverHost := obj.URL.Host
		for _, origin := range origins {
			if origin.URL.Host == serverHost || origin.AuthURL.Host == serverHost {
				originAvailabilityMap[origin.URL.String()] = true
			}
		}
		for _, cache := range caches {
			if cache.URL.Host == serverHost || cache.AuthURL.Host == serverHost {
				cacheAvailabilityMap[cache.URL.String()] = true
			}
		}
	}

	// If we have not discovered any origins then we throw in any whose response
	// was inconclusive (may have been a temporary overload or a permission denied).
	//
	// If we have an origin that claims to have the object and everything else is an
	// error then we'll use that origin.
	//
	// We are extra aggressive about adding back in origins under the assumption that
	// missing an origin due to error is going to be more catastrophic to a client than
	// missing a cache.
	addExtraOrigins := true
	foundOrigins := false
	if statOrigins && len(origins) > 0 {
		for _, origin := range origins {
			if originAvailabilityMap[origin.URL.String()] {
				foundOrigins = true
				break
			}
		}
		if !foundOrigins {
			addExtraOrigins = true
		}
	}

	// Handle denied servers
	for _, ds := range qr.DeniedServers {
		if addExtraOrigins {
			for _, origin := range origins {
				if origin.AuthURL.String() == ds {
					foundOrigins = true
					originAvailabilityMap[origin.URL.String()] = true
				}
			}
		}
		for _, cache := range caches {
			if cache.AuthURL.String() == ds {
				cacheAvailabilityMap[cache.URL.String()] = true
			}
		}
	}
	if addExtraOrigins {
		for _, es := range qr.OtherErrorServers {
			for _, origin := range origins {
				if origin.AuthURL.String() == es {
					foundOrigins = true
					originAvailabilityMap[origin.URL.String()] = true
				}
			}
		}
	}

	// If we issued stat requests against the Origin but none have the object,
	// it likely doesn't exist. This constitutes an actual error that we can propagate
	// back to the client.
	if statOrigins && len(origins) > 0 && !foundOrigins {
		msg := "no queried origins possess the object"
		log.Debugln(msg, reqPath)
		return nil, nil, objectNotFoundErr{msg: msg, object: reqPath}
	}

	return originAvailabilityMap, cacheAvailabilityMap, nil
}
