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
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"github.com/hashicorp/go-version"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

type (
	// status of director-based health tests to origins and caches
	HealthTestStatus string

	// Prometheus HTTP discovery endpoint struct, used by director
	// to dynamically return available origin/cache servers for Prometheus to scrape
	PromDiscoveryItem struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}

	// Util struct to keep track of director-based health tests it created
	healthTestUtil struct {
		ErrGrp        *errgroup.Group
		ErrGrpContext context.Context
		Cancel        context.CancelFunc
		Status        HealthTestStatus
	}
	// Utility struct to keep track of the `stat` call the director made to the origin/cache servers
	serverStatUtil struct {
		Context     context.Context
		Cancel      context.CancelFunc
		Errgroup    *utils.Group
		ResultCache *ttlcache.Cache[string, *objectMetadata]
	}

	// Context key for the project name
	ProjectContextKey struct{}

	// An internal struct for holding advertisements without any mutexing.
	// We assume these are copies from the internal ttlcache. Note that we
	// only store a single namespace ad for each server ad because there can
	// be at most one supported namespace for each server that's the "best match"
	copyAd struct {
		ServerAd    server_structs.ServerAd
		NamespaceAd server_structs.NamespaceAdV2
	}

	// Special Director redirect errors
	noOriginsForNsErr struct {
		ns string
	}
	noOriginsForReqErr struct {
		verb    string
		queries string
	}
	objectNotFoundErr struct {
		msg    string
		object string
	}
	directorStartupErr struct {
		ns string
	}
)

func (e noOriginsForNsErr) Error() string {
	return fmt.Sprintf("no origins found for the requested namespace '%s'", e.ns)
}
func (e noOriginsForReqErr) Error() string {
	return fmt.Sprintf("no origins found that support the '%s' request type with queries '%s'", e.verb, e.queries)
}
func (e objectNotFoundErr) Error() string {
	return fmt.Sprintf("object %s could not be found: %s", e.object, e.msg)
}
func (e directorStartupErr) Error() string {
	return fmt.Sprintf("no servers were found for the requested path '%s'; director just restarted, try again shortly", e.ns)
}

const (
	HealthStatusDisabled HealthTestStatus = "Health Test Disabled"
	HealthStatusUnknown  HealthTestStatus = "Unknown"
	HealthStatusInit     HealthTestStatus = "Initializing"
	HealthStatusOK       HealthTestStatus = "OK"
	HealthStatusError    HealthTestStatus = "Error"
)

const (
	// The number of caches to send in the Link header. As discussed in issue
	// https://github.com/PelicanPlatform/pelican/issues/1247, the client stops
	// after three attempts, so there's really no need to send every cache we know
	serverResLimit = 6
)

var (
	minClientVersion, _ = version.NewVersion("7.0.0")
	minOriginVersion, _ = version.NewVersion("7.0.0")
	minCacheVersion, _  = version.NewVersion("7.3.0")
	// TODO: Consolidate the two maps into server_structs.Advertisement. [#1391]
	healthTestUtils      = make(map[string]*healthTestUtil) // The utilities for the director file tests. The key is string form of ServerAd.URL
	healthTestUtilsMutex = sync.RWMutex{}

	statUtils      = make(map[string]*serverStatUtil) // The utilities for the stat call. The key is string form of ServerAd.URL
	statUtilsMutex = sync.RWMutex{}

	startupTime = time.Now()
)

func init() {
	hookServerAdsCache()
}

// Used for testing, where the Director has pretty much _always_ been started in the
// last 5 minutes.
func SetStartupTime(t time.Time) {
	startupTime = t
}

func inStartupSequence() bool {
	return time.Since(startupTime) <= 5*time.Minute
}

func getRedirectURL(reqPath string, ad server_structs.ServerAd, requiresAuth bool) (redirectURL url.URL) {
	var serverURL url.URL
	if requiresAuth && ad.AuthURL.String() != "" {
		serverURL = ad.AuthURL
		if ad.AuthURL == (url.URL{}) {
			serverURL = ad.URL
		}
	} else {
		serverURL = ad.URL
	}
	reqPath = path.Clean("/" + reqPath)
	if requiresAuth {
		redirectURL.Scheme = "https"
	} else {
		redirectURL.Scheme = "https"
		if ad.FromTopology {
			redirectURL.Scheme = "http"
		}
	}
	redirectURL.Host = serverURL.Host
	redirectURL.Path = reqPath
	return
}

// Calculate the depth attribute of Link header given the path to the file
// and the prefix of the namespace that can serve the file
//
// Ref: https://www.rfc-editor.org/rfc/rfc6249.html#section-3.4
func getLinkDepth(filepath, prefix string) (int, error) {
	if filepath == "" || prefix == "" {
		return 0, errors.New("either filepath or prefix is an empty path")
	}
	if !strings.HasPrefix(filepath, prefix) {
		return 0, errors.New("filepath does not contain the prefix")
	}
	// We want to remove shared prefix between filepath and prefix, then split the remaining string by slash.
	// To make the final calculation easier, we also remove the head slash from the file path.
	// e.g. filepath = /foo/bar/barz.txt   prefix = /foo
	// we want commonPath = bar/barz.txt
	commonPath := strings.TrimPrefix(filepath, prefix)
	commonPath = strings.TrimPrefix(commonPath, "/")
	if len(commonPath) == 0 {
		return 0, nil
	}
	pathDepth := len(strings.Split(commonPath, "/"))
	return pathDepth, nil
}

// Given a gin request for either the object or origin endpoint, extract the object path
// from the request URL.
func getObjectPathFromRequest(ctx *gin.Context) (oPath string) {
	objectPath := "/api/v1.0/director/object"
	originPath := "/api/v1.0/director/origin"
	statPath := "/api/v1.0/director_ui/servers/origins/stat"

	oPath = path.Clean("/" + ctx.Request.URL.Path)
	// Trim prefixes as needed to get the actual object path
	if strings.HasPrefix(oPath, objectPath) {
		return strings.TrimPrefix(oPath, objectPath)
	}

	if strings.HasPrefix(oPath, originPath) {
		return strings.TrimPrefix(oPath, originPath)
	}

	if strings.HasPrefix(oPath, statPath) {
		return strings.TrimPrefix(oPath, statPath)
	}

	return oPath
}

// Given a raw gin request, determine whether it's an object/cache request
func isCacheRequest(ctx *gin.Context) bool {
	return strings.HasPrefix(ctx.Request.URL.Path, "/api/v1.0/director/object")
}

// Given a raw gin request, determine whether it's a source/origin request
func isOriginRequest(ctx *gin.Context) bool {
	return strings.HasPrefix(ctx.Request.URL.Path, "/api/v1.0/director/origin") ||
		strings.HasPrefix(ctx.Request.URL.Path, "/api/v1.0/director_ui/servers/origins/stat")
}

// Aggregate various request parameters from header and query to a single url.Values struct
func getRequestParameters(req *http.Request) (requestParams url.Values) {
	requestParams = url.Values{}

	// Start off by passing along any generic query params. If we have any reserved query params
	// that we specifically handle from both queries and headers, we'll overwrite them later with a Set().
	for key, vals := range req.URL.Query() {
		for _, val := range vals {
			requestParams.Add(key, val)
		}
	}

	authz := ""
	if authzQuery := req.URL.Query()["authz"]; len(authzQuery) > 0 {
		authz = authzQuery[0]
		// if the authz URL query is coming from XRootD, it probably has a "Bearer " tacked in front
		// even though it's coming via a URL
		authz = strings.TrimPrefix(authz, "Bearer ")
	} else if authzHeader := req.Header["Authorization"]; len(authzHeader) > 0 {
		authz = strings.TrimPrefix(authzHeader[0], "Bearer ")
	}

	timeout := ""
	if timeoutQuery := req.URL.Query()["pelican.timeout"]; len(timeoutQuery) > 0 {
		timeout = timeoutQuery[0]
	} else if timeoutHeader := req.Header["X-Pelican-Timeout"]; len(timeoutHeader) > 0 {
		timeout = timeoutHeader[0]
	}

	directRead := req.URL.Query().Has(pelican_url.QueryDirectRead)
	skipStat := req.URL.Query().Has(pelican_url.QuerySkipStat)
	preferCached := req.URL.Query().Has(pelican_url.QueryPreferCached)

	// url.Values.Encode will help us escape all them
	if authz != "" {
		requestParams.Set("authz", authz)
	}
	if timeout != "" {
		requestParams.Set("pelican.timeout", timeout)
	}
	if skipStat {
		requestParams.Set(pelican_url.QuerySkipStat, "")
	}
	if preferCached {
		requestParams.Set(pelican_url.QueryPreferCached, "")
	}
	if directRead {
		requestParams.Set(pelican_url.QueryDirectRead, "")
	}
	return
}

// Generate the link header for the response, which encodes our metalink-prioritized list of redirect servers
func generateLinkHeader(ctx *gin.Context, sAds []server_structs.ServerAd, nsAd server_structs.NamespaceAdV2) {
	reqPath := getObjectPathFromRequest(ctx)

	// if err != nil, depth == 0, which is the default value for depth
	// so we can use it as the value for the header even with err
	depth, err := getLinkDepth(reqPath, nsAd.Path)
	if err != nil {
		log.Errorf("Failed to get depth attribute for the redirecting request to %q, with best match namespace prefix %q", reqPath, nsAd.Path)
	}

	linkHeader := ""
	first := true
	serversToSend := serverResLimit
	if numAds := len(sAds); numAds < serverResLimit {
		serversToSend = numAds
	}
	for idx, ad := range sAds[:serversToSend] {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad, !nsAd.Caps.PublicReads)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; pri=%d; depth=%d`, redirectURL.String(), idx+1, depth)
	}
	ctx.Writer.Header()["Link"] = []string{linkHeader}
}

// Generates the CORS headers needed to enable communication with web client
func corsHeadersMiddleware(ginCtx *gin.Context) {
	ginCtx.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	ginCtx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	ginCtx.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization") // TODO: , X-Pelican-User, X-Pelican-Timeout, X-Pelican-Token-Generation, X-Pelican-Authorization, X-Pelican-Namespace
	ginCtx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Type, Authorization, X-Pelican-User, X-Pelican-Timeout, X-Pelican-Token-Generation, X-Pelican-Authorization, X-Pelican-Namespace")
}

// Generates the X-Pelican-Authorization header (when applicable) for responses that have
// issued a request where token generation may be needed. This header informs the client
// of the issuer that can be used to generate a token for the requested resource.
func generateXAuthHeader(ginCtx *gin.Context, namespaceAd server_structs.NamespaceAdV2) {
	if len(namespaceAd.Issuer) != 0 {
		issStrings := []string{}
		for _, tokIss := range namespaceAd.Issuer {
			issStrings = append(issStrings, "issuer="+tokIss.IssuerUrl.String())
		}
		ginCtx.Writer.Header()["X-Pelican-Authorization"] = issStrings
	}
}

// Generates the X-Pelican-Token-Generation header (when applicable) for responses that have
// issued a request where token generation may be needed.
func generateXTokenGenHeader(ginCtx *gin.Context, namespaceAd server_structs.NamespaceAdV2) {
	if len(namespaceAd.Generation) != 0 {
		tokenGen := ""
		first := true
		// TODO: At some point, the director stopped sending the `base-path` key in the token gen header. I'm unsure of the _proper_ way
		// to fix this because the token gen header uses the issuer URL from NamespaceAdV2.Generation.CredentialIssuer, whereas basepaths
		// come from NamespaceAdV2.Issuer.BasePaths. For now, connecting these two means checking if they have the same issuer URL. This
		// really needs to be cleaned up in the future, and maybe we need to give more thought to why we have these two structs in the
		// ad. See https://github.com/PelicanPlatform/pelican/issues/1540
		var basePath string
		for _, issuer := range namespaceAd.Issuer {
			if issuer.IssuerUrl.String() == namespaceAd.Generation[0].CredentialIssuer.String() {
				if len(issuer.BasePaths) > 0 {
					basePath = issuer.BasePaths[0]
				}
				break
			}
		}

		hdrVals := []string{namespaceAd.Generation[0].CredentialIssuer.String(), fmt.Sprint(namespaceAd.Generation[0].MaxScopeDepth),
			string(namespaceAd.Generation[0].Strategy), basePath}
		for idx, hdrKey := range []string{"issuer", "max-scope-depth", "strategy", "base-path"} {
			hdrVal := hdrVals[idx]
			if hdrVal == "" {
				continue
			} else if hdrKey == "max-scope-depth" && hdrVal == "0" {
				// don't send a 0 max-scope-depth because it's malformed and probably means there should be no token generation header
				continue
			}
			if !first {
				tokenGen += ", "
			}
			first = false
			tokenGen += hdrKey + "=" + hdrVal
		}

		if tokenGen != "" {
			ginCtx.Writer.Header()["X-Pelican-Token-Generation"] = []string{tokenGen}
		}
	}
}

// Generate the X-Pelican-Namespace header, which includes information about the namespace and whether token auth is required
// for reading from this namespace
func generateXNamespaceHeader(ginCtx *gin.Context, oAds []server_structs.ServerAd, bestNSAd server_structs.NamespaceAdV2) {
	var collUrl string
	// If the namespace or the origin does not allow directory listings, then we should not advertise a collections-url.
	for _, oAd := range oAds {
		if oAd.Caps.Listings && bestNSAd.Caps.Listings {
			if !bestNSAd.Caps.PublicReads && oAd.AuthURL != (url.URL{}) {
				collUrl = oAd.AuthURL.String()
				break
			} else {
				collUrl = oAd.URL.String()
				break
			}
		}
	}

	xPelicanNamespace := fmt.Sprintf("namespace=%s, require-token=%v", bestNSAd.Path, !bestNSAd.Caps.PublicReads)
	if collUrl != "" {
		xPelicanNamespace += fmt.Sprintf(", collections-url=%s", collUrl)
	}
	ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{xPelicanNamespace}
}

// Generate the X-Pelican-Broker header using the first origin ad we find supporting
// a broker URL.
// NOTE -- while we don't distinguish between origin/cache server ads, this function
// really must be passed origin ads, as no cache ad would be expected to contain a
// broker URL.
func generateXBrokerHeader(ginCtx *gin.Context, oAds []server_structs.ServerAd) {
	for _, ad := range oAds {
		if brokerUrl := ad.BrokerURL.String(); brokerUrl != "" {
			ginCtx.Writer.Header()["X-Pelican-Broker"] = []string{brokerUrl}
			return
		}
	}
}

// Populate the X-Pelican-JobId header with the request ID. This is used for tracking
// requests through the system.
func generateXJobIdHeader(ginCtx *gin.Context, requestId uuid.UUID) {
	ginCtx.Writer.Header()["X-Pelican-JobId"] = []string{requestId.String()}
}

// Given a URL and a set of query params, add the query params to the URL. This is
// used in Director's redirect logic, where we only populate the final redirect URL
// with query params (and not the URLs generated for metalink headers).
func getFinalRedirectURL(rurl url.URL, requestParams url.Values) string {
	rQuery := rurl.Query()
	for key, vals := range requestParams {
		for _, val := range vals {
			rQuery.Add(key, val)
		}
	}
	rurl.RawQuery = rQuery.Encode()
	return rurl.String()
}

// Helper function to extract version and service from User-Agent
func extractVersionAndService(ginCtx *gin.Context) (reqVer *version.Version, service string, err error) {
	userAgentSlc := ginCtx.Request.Header["User-Agent"]
	if len(userAgentSlc) < 1 {
		return nil, "", errors.New("No user agent could be found")
	}

	userAgent := userAgentSlc[0]
	reqVerStr, service := utils.ExtractVersionAndServiceFromUserAgent(userAgent)
	if reqVerStr == "" || service == "" {
		return nil, "", nil
	}
	reqVer, err = version.NewVersion(reqVerStr)
	if err != nil {
		return nil, "", errors.Wrapf(err, "Could not parse service version as a semantic version: %s\n", reqVerStr)
	}
	return reqVer, service, nil
}

func validateVersionCompat(reqVer *version.Version, service string) error {
	var minCompatVer *version.Version
	switch service {
	case "client":
		minCompatVer = minClientVersion
	case "origin":
		minCompatVer = minOriginVersion
	case "cache":
		minCompatVer = minCacheVersion
	case "": // service not provided, ie: using curl
		return nil
	default:
		return errors.Errorf("Invalid version format. The director does not support your %s version (%s).", service, reqVer.String())
	}

	if reqVer == nil { // version not provided, ie: using curl
		return nil
	}

	if reqVer.LessThan(minCompatVer) {
		return errors.Errorf("The director does not support your %s version (%s). Please update to %s or newer.", service, reqVer.String(), minCompatVer.String())
	}

	return nil
}

// Validate the director-specific query params from the redirect request
func validateQueryParams(query url.Values) error {
	_, hasDirectRead := query[pelican_url.QueryDirectRead]
	_, hasPreferCached := query[pelican_url.QueryPreferCached]

	if hasDirectRead && hasPreferCached {
		return errors.New("cannot have both directread and prefercached query parameters")
	}
	return nil
}

// Given a gin request, make sure there are no conflicting query params or other issues.
func validateIncomingRequest(ctx *gin.Context) (err error) {
	serviceVersion, service, _ := extractVersionAndService(ctx)

	// TODO: Move this version compat check into the new feature compat code
	if err = validateVersionCompat(serviceVersion, service); err != nil {
		return errors.Wrap(err, "version compatibility check failed")
	}

	// Validate the incoming request doesn't have competing query params
	if err = validateQueryParams(ctx.Request.URL.Query()); err != nil {
		return errors.Wrap(err, "invalid query parameter combination")
	}

	return nil
}

// Generate the relevant Prometheus metrics based on the redirect. We should always record the client
// information, but we should only record the redirection if we're sure the Director isn't responding
// with an error, 404, etc.
func collectRedirectMetrics(ctx *gin.Context, chosenService string, redirectSucceeded bool) {
	serviceVersion, service, _ := extractVersionAndService(ctx)
	collectClientVersionMetric(serviceVersion, service)
	if redirectSucceeded {
		collectDirectorRedirectionMetric(ctx, chosenService)
	}
}

// Determine whether this request may require redirecting a cache to another cache.
// TODO: At the time of comment writing, this feature has never been turned on in production
// and it's likely we'll need to revisit this in the future when we're ready to flip
// the switch.
// NOTE: Again, while there's no typed distinction between origin/cache ServerAds, this
// function should only be passed the slice of origin ads that may fulfill the request's needs
// because we count those and use them in decision making.
func requiresCacheChaining(ctx *gin.Context, oAds []server_structs.ServerAd) bool {
	reqParams := getRequestParameters(ctx.Request)
	// Can be enabled by query param and director param, but with the following exceptions:
	// - Number of available Origins >= serverResLimit
	// - This is a non-read request
	// - The request has directread, which means direct read to the origin
	if len(oAds) < serverResLimit &&
		param.Director_CachesPullFromCaches.GetBool() &&
		reqParams.Has(pelican_url.QueryPreferCached) &&
		ctx.Request.Method == http.MethodGet {
		return true
	}

	return false
}

// Given an HTTP verb, return the corresponding Pelican verb. Used for creating
// more user-friendly error messages.
func mapHTTPVerbToPelVerb(httpVerb string) string {
	switch httpVerb {
	case http.MethodGet:
		return "get"
	case http.MethodPut:
		return "put"
	case http.MethodDelete:
		return "delete"
	case "PROPFIND":
		return "ls"
	default:
		return "unknown"
	}
}

// Given a gin request context, determine which capabilities are requested by the client.
func mapQueriesToCaps(ctx *gin.Context) string {
	var caps []string
	if ctx.Request.URL.Query().Has(pelican_url.QueryDirectRead) {
		caps = append(caps, "DirectReads")
	}
	if ctx.Request.URL.Query().Has(pelican_url.QueryRecursive) {
		caps = append(caps, "Listings")
	}

	var capsStr string
	for i, cap := range caps {
		if i == 0 {
			capsStr = cap
		} else {
			capsStr += " AND " + cap
		}
	}
	return capsStr
}

func generateRedirectResponse(ctx *gin.Context, chosenAds []server_structs.ServerAd, oAds []server_structs.ServerAd, nsAd server_structs.NamespaceAdV2, requestId uuid.UUID) {
	reqPath := getObjectPathFromRequest(ctx)
	if len(chosenAds) == 0 {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("No servers found for the requested path '%s': Request ID: %s", reqPath, requestId.String()),
		})
		return
	}

	generateLinkHeader(ctx, chosenAds, nsAd)
	generateXAuthHeader(ctx, nsAd)
	generateXTokenGenHeader(ctx, nsAd)
	generateXNamespaceHeader(ctx, oAds, nsAd)
	generateXBrokerHeader(ctx, chosenAds)
	generateXJobIdHeader(ctx, requestId)

	redirectURL := getRedirectURL(reqPath, chosenAds[0], !nsAd.Caps.PublicReads)
	reqParams := getRequestParameters(ctx.Request)

	// Use debugging redirect info if available and it was asked for
	if redirectInfo, exists := ctx.Get("redirectInfo"); exists && ctx.GetHeader("X-Pelican-Debug") == "true" {
		redirectInfoJSON, err := json.Marshal(redirectInfo)
		if err == nil {
			// If using ctx.JSON, we need to set the Location header manually.
			ctx.Writer.Header().Set("Location", getFinalRedirectURL(redirectURL, reqParams))
			ctx.JSON(http.StatusTemporaryRedirect, redirectInfoJSON)
			return
		} else {
			// Don't treat this is a redirect failure, just log it for director admins to see
			// and continue with the redirect.
			log.Errorf("Failed to marshal redirect info to JSON: %v", err)
		}
	}

	// Check if the request has asked to not be redirected and return directly if so
	if (reqParams.Has("redirect") && reqParams.Get("redirect") == "false") || ctx.Request.Method == http.MethodOptions {
		ctx.Status(http.StatusOK)
		return
	}

	// Note we only append the `authz` query parameter in the case of the redirect response and not the
	// duplicate link metadata above.  This is purposeful: the Link header might get too long if we repeat
	// the token 20 times for 20 caches.  This means a "normal HTTP client" will correctly redirect but
	// anything parsing the `Link` header for metalinks will need logic for redirecting appropriately.
	ctx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, reqParams))
}

// Get or create a taint we can use for tracking the behavior of this request
// through the system.
func getRequestID(ctx *gin.Context) uuid.UUID {
	// Canonicalize the header key to avoid any issues with case sensitivity
	canonicalKey := http.CanonicalHeaderKey("X-Pelican-JobId")
	if jobID := ctx.Request.Header[canonicalKey]; len(jobID) > 0 {
		if id, err := uuid.Parse(jobID[0]); err == nil {
			return id
		}
	}

	// If request doesn't tell us its identity, assign one
	return uuid.New()
}

// If `getSortedAds` returns an error, determine which type it is and respond
// to the client with a sensible explanation of what went wrong.
func processSortedAdsErr(ginCtx *gin.Context, err error, requestId uuid.UUID) {
	switch err.(type) {
	case noOriginsForNsErr:
		msg := fmt.Sprintf("No sources found for the requested path: %v: Request ID: %s", err, requestId.String())
		log.Debugln(msg)
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
	case noOriginsForReqErr:
		msg := fmt.Sprintf("Discovered sources for the namespace, but none support the request: %v: "+
			"See '%s' to troubleshoot available origins/caches and their capabilities: Request ID: %s", err, param.Server_ExternalWebUrl.GetString(), requestId.String())
		log.Debugln(msg)
		ginCtx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
	case objectNotFoundErr:
		msg := fmt.Sprintf("No sources reported possession of the object: %v: Are you sure it exists?: Request ID: %s", err, requestId.String())
		log.Debugln(msg)
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
	case directorStartupErr:
		msg := fmt.Sprintf("%v: Request ID: %s", err, requestId.String())
		log.Debugln(msg)
		ginCtx.JSON(http.StatusTooManyRequests, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
	default:
		msg := fmt.Sprintf("Failed to get/sort server ads for the requested path: %v: Request ID: %s", err, requestId.String())
		log.Debugln(msg)
		ginCtx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
	}
}

func redirectToCache(ginCtx *gin.Context) {
	// Later we'll collect metrics for which service we sent the user to. For now, assume
	// we're sending them to a cache.
	chosenService := "cache"
	redirectSucceeded := false
	defer func(chosenService *string, redirectSucceeded *bool) {
		collectRedirectMetrics(ginCtx, *chosenService, *redirectSucceeded)
	}(&chosenService, &redirectSucceeded)

	// Assign this request an ID (which may come from the client) so we can use it to track
	// the request through the Director.
	requestId := getRequestID(ginCtx)

	// Make sure the user hasn't asked us to do anything too goofy
	if err := validateIncomingRequest(ginCtx); err != nil {
		log.Debugf("Failed to validate incoming request: %v", err)
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to validate incoming request: %v: Request ID: %s", err, requestId.String()),
		})
		return
	}

	// Get the sorted origins/caches for the request. All returned ads should be capable of serving the request,
	// as matchmaking is handled within.
	oAds, cAds, err := getSortedAds(ginCtx, requestId)
	if err != nil {
		processSortedAdsErr(ginCtx, err, requestId)
		return
	}

	// If the namespace prefix is exported by at least one functioning origin but there are no supporting
	// caches, fallback to the origin if able.
	if len(cAds) == 0 {
		for _, oAd := range oAds {
			// Find the first origin that enables direct reads as the fallback
			if oAd.ServerAd.Caps.DirectReads && oAd.NamespaceAd.Caps.DirectReads {
				cAds = append(cAds, oAd)
				break
			}
		}
		if len(cAds) == 0 {
			msg := "No caches can fulfill this request and no fallback origins with the 'DirectReads' capability found for this object. Request ID: " + requestId.String()
			log.Debugln(msg)
			ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    msg,
			})
			return
		}

		// At this point, the cacheAds is full of originAds
		// We need to indicate that we are redirecting to an origin and not a cache
		// This is for the purpose of metrics
		// See collectDirectorRedirectionMetric
		chosenService = "origin"
	}

	chosenServers := make([]server_structs.ServerAd, 0, len(cAds))
	for _, ad := range cAds {
		chosenServers = append(chosenServers, ad.ServerAd)
	}

	oServers := make([]server_structs.ServerAd, 0, len(oAds))
	for _, ad := range oAds {
		oServers = append(oServers, ad.ServerAd)
	}

	redirectSucceeded = true
	generateRedirectResponse(ginCtx, chosenServers, oServers, oAds[0].NamespaceAd, requestId)
}

func redirectToOrigin(ginCtx *gin.Context) {
	chosenService := "origin"
	redirectSucceeded := false
	defer func(chosenService *string, redirectSucceeded *bool) {
		collectRedirectMetrics(ginCtx, *chosenService, *redirectSucceeded)
	}(&chosenService, &redirectSucceeded)

	// Assign this request an ID (which may come from the client) so we can use it to track
	// the request through the Director.
	requestId := getRequestID(ginCtx)

	// Make sure the user hasn't asked us to do anything too goofy
	if err := validateIncomingRequest(ginCtx); err != nil {
		log.Debugf("Failed to validate incoming request: %v", err)
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to validate incoming request: %v: Request ID: %s", err, requestId.String()),
		})
		return
	}

	// /pelican/monitoring is the path for director-based health test
	// where we have /director/healthTest API to mock a test object for caches to pull (as if it's from an origin)
	reqPath := getObjectPathFromRequest(ginCtx)
	if strings.HasPrefix(reqPath, server_utils.MonitoringBaseNs+"/") {
		redirectSucceeded = true
		ginCtx.Redirect(http.StatusTemporaryRedirect, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/director/healthTest"+reqPath)
		return
	}

	// Get the sorted origins/caches for the request. All returned ads should be capable of serving the request,
	// as matchmaking is handled here.
	oAds, cAds, err := getSortedAds(ginCtx, requestId)
	if err != nil {
		processSortedAdsErr(ginCtx, err, requestId)
		return
	}

	chosenServers := make([]server_structs.ServerAd, 0, serverResLimit)
	for idx, ad := range oAds {
		if idx >= serverResLimit {
			break
		}
		chosenServers = append(chosenServers, ad.ServerAd)
	}

	if requiresCacheChaining(ginCtx, chosenServers) {
		chosenCaches := make([]server_structs.ServerAd, 0, serverResLimit-len(oAds))
		for i, ad := range cAds {
			if i+len(oAds) < serverResLimit {
				chosenCaches = append(chosenCaches, ad.ServerAd)
			} else {
				break
			}
		}

		chosenServers = append(chosenCaches, chosenServers...)
	}

	oServers := make([]server_structs.ServerAd, 0, len(oAds))
	for _, ad := range oAds {
		oServers = append(oServers, ad.ServerAd)
	}

	redirectSucceeded = true
	generateRedirectResponse(ginCtx, chosenServers, oServers, oAds[0].NamespaceAd, requestId)
}

func checkHostnameRedirects(c *gin.Context, incomingHost string) {
	oRedirectHosts := param.Director_OriginResponseHostnames.GetStringSlice()
	cRedirectHosts := param.Director_CacheResponseHostnames.GetStringSlice()

	for _, hostname := range oRedirectHosts {
		if hostname == incomingHost {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				log.Debugln("Director is serving an origin based on incoming 'Host' header value of '" + hostname + "'")
				return
			}
		}
	}
	for _, hostname := range cRedirectHosts {
		if hostname == incomingHost {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				redirectToCache(c)
				c.Abort()
				log.Debugln("Director is serving a cache based on incoming 'Host' header value of '" + hostname + "'")
				return
			}
		}
	}
}

// Middleware sends GET /foo/bar to the RedirectToCache function, as if the
// original request had been made to /api/v1.0/director/object/foo/bar
func ShortcutMiddleware(defaultResponse string) gin.HandlerFunc {
	return func(c *gin.Context) {
		web_ui.ServerHeaderMiddleware(c)
		corsHeadersMiddleware(c)

		// If this is a OPTIONS request, we should just return OK
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusOK)
			c.Abort()
			return
		}

		// If this is a request for getting public key, don't modify the path
		// If this is a request to the Prometheus API, don't modify the path
		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/") ||
			(strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/") && !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/")) {
			c.Next()
			return
		}
		// Regardless of the remainder of the settings, we currently handle PUT or DELETE as a query to the origin endpoint
		if c.Request.Method == http.MethodPut || c.Request.Method == http.MethodDelete {
			c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
			redirectToOrigin(c)
			c.Abort()
			return
		}

		// We grab the host and x-forwarded-host headers, which can be set by a client with the intent of changing the
		// Director's default behavior (eg the director normally forwards to caches, but if it receives a request with
		// a pre-configured hostname in its x-forwarded-host header, that indicates we should actually serve an origin.)
		host, hostPresent := c.Request.Header["Host"]
		xForwardedHost, xForwardedHostPresent := c.Request.Header["X-Forwarded-Host"]

		if hostPresent {
			checkHostnameRedirects(c, host[0])
		} else if xForwardedHostPresent {
			checkHostnameRedirects(c, xForwardedHost[0])
		}

		// If we are doing a PROPFIND, we should always redirect to the origin
		if c.Request.Method == "PROPFIND" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == "PROPFIND" || c.Request.Method == http.MethodHead) {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				return
			}
		}

		// Check for the DirectRead query parameter and redirect to the origin if it's set if the origin allows DirectReads
		if c.Request.URL.Query().Has(pelican_url.QueryDirectRead) {
			log.Debugln("directread query parameter detected, redirecting to origin")
			// We'll redirect to origin here and the origin will decide if it can serve the request (if direct reads are enabled)
			redirectToOrigin(c)
			c.Abort()
			return
		}

		// If we're configured for cache mode or we haven't set the flag,
		// we should use cache middleware
		if defaultResponse == "cache" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				redirectToCache(c)
				c.Abort()
				return
			}

			// If the path starts with the correct prefix, continue with the next handler
			c.Next()
		} else if defaultResponse == "origin" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				return
			}
			c.Next()
		}
	}
}

func registerServerAd(engineCtx context.Context, ctx *gin.Context, sType server_structs.ServerType) {
	ctx.Set("serverType", sType.String())
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bearer token not present in the 'Authorization' header",
		})
		return
	}

	reqVer, service, _ := extractVersionAndService(ctx)
	err := validateVersionCompat(reqVer, service)
	if err != nil {
		log.Warningf("A version incompatibility was encountered while registering %s and no response was served: %v", sType, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Incompatible versions detected: " + fmt.Sprintf("%v", err),
		})
		return
	}

	// Check if the allowed prefixes for caches data from the registry
	// has been initialized in the director
	if sType == server_structs.CacheType {
		// If the allowed prefix for caches data is not initialized,
		// wait for it to be initialized for 3 seconds.
		if allowedPrefixesForCachesLastSetTimestamp.Load() == 0 {
			log.Warning("Allowed prefixes for caches data is not initialized. Waiting for initialization before continuing with processing cache server advertisement.")
			start := time.Now()
			// Wait until last set timestamp is updated
			for allowedPrefixesForCachesLastSetTimestamp.Load() == 0 {
				if time.Since(start) >= 3*time.Second {
					log.Error("Allowed prefix for caches data was not initialized within the 3-second timeout")
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		// If the allowed prefix for caches data is stale (older than 15 minutes),
		// fail the server registration.
		if time.Since(time.Unix(allowedPrefixesForCachesLastSetTimestamp.Load(), 0)) >= 15*time.Minute {
			log.Error("Allowed prefixes for caches data is outdated, rejecting cache server ad.")
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Something is wrong with the director or registry. The Director is unable to fetch required information about this cache's allowed prefixes from the Registry.",
			})
			return
		}
	}

	ad := server_structs.OriginAdvertiseV1{}
	adV2 := server_structs.OriginAdvertiseV2{}
	err = ctx.ShouldBindBodyWith(&ad, binding.JSON)
	if err != nil {
		// Failed binding to a V1 type, so should now check to see if it's a V2 type
		adV2 = server_structs.OriginAdvertiseV2{}
		err2 := ctx.ShouldBindBodyWith(&adV2, binding.JSON)
		if err2 != nil {
			log.Debugln("Failed to parse ad of type", sType.String(), "due to error:", err, "original V1 error is", err)
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid %s registration", sType),
			})
			return
		}
	} else {
		// If the OriginAdvertisement is a V1 type, convert to a V2 type
		adV2 = server_structs.ConvertOriginAdV1ToV2(ad)
	}

	// Check every namespace path to strip the trailing slash
	for i := range adV2.Namespaces {
		adV2.Namespaces[i].Path = server_utils.RemoveTrailingSlash(adV2.Namespaces[i].Path)
	}

	// Filter the advertised prefixes in the cache server ad
	// based on the allowed prefixes for caches data.
	if sType == server_structs.CacheType {
		// Parse URL to extract hostname
		parsedURL, err := url.Parse(adV2.DataURL)
		if err != nil {
			log.Debugln("Failed to parse data URL for cache:", err)
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid Cache URL %s (config parameter: Cache.Url): %s", adV2.DataURL, err.Error()),
			})
			return
		}
		cacheHostname := parsedURL.Hostname()

		allowedPrefixesMap := allowedPrefixesForCaches.Load()

		// If the cache hostname is present in the allowed prefixes map,
		// filter the advertised prefixes. If the cache hostname is not present,
		// do nothing. This is the default behavior where all prefixes are allowed.
		//
		// Variable `prefixes` is a set of prefixes that the given cache is allowed to serve.
		if prefixes, exists := (*allowedPrefixesMap)[cacheHostname]; exists {
			filteredNamespaces := []server_structs.NamespaceAdV2{}
			filteredPaths := []string{} // Collect filtered prefixes

			for _, namespace := range adV2.Namespaces {
				// Default allow for paths starting with "/pelican/"
				if strings.HasPrefix(namespace.Path, "/pelican/") {
					filteredNamespaces = append(filteredNamespaces, namespace)
					continue
				}

				// Check if the namespace path exists in the allowed set
				if _, allowed := prefixes[namespace.Path]; allowed {
					filteredNamespaces = append(filteredNamespaces, namespace)
				} else {
					filteredPaths = append(filteredPaths, namespace.Path) // Collect the filtered path
				}
			}

			// Log all filtered prefixes at once
			if len(filteredPaths) > 0 {
				log.Infof("Filtered out prefixes: %v in the server ad for cache %s", filteredPaths, cacheHostname)
			}

			adV2.Namespaces = filteredNamespaces
		}
	}

	// Set to ctx for metrics handler downstream
	ctx.Set("serverName", adV2.Name)
	ctx.Set("serverWebUrl", adV2.WebURL)

	// Iterate over each advertised namespace and join the paths together
	// into a string where each path is separated by a space
	// i.e. "<path> <path> <path>"
	var namespacePaths string
	for _, namespace := range adV2.Namespaces {
		path := namespace.Path
		namespacePaths = fmt.Sprintf("%s %s", namespacePaths, path)
	}
	namespacePaths = strings.TrimSpace(namespacePaths)
	ctx.Set("namespacePaths", namespacePaths)

	// Verify server registration
	token := strings.TrimPrefix(tokens[0], "Bearer ")

	registryPrefix := server_utils.RemoveTrailingSlash(adV2.RegistryPrefix)
	verifyServer := true
	if registryPrefix == "" {
		if sType == server_structs.OriginType {
			// For origins < 7.9.0, they are not registered, and we skip the verification
			verifyServer = false
		} else {
			// For caches <= 7.8.1, they don't have RegistryPrefix
			// so we fall back to Name
			registryPrefix = server_structs.GetCacheNs(adV2.Name)
		}
	}

	approvalErrMsg := "You may find more information on " + param.Server_ExternalWebUrl.GetString()
	// Prepare the admin approval error message
	if param.Director_SupportContactEmail.GetString() != "" && param.Director_SupportContactUrl.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Contact %s or visit %s for help.", param.Director_SupportContactEmail.GetString(), param.Director_SupportContactUrl.GetString())
	} else if param.Director_SupportContactEmail.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Contact %s for help.", param.Director_SupportContactEmail.GetString())
	} else if param.Director_SupportContactUrl.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Visit %s for help.", param.Director_SupportContactUrl.GetString())
	}

	if verifyServer {
		ok, err := verifyAdvertiseToken(engineCtx, token, registryPrefix)
		if err != nil {
			if err == adminApprovalErr {
				log.Warningf("Failed to verify token. %s %q was not approved", sType.String(), adV2.Name)
				ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("%s %q was not approved by an administrator. %s", sType.String(), ad.Name, approvalErrMsg)})
				metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
				return
			} else {
				log.Warningln("Failed to verify token:", err)
				ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("Authorization token verification failed %v", err),
				})
				metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
				return
			}
		}
		if !ok {
			log.Warningf("%s %v advertised without valid token scope\n", sType, adV2.Name)
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authorization token verification failed. Token missing required scope",
			})
			metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
			return
		}
	}

	// For origin, also verify namespace registrations
	if sType == server_structs.OriginType {
		for _, namespace := range adV2.Namespaces {
			// We're assuming there's only one token in the slice
			token := strings.TrimPrefix(tokens[0], "Bearer ")
			ok, err := verifyAdvertiseToken(engineCtx, token, namespace.Path)
			if err != nil {
				if err == adminApprovalErr {
					log.Warningf("Failed to verify advertise token. Namespace %q requires administrator approval", namespace.Path)
					ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("The namespace %q was not approved by an administrator. %s", namespace.Path, approvalErrMsg)})
					metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
					return
				} else {
					log.Warningln("Failed to verify token:", err)
					ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
						Status: server_structs.RespFailed,
						Msg:    fmt.Sprintf("Authorization token verification failed: %v", err),
					})
					metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
					return
				}
			}
			if !ok {
				log.Warningf("%s %v advertised to namespace %v without valid token scope\n",
					sType, adV2.Name, namespace.Path)
				ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Authorization token verification failed. Token missing required scope",
				})
				metrics.PelicanDirectorRejectedAdvertisements.With(prometheus.Labels{"hostname": adV2.Name}).Inc()
				return
			}
		}
	}

	// if we didn't receive a version from the ad but we were able to extract the request version from the user agent,
	// then we can fallback to the request version
	// otherwise, we set the version to unknown because our sources of truth are not available
	if adV2.Version == "" && reqVer != nil {
		adV2.Version = reqVer.String()
	} else if adV2.Version != "" && reqVer != nil {
		parsedAdVersion, err := version.NewVersion(adV2.Version)
		if err != nil {
			// ad version was not a valid version, so we fallback to the request version
			adV2.Version = reqVer.String()
		} else if !parsedAdVersion.Equal(reqVer) {
			// if the reqVer doesn't match the adV2.version, we should use the adV2.version
			adV2.Version = parsedAdVersion.String()
		}
	} else if adV2.Version == "" {
		adV2.Version = "unknown"
	}

	sn := adV2.Name
	// Process received server(origin/cache) downtimes and toggle the director's in-memory downtime tracker when necessary
	if adV2.Downtimes != nil {
		filteredServersMutex.Lock()

		// Update the cached server downtime list
		serverDowntimes[sn] = adV2.Downtimes

		now := time.Now().UTC().UnixMilli()
		active := false // Flag to indicate if this server has active downtime in this server ad
		for _, dt := range adV2.Downtimes {
			if dt.StartTime <= now &&
				(dt.EndTime >= now || dt.EndTime == server_structs.IndefiniteEndTime) {
				active = true
				break
			}
		}

		// Inspect the existing downtime status for this server
		existingFilterType, isServerFiltered := filteredServers[sn]

		if active {
			// Only override if there's no filter
			if !isServerFiltered {
				filteredServers[sn] = serverFiltered
			}
		} else {
			// Clear only the downtimes with serverFiltered tag if it’s stale
			if isServerFiltered && existingFilterType == serverFiltered {
				delete(filteredServers, sn)
			}
		}
		filteredServersMutex.Unlock()
	}

	// "Status" represents the server's overall health status. It is introduced in Pelican 7.17.0
	if adV2.Status != "" { // For backward compatibility, we only process this if it is set
		// If the server is about to shutdown, we silently put it into downtime.
		// Then it will not receive new requests from the Director, but it will still be able to serve the existing ones.
		if metrics.ParseHealthStatus(adV2.Status) == metrics.StatusShuttingDown {
			filteredServersMutex.Lock()
			// Inspect the existing downtime status for this server
			existingFilterType, isServerFiltered := filteredServers[sn]

			// Put the server in downtime only if no filter (downtime) exists or it was tempAllowed
			if !isServerFiltered || existingFilterType == tempAllowed {
				filteredServers[sn] = shutdownFiltered
				log.Debugf("Server %s is shutting down, applying downtime to prevent new transfer requests", sn)
			}
			filteredServersMutex.Unlock()
		} else {
			// If the server is back online, we flush out existing shutdown filter if it exists
			filteredServersMutex.Lock()
			if existingFilterType, isServerFiltered := filteredServers[sn]; isServerFiltered {
				if existingFilterType == shutdownFiltered {
					delete(filteredServers, sn)
					log.Debugf("Removed the active downtime for server %s as it has come back online", sn)
				}
			}
			filteredServersMutex.Unlock()
		}
	}

	// Forward to other directors, if applicable
	forwardServiceAd(engineCtx, &adV2, sType)

	// Correct any clock skews detected in the client
	now := time.Now()
	if skew := now.Sub(adV2.Now); !adV2.Now.IsZero() && (skew > 100*time.Millisecond || skew < -100*time.Millisecond) {
		lifetime := adV2.GetExpiration().Sub(adV2.Now)
		if lifetime > 0 {
			adV2.Expiration = now.Add(lifetime)
		}
	}
	adV2.Now = time.Time{}

	finishRegisterServeAd(engineCtx, ctx, &adV2, sType)
}

// Finish registering the provided service ad (cache or origin) after authorization was completed.
func finishRegisterServeAd(engineCtx context.Context, ctx *gin.Context, adV2 *server_structs.OriginAdvertiseV2, sType server_structs.ServerType) {
	log.Debugf("finishRegisterServeAd received %+v", adV2)
	st := adV2.StorageType
	// Defaults to POSIX
	if st == "" {
		st = server_structs.OriginStoragePosix
	}
	// Disable director test if the server isn't POSIX
	if st != server_structs.OriginStoragePosix && !adV2.DisableDirectorTest {
		log.Warningf("%s server '%s' with storage type '%s' enabled director test. This is not supported.", sType, adV2.Name, string(st))
		adV2.DisableDirectorTest = true
	}

	adUrl, err := url.Parse(adV2.DataURL)
	if err != nil {
		log.Warningf("Failed to parse %s URL %v: %v\n", sType, adV2.DataURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. %s.URL %s is not a valid URL", sType, sType, adV2.DataURL), // Origin.URL / Cache.URL
		})
		return
	}

	adWebUrl, err := url.Parse(adV2.WebURL)
	if err != nil && adV2.WebURL != "" { // We allow empty WebURL string for backward compatibility
		log.Warningf("Failed to parse server Web URL %v: %v\n", adV2.WebURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. %s %s is not a valid URL", param.Server_ExternalWebUrl.GetName(), sType, adV2.WebURL),
		})
		return
	}

	brokerUrl, err := url.Parse(adV2.BrokerURL)
	if err != nil {
		log.Warningf("Failed to parse broker URL %s: %s", adV2.BrokerURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. BrokerURL %s is not a valid URL", sType, adV2.BrokerURL),
		})
	}

	sAd := server_structs.ServerAd{
		RegistryPrefix:      adV2.RegistryPrefix,
		StorageType:         st,
		DisableDirectorTest: adV2.DisableDirectorTest,
		URL:                 *adUrl,
		WebURL:              *adWebUrl,
		BrokerURL:           *brokerUrl,
		Type:                sType.String(),
		Caps:                adV2.Caps,
		RequiredFeatures:    adV2.RequiredFeatures,
		IOLoad:              0.0, // Explicitly set to 0. The sort algorithm takes 0.0 as unknown load
		Downtimes:           adV2.Downtimes,
		Status:              adV2.Status,
	}
	sAd.CopyFrom(adV2)

	recordAd(engineCtx, sAd, &adV2.Namespaces)

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "Successful registration"})
}

func serverAdMetricMiddleware(ctx *gin.Context) {
	ctx.Next()

	serverName := "Unknown"
	serverWebUrl := ctx.ClientIP()
	statusCode := ctx.Writer.Status()

	if ctx.GetString("serverName") != "" {
		serverName = ctx.GetString("serverName")
	}
	if ctx.GetString("serverWebUrl") != "" {
		serverWebUrl = ctx.GetString("serverWebUrl")
	}

	// Separate each path by the space separator
	namespacePaths := strings.Split(ctx.GetString("namespacePaths"), " ")
	// Update metrics for each path
	for _, namespacePath := range namespacePaths {
		if len(namespacePath) == 0 {
			continue
		}
		metrics.PelicanDirectorAdvertisementsReceivedTotal.With(
			prometheus.Labels{
				"server_name":      serverName,
				"server_web_url":   serverWebUrl,
				"server_type":      ctx.GetString("serverType"),
				"status_code":      strconv.Itoa(statusCode),
				"namespace_prefix": namespacePath,
			}).Inc()
	}
}

// Return a list of registered origins and caches in Prometheus HTTP SD format
// for director's Prometheus service discovery
func discoverOriginCache(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer, token.FederationIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorServiceDiscovery},
	}

	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		log.Warningf("Cannot verify token for accessing director's service discovery: %v", err)
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	promDiscoveryRes := make([]PromDiscoveryItem, 0)
	for _, ad := range serverAds.Items() {
		serverAd := ad.Value()
		if serverAd.WebURL.String() == "" {
			// Origins and caches fetched from topology can't be scraped as they
			// don't have a WebURL
			continue
		}
		var auth_url string
		if serverAd.AuthURL == (url.URL{}) {
			auth_url = serverAd.URL.String()
		} else {
			auth_url = serverAd.AuthURL.String()
		}
		promDiscoveryRes = append(promDiscoveryRes, PromDiscoveryItem{
			Targets: []string{serverAd.WebURL.Hostname() + ":" + serverAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(serverAd.Type),
				"server_name":     serverAd.Name,
				"server_auth_url": auth_url,
				"server_url":      serverAd.URL.String(),
				"server_web_url":  serverAd.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", serverAd.Latitude),
				"server_long":     fmt.Sprintf("%.4f", serverAd.Longitude),
			},
		})
	}
	ctx.JSON(200, promDiscoveryRes)
}

func listNamespacesV1(ctx *gin.Context) {
	namespaceAdsV2 := listNamespacesFromOrigins()

	namespaceAdsV1 := server_structs.ConvertNamespaceAdsV2ToV1(namespaceAdsV2)

	ctx.JSON(http.StatusOK, namespaceAdsV1)
}

func listNamespacesV2(ctx *gin.Context) {
	namespacesAdsV2 := listNamespacesFromOrigins()
	namespacesAdsV2 = append(namespacesAdsV2, server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{
			PublicReads: true,
			Reads:       true,
		},
		Path: server_utils.MonitoringBaseNs,
	})
	ctx.JSON(http.StatusOK, namespacesAdsV2)
}

func getPrefixByPath(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	if pathParam == "" || pathParam == "/" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad request. Path is empty or '/' ",
		})
		return
	}

	oAds, _ := getAdsForPath(pathParam)
	if len(oAds) == 0 {
		ctx.AbortWithStatusJSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No server is currently advertising the path",
		})
		return
	}
	ns := oAds[0].NamespaceAd
	// If originNs.Path is an empty value, then the namespace is not found
	if ns.Path == "" {
		ctx.AbortWithStatusJSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace prefix not found for " + pathParam,
		})
		return
	}

	res := server_structs.GetPrefixByPathRes{Prefix: ns.Path}
	ctx.JSON(http.StatusOK, res)
}

// Given a request for a health test file, validate the incoming path, the file extension and the timestamp.
func validateHealthTestRequest(fPath string) (string, error) {
	// Incoming paths might look like
	//   - /pelican/monitoring/directorTest/director-test-2006-01-02T15:04:10Z.txt
	//   - /pelican/monitoring/selfTest/self-test-2006-01-02T15:04:10Z.txt
	// These paths/prefixes are defined by the file transfer test utilities in server_utils/test_file_transfer.go
	if fPath == "" || !strings.HasPrefix(fPath, server_utils.MonitoringBaseNs+"/") {
		return "", fmt.Errorf("Path parameter is not a valid health test path: %s", fPath)
	}
	fName := strings.TrimPrefix(fPath, server_utils.MonitoringBaseNs+"/")
	if fName == "" {
		return "", fmt.Errorf("Path parameter is not a valid health test path because it contains no file name: %s", fPath)
	}
	fNameSplit := strings.Split(fName, "/")
	if len(fNameSplit) == 0 {
		return "", fmt.Errorf("Path parameter is not a valid health test path because it contains no file name: %s", fPath)
	}
	// Grab the filename from the remaining components
	fName = fNameSplit[len(fNameSplit)-1]

	// Validate the file extension
	extSplit := strings.SplitN(fName, ".", 2)
	if len(extSplit) != 2 {
		return "", fmt.Errorf("Test file name is missing file extension: %s", fPath)
	}

	// validate the timestamp in the file name
	var tStampStr string
	if strings.HasPrefix(fName, server_utils.DirectorTest.String()) {
		tStampStr = strings.TrimPrefix(fName, server_utils.DirectorTest.String()+"-")
	} else if strings.HasPrefix(fName, server_utils.ServerSelfTest.String()) {
		tStampStr = strings.TrimPrefix(fName, server_utils.ServerSelfTest.String()+"-")
	} else {
		return "", fmt.Errorf("File name does not have a valid prefix: %s", fName)
	}
	tStampStr = strings.TrimSuffix(tStampStr, "."+extSplit[1])
	tStamp, err := time.Parse("2006-01-02T15:04:05Z07:00", tStampStr)
	if err != nil {
		return "", fmt.Errorf("Invalid timestamp in file name: '%s'. Should conform to 2006-01-02T15:04:05Z07:00 format (RFC 3339)", tStampStr)
	}
	formatted := tStamp.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	return formatted, nil
}

// Generate a PROPFIND response for a health test file. This is important for caches, where xrdcl-pelican's first query
// will always be a PROPFIND request to check whether the requested resource is an object or a collection.
func generatePROPFINDResponse(fPath string, size int, tStamp string) string {
	// Generate the XML content. This template was obtained by sending a curl command to a real cache to query for a known test file:
	//   curl -v -X PROPFIND -i -H "Depth: 0" https://osdf-uw-cache.svc.osg-htc.org:8443/pelican/monitoring/directorTest/director-test-2025-01-24T12:16:59Z.txt
	xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
	<D:multistatus xmlns:D="DAV:" xmlns:ns1="http://apache.org/dav/props/" xmlns:ns0="DAV:">
		<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:lp3="LCGDM:">
			<D:href>%s</D:href>
			<D:propstat>
				<D:prop>
					<lp1:getcontentlength>%d</lp1:getcontentlength>
					<lp1:getlastmodified>%s</lp1:getlastmodified>
					<lp1:iscollection>0</lp1:iscollection>
					<lp1:executable>F</lp1:executable>
				</D:prop>
				<D:status>HTTP/1.1 200 OK</D:status>
			</D:propstat>
		</D:response>
	</D:multistatus>`, fPath, size, tStamp)

	return xmlContent
}

// Generate a mock file for caches to fetch. This is for director-based health tests for caches
// So that we don't require an origin to feed the test file to the cache
func getHealthTestFile(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	cleanedPath := path.Clean(pathParam)
	tStamp, err := validateHealthTestRequest(cleanedPath)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	fileContent := server_utils.DirectorTestBody + "\n"

	method := ctx.Request.Method
	switch method {
	case "PROPFIND":
		var buf bytes.Buffer
		if err := xml.EscapeText(&buf, []byte(cleanedPath)); err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    errors.Wrapf(err, "Unable to properly escape XML content for path: %s", cleanedPath).Error(),
			})
		}

		// Respond with the special Multi Status 207 code. Technically we're only sending a
		// single XML response in our "multi-status" xml (notice the 200 OK in the XML body),
		// but this is the PROPFIND status code clients will typically expect to see.
		ctx.String(http.StatusMultiStatus, generatePROPFINDResponse(cleanedPath, len(fileContent), tStamp))
	case "HEAD":
		ctx.Header("Content-Length", strconv.Itoa(len(fileContent)))
	case "GET":
		ctx.String(http.StatusOK, fileContent)
	default:
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Unsupported method: " + method})
	}
}

// collectClientVersionMetric will get the user agent of an incoming request
// parse out the version from it and update the pelican_director_client_version_total metric
//
// In the case that parser fails, then metric is not updated
func collectClientVersionMetric(reqVer *version.Version, service string) {
	if reqVer == nil || service == "" {
		// TODO: Remove this metric (the line directly below)
		// The renamed metric was added in v7.16
		metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": "other", "service": "other"}).Inc()
		metrics.PelicanDirectorClientRequestsTotal.With(prometheus.Labels{"version": "other", "service": "other"}).Inc()
		return
	}

	directorVersion, err := version.NewVersion(config.GetVersion())
	if err != nil {
		return
	}

	if reqVer.GreaterThan(directorVersion) {
		// TODO: Remove this metric (the line directly below)
		// The renamed metric was added in v7.16
		metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": "pelican-future", "service": service}).Inc()
		metrics.PelicanDirectorClientRequestsTotal.With(prometheus.Labels{"version": "pelican-future", "service": service}).Inc()
	}

	versionSegments := reqVer.Segments()
	if len(versionSegments) < 2 {
		return
	}

	strSegments := []string{
		fmt.Sprintf("%d", versionSegments[0]),
		fmt.Sprintf("%d", versionSegments[1]),
	}

	shortenedVersion := strings.Join(strSegments, ".")

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": shortenedVersion, "service": service}).Inc()
	metrics.PelicanDirectorClientRequestsTotal.With(prometheus.Labels{"version": shortenedVersion, "service": service}).Inc()
}

func collectDirectorRedirectionMetric(ctx *gin.Context, destination string) {
	labels := prometheus.Labels{
		"destination": destination,
		"status_code": strconv.Itoa(ctx.Writer.Status()),
		"version":     "",
		"network":     "",
	}

	version, _, err := extractVersionAndService(ctx)
	if err != nil {
		log.Warningf("Failed to extract version and service from request: %v", err)
		return
	}
	if version != nil {
		labels["version"] = version.String()
	} else {
		labels["version"] = "unknown"
	}

	maskedIp, ok := utils.ApplyIPMask(ctx.ClientIP())
	if ok {
		labels["network"] = maskedIp
	} else {
		labels["network"] = "unknown"
	}
	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	metrics.PelicanDirectorRedirectionsTotal.With(labels).Inc()
	metrics.PelicanDirectorRedirectsTotal.With(labels).Inc()
}

func RegisterDirectorAPI(ctx context.Context, router *gin.RouterGroup) {
	egrp := ctx.Value(config.EgrpKey).(*errgroup.Group)

	// Print out a log statement so we know what version is running
	log.Debugf("Starting Pelican Director API v%s", "s")
	gin.SetMode(gin.DebugMode)

	directorAPIV1 := router.Group("/api/v1.0/director", web_ui.ServerHeaderMiddleware)
	{
		// Answer CORS preflight requests, trivial response inlined
		directorAPIV1.OPTIONS("/*any", corsHeadersMiddleware, func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "")
		})

		// Establish the routes used for cache/origin redirection
		directorAPIV1.GET("/object/*any", corsHeadersMiddleware, redirectToCache)
		directorAPIV1.HEAD("/object/*any", corsHeadersMiddleware, redirectToCache)
		directorAPIV1.GET("/origin/*any", corsHeadersMiddleware, redirectToOrigin)
		directorAPIV1.HEAD("/origin/*any", corsHeadersMiddleware, redirectToOrigin)
		directorAPIV1.PUT("/origin/*any", corsHeadersMiddleware, redirectToOrigin)
		directorAPIV1.DELETE("/origin/*any", corsHeadersMiddleware, redirectToOrigin)
		directorAPIV1.Handle("PROPFIND", "/origin/*any", corsHeadersMiddleware, redirectToOrigin)

		// Other API endpoints
		directorAPIV1.GET("/directors", listDirectors)
		directorAPIV1.POST("/registerDirector", serverAdMetricMiddleware, func(gctx *gin.Context) { registerDirectorAd(ctx, egrp, gctx) })
		directorAPIV1.POST("/registerOrigin", serverAdMetricMiddleware, func(gctx *gin.Context) { registerServerAd(ctx, gctx, server_structs.OriginType) })
		directorAPIV1.POST("/registerCache", serverAdMetricMiddleware, func(gctx *gin.Context) { registerServerAd(ctx, gctx, server_structs.CacheType) })
		directorAPIV1.GET("/getFedToken", getFedToken)
		directorAPIV1.GET("/listNamespaces", listNamespacesV1)
		directorAPIV1.GET("/namespaces/prefix/*path", getPrefixByPath)
		directorAPIV1.GET("/healthTest/*path", getHealthTestFile)
		directorAPIV1.HEAD("/healthTest/*path", getHealthTestFile)
		directorAPIV1.Handle("PROPFIND", "/healthTest/*path", getHealthTestFile)

		// In the foreseeable feature, director will scrape all servers in Pelican ecosystem (including registry)
		// so that director can be our point of contact for collecting system-level metrics.
		// Rename the endpoint to reflect such plan.
		directorAPIV1.GET("/discoverServers", discoverOriginCache)

	}

	directorAPIV2 := router.Group("/api/v2.0/director", web_ui.ServerHeaderMiddleware)
	{
		directorAPIV2.GET("/listNamespaces", listNamespacesV2)
	}
}
