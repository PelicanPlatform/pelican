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

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// directorDebugCtxKey is used to signal that the director query should include
// the X-Pelican-Debug header regardless of the current log level.
type directorDebugCtxKey struct{}

// WithDirectorDebug returns a derived context that causes director queries
// to include the X-Pelican-Debug header, requesting decision information.
func WithDirectorDebug(ctx context.Context) context.Context {
	return context.WithValue(ctx, directorDebugCtxKey{}, true)
}

// Check whether an HTTP response is actually a response from a Pelican service, as
// indicated by the "Server" header pointing to a pelican process.
//
// We use this to handle retries in the event that the Director is down, but some ingress proxy in
// front of it is still answering requests with errant 404s, 500s, 502s, etc.
func fromPelican(resp *http.Response) bool {
	if param.Client_AssumeDirectorServerHeader.GetBool() {
		log.Debugln("Will assume response is from Director instead of checking for matching Server header. To change this behavior,",
			"set the 'Client.AssumeDirectorServerHeader' configuration option to false.")
		return true
	}
	return strings.HasPrefix(resp.Header.Get("Server"), "pelican/")
}

// Make a request to the director for a given verb/resource; return the
// HTTP response object only if a 307 is returned.  When the X-Pelican-Debug
// header was sent and the director includes decision information in the
// response body, redirectBody will contain that JSON payload.
//
// When cacheMode is true the request path is routed through the director's
// origin endpoint (/api/v1.0/director/origin/…) so that the director
// redirects to origins instead of caches.  This is the correct behaviour
// when the caller is itself an embedded cache.
func queryDirector(ctx context.Context, verb string, pUrl *pelican_url.PelicanURL, token string, cacheMode bool) (resp *http.Response, redirectBody string, err error) {
	resourceUrl, err := url.Parse(pUrl.FedInfo.DirectorEndpoint)
	if err != nil {
		log.Errorln("Failed to parse the director URL:", err)
		return nil, "", err
	}
	if cacheMode {
		resourceUrl.Path = path.Join("/api/v1.0/director/origin", pUrl.Path)
	} else {
		resourceUrl.Path = pUrl.Path
	}
	resourceUrl.RawQuery = pUrl.RawQuery

	// Here we use http.Transport to prevent the client from following the director's
	// redirect. We use the Location url elsewhere (plus we still need to do the token
	// dance!)
	client := config.GetClientNoRedirect()

	var errMsg string
	var body []byte
	// The `fromDirector` variable indicates we think this response came from a director
	// process, not a proxy / ingress like traefik.
	var fromDirector bool
	// In case the director is momentarily down, we will retry a few times using a backoff strategy
	// I assume numRetries is >=1, which should enforced in config.go. However, not all tests that hit this code initialize the client.
	numRetries := param.Client_DirectorRetries.GetInt()
	if numRetries < 1 {
		log.Errorf("The config parameter %s is currently set to %d. This should not be possible. Will use fallback of 1 retry",
			param.Client_DirectorRetries.GetName(), numRetries)
		numRetries = 1
	}
	for idx := 0; idx < numRetries; idx++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, verb, resourceUrl.String(), nil)
		if err != nil {
			log.Errorln("Failed to create an HTTP request:", err)
			return nil, "", err
		}

		// Include the Client's version as a User-Agent header. The Director will decide
		// if it supports the version, and provide an error message in the case that it
		// cannot.
		req.Header.Set("User-Agent", getUserAgent(""))

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		// If the client has a declared GeoLocation, send it as X-Pelican-Coordinate
		// so the director can use it for client-server matchmaking.
		if geoStr := param.GeoLocation.GetString(); geoStr != "" {
			if lat, long, geoErr := utils.ParseCoordinateStr(geoStr); geoErr == nil {
				req.Header.Set(string(server_structs.XPelicanCoordinateHeaderName),
					fmt.Sprintf("lat=%g,long=%g", lat, long))
			} else {
				log.Warningf("Ignoring invalid %s value %q: %v", param.GeoLocation.GetName(), geoStr, geoErr)
			}
		}

		forceDebug, _ := ctx.Value(directorDebugCtxKey{}).(bool)
		if config.GetEffectiveLogLevel() >= log.DebugLevel || forceDebug {
			req.Header.Set("X-Pelican-Debug", "true")
		}

		// Perform the HTTP request
		resp, err = client.Do(req)

		if err != nil {
			log.Errorln("Failed to get response from the director:", err)
			// Check if this is a timeout error and use the appropriate retryable error type
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				err = error_codes.NewTransfer_DirectorTimeoutError(err)
			} else {
				// Wrap other network errors in Contact.Director error type
				err = error_codes.NewContact_DirectorError(err)
			}
			return
		}

		defer resp.Body.Close()
		log.Tracef("Director's response: %#v\n", resp)
		// Check HTTP response -- should be 307 (redirect), else something went wrong
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Errorln("Failed to read the body from the director response:", err)
			return resp, "", err
		}
		errMsg = string(body)

		// If this isn't a Pelican process _and_ we got an error, sleep then retry. We may be talking
		// to something like a Traefik ingress controller that's waiting for the Director to come
		// back online.
		fromDirector = fromPelican(resp)
		if !fromDirector && (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusInternalServerError) {
			if idx == 0 {
				log.Warnf("Response not from a Pelican process, the Director may be rebooting; will retry a total of %d times.", numRetries)
			}
			sleepFor := 3*idx + 3
			log.Warningln("Sleeping for", sleepFor, "seconds before retrying.")
			// backoff+randomness to avoid thundering herd
			time.Sleep(time.Duration(sleepFor)*time.Second + time.Duration(rand.Float32()*1000)*time.Millisecond)
		} else if fromDirector && resp.StatusCode == http.StatusTooManyRequests {
			// We just hit the Director after a reboot, but potentially before it's repopulated its
			// cache of server adds. Retry until we stop getting the 429 or we hit our limit.
			if idx == 0 {
				log.Warningln("The Director indicates it has just rebooted and is still discovering federation services.")
			}
			sleepFor := 3*idx + 3
			log.Warningln("Sleeping for", sleepFor, "seconds before retrying.")
			time.Sleep(time.Duration(sleepFor)*time.Second + time.Duration(rand.Float32()*1000)*time.Millisecond)
		} else {
			break
		}
	}

	// The Content-Type will be alike "application/json; charset=utf-8"
	if resp.StatusCode != http.StatusTemporaryRedirect && utils.HasContentType(resp, "application/json") {
		var respErr server_structs.SimpleApiResp
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			log.Errorln("Failed to unmarshal the director's JSON response:", err)
			return resp, "", unmarshalErr
		}
		fromDirector = true
		// In case we have old director returning "error": "message content"
		if respErr.Msg != "" {
			errMsg = respErr.Msg
		}
	}

	bodyString := string(body)
	if resp.StatusCode == http.StatusMultiStatus && verb == "PROPFIND" {
		// This is a director >7.9 proxy the PROPFIND response instead of redirect to the origin
		return
	} else if resp.StatusCode != 307 {
		// Attempt to query the director using the PUT HTTP method instead of DELETE,
		// as older versions of the director may not support the DELETE endpoint.
		if resp.StatusCode == http.StatusNotFound && verb == http.MethodDelete {
			if strings.Contains(strings.ToLower(bodyString), "page not found") {
				log.Warningf("Failed to query the DELETE endpoint; the director appears to be an older version, attempting with the PUT method")
				return queryDirector(ctx, http.MethodPut, pUrl, token, cacheMode)
			}
		}
		if resp.StatusCode == http.StatusNotFound && fromDirector && (errMsg == "All sources report object was not found" || errMsg == "Object not found at any cache") {
			sce := StatusCodeError(http.StatusNotFound)
			err = &sce
		} else {
			err = errors.Errorf("%d: %s", resp.StatusCode, errMsg)
		}
		return resp, "", err
	}

	// A 307 may come with a body that contains the redirect choice information
	if bodyString != "" {
		log.Debugf("Director's redirect choice information: %s", bodyString)
		redirectBody = bodyString
	}

	return
}

type ServerPriority struct {
	URL      *url.URL
	Priority int
}

func parseServersFromDirectorResponse(resp *http.Response) (servers []*url.URL, err error) {
	linkHeader := resp.Header.Values("Link")
	if len(linkHeader) == 0 {
		return nil, nil
	}

	serversPrio := make([]ServerPriority, 0)
	for _, linksStr := range strings.Split(linkHeader[0], ",") {
		links := strings.Split(strings.ReplaceAll(linksStr, " ", ""), ";")

		var endpoint string
		// var rel string // "rel", as defined in the Metalink/HTTP RFC. Currently not being used by
		// the OSDF Client, but is provided by the director. Will be useful in the future when
		// we start looking at cases where we want to duplicate from caches if we're throttling
		// connections to the origin.
		var pri int
		for _, val := range links {
			if strings.HasPrefix(val, "<") {
				endpoint = val[1 : len(val)-1]
			} else if strings.HasPrefix(val, "pri") {
				pri, _ = strconv.Atoi(val[4:])
			}
			// } else if strings.HasPrefix(val, "rel") {
			// 	rel = val[5 : len(val)-1]
			// }
		}

		// Construct the cache objects, getting endpoint and auth requirements from
		// Director
		server, err := url.Parse(endpoint)
		if err != nil {
			log.Errorln("Failed to parse server:", endpoint, "error:", err)
			continue
		}
		serversPrio = append(serversPrio, ServerPriority{URL: server, Priority: pri})
	}

	// Making the assumption that the Link header doesn't already provide the caches
	// in order (even though it probably does). This sorts the caches and ensures
	// we're using the "pri" tag to order them
	sort.Slice(serversPrio, func(i, j int) bool {
		return serversPrio[i].Priority < serversPrio[j].Priority
	})

	servers = make([]*url.URL, len(serversPrio))
	for i, serverPrio := range serversPrio {
		servers[i] = serverPrio.URL
	}

	return
}

// Retrieve federation namespace information for a given URL.
//
// This is the public API; it always queries the director's default
// endpoint.  Internal callers that need embedded cache-mode
// behaviour should use getDirectorInfoForPath instead.
func GetDirectorInfoForPath(ctx context.Context, pUrl *pelican_url.PelicanURL, httpMethod string, token string) (parsedResponse server_structs.DirectorResponse, err error) {
	return getDirectorInfoForPath(ctx, pUrl, httpMethod, token, false)
}

// getDirectorInfoForPath is the internal implementation that accepts a
// cacheMode flag.  When cacheMode is true the director's origin
// endpoint is queried so that the response contains origins rather
// than caches.
func getDirectorInfoForPath(ctx context.Context, pUrl *pelican_url.PelicanURL, httpMethod string, token string, cacheMode bool) (parsedResponse server_structs.DirectorResponse, err error) {
	if pUrl.FedInfo.DirectorEndpoint == "" {
		// A federation whose discovery document names no director has no
		// matchmaking to do: the discovery host serves the objects itself (a
		// standalone origin).  Ask it about the object rather than failing for
		// want of a director.
		//
		// Callers here need the answer before they can act -- `token create`
		// has to know the issuer, and a listing or a stat has no rejected
		// response to learn from -- so this pays for a round trip.  A download
		// does not; see resolveWithoutDirector.
		if pUrl.FedInfo.DiscoveryEndpoint != "" {
			return fetchNamespaceMetadata(ctx, pUrl, httpMethod, token)
		}
		return server_structs.DirectorResponse{},
			errors.Errorf("unable to retrieve information from a Director for object %s because none was found in pelican URL metadata.", pUrl.Path)
	}

	log.Debugln("Will query director at", pUrl.FedInfo.DirectorEndpoint, "for object", pUrl.Path)

	var dirResp *http.Response
	var redirectBodyStr string
	dirResp, redirectBodyStr, err = queryDirector(ctx, httpMethod, pUrl, token, cacheMode)
	if err != nil {
		if (httpMethod == http.MethodPut || httpMethod == http.MethodDelete) && dirResp != nil && dirResp.StatusCode == 405 {
			err = errors.Errorf("the director returned status code 405, indicating it understood the request but could not find an origin that supports PUT/DELETE operations for object: %s.", pUrl.Path)
			return
		} else {
			// If not already a PelicanError, wrap it appropriately
			var pe *error_codes.PelicanError
			if !errors.As(err, &pe) {
				// Check if this is a timeout error and use the appropriate retryable error type
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					err = errors.Wrapf(error_codes.NewTransfer_DirectorTimeoutError(err), "error while querying the director at %s", pUrl.FedInfo.DirectorEndpoint)
				} else {
					err = errors.Wrapf(error_codes.NewContact_DirectorError(err), "error while querying the director at %s", pUrl.FedInfo.DirectorEndpoint)
				}
			} else {
				// If it's already a PelicanError, wrap the context around it
				err = errors.Wrapf(err, "error while querying the director at %s", pUrl.FedInfo.DirectorEndpoint)
			}
			return
		}
	}

	parsedResponse, err = ParseDirectorInfo(dirResp)
	if err != nil {
		err = errors.Wrap(err, "failed to parse director response")
		return
	}

	if redirectBodyStr != "" {
		var redirectInfo server_structs.RedirectInfo
		if jsonErr := json.Unmarshal([]byte(redirectBodyStr), &redirectInfo); jsonErr == nil {
			parsedResponse.RedirectInfo = &redirectInfo
		} else {
			log.Debugf("Failed to parse director redirect info: %v", jsonErr)
		}
	}

	return
}

// resolveForRequest resolves an object for an operation that issues its own
// request and can learn from being refused -- a download, a stat, a listing, a
// cache-age probe.  In a federation with a director this is the ordinary query;
// in one without, it costs no round trip, because the operation's own request
// will carry back whatever a metadata query would have told it.
//
// Operations that cannot recover that way -- `token create`, or a write, which
// would rather know before streaming a body than after being refused -- call
// getDirectorInfoForPath instead.
func resolveForRequest(ctx context.Context, pUrl *pelican_url.PelicanURL, httpMethod string, token string, cacheMode bool) (server_structs.DirectorResponse, error) {
	if pUrl.FedInfo.DirectorEndpoint == "" && pUrl.FedInfo.DiscoveryEndpoint != "" {
		return resolveWithoutDirector(pUrl)
	}
	return getDirectorInfoForPath(ctx, pUrl, httpMethod, token, cacheMode)
}

// resolveWithoutDirector answers a federation that publishes no director,
// without asking anyone.
//
// A director exists to answer two questions: which server holds the object, and
// what credential it wants.  Neither needs asking here.  The server is the
// discovery host from the user's own pelican:// URL -- in a federation of one
// there is no other candidate and no Link headers to sort -- and the credential
// is whatever the origin says when it turns the request down, on headers it
// attaches to that very response.  So a download simply starts, carrying a
// credential if the caller had one, and learns the rest from the answer (see
// canApplyTokenHint); the metadata request that used to precede it was a round
// trip spent asking what the transfer itself was about to reveal.
//
// Only callers that can recover from an incomplete answer may use this.  A
// download can, because a rejection carries the hints and it retries.  A
// listing, a stat, or `token create` cannot -- they have no second chance to
// learn an issuer from -- and go through fetchNamespaceMetadata instead.
//
// Namespace and RequireToken are deliberately left zero.  Guessing them would
// be worse than not knowing: the origin is about to say.
func resolveWithoutDirector(pUrl *pelican_url.PelicanURL) (server_structs.DirectorResponse, error) {
	objectServer, err := url.Parse(pUrl.FedInfo.DiscoveryEndpoint)
	if err != nil {
		return server_structs.DirectorResponse{},
			errors.Wrapf(err, "failed to parse the federation's discovery endpoint %s as an object server", pUrl.FedInfo.DiscoveryEndpoint)
	}
	log.Debugln("Federation publishes no director; addressing", pUrl.Path, "to the object server at", objectServer.Host)

	return server_structs.DirectorResponse{
		ObjectServers: []*url.URL{objectServer},
		XPelNsHdr: server_structs.XPelNs{
			// An origin serving its own namespace is also its own listing
			// endpoint, which is what it advertises as collections-url when
			// asked; a recursive transfer needs that before it starts.
			CollectionsUrl: objectServer,
		},
	}, nil
}

// fetchNamespaceMetadata asks the origin what it would tell a director about a
// namespace: which prefix the path falls under, whether it wants a credential,
// and which issuer mints one.
//
// This costs a round trip, and most callers should not need one -- a transfer
// learns the same thing from the response to the request it was going to make
// anyway (see resolveWithoutDirector).  It is for callers with nothing to learn
// from: `token create` has to know the issuer before it mints anything, and a
// write wants it before streaming a body rather than after being refused.
//
// A HEAD collects it, and works whether the object turns out to be public
// (200), protected (401/403), or absent (404) -- the metadata describes the
// namespace, not the object.
//
// This asks nothing new of the client's trust: the server being questioned is
// the host from the user's own pelican:// URL, which already served the
// discovery document that everything else in this federation is believed on
// the strength of.
func fetchNamespaceMetadata(ctx context.Context, pUrl *pelican_url.PelicanURL, httpMethod string, token string) (parsedResponse server_structs.DirectorResponse, err error) {
	objectServer, err := url.Parse(pUrl.FedInfo.DiscoveryEndpoint)
	if err != nil {
		return server_structs.DirectorResponse{},
			errors.Wrapf(err, "failed to parse the federation's discovery endpoint %s as an object server", pUrl.FedInfo.DiscoveryEndpoint)
	}
	log.Debugln("Federation publishes no director; resolving", pUrl.Path, "against the object server at", objectServer.Host)

	probeUrl := *objectServer
	probeUrl.Path = pUrl.Path
	probeUrl.RawQuery = pUrl.RawQuery

	// HEAD regardless of the caller's verb: this is a metadata lookup, and a
	// GET would start streaming an object the caller has not asked for yet.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeUrl.String(), nil)
	if err != nil {
		return server_structs.DirectorResponse{}, errors.Wrap(err, "failed to build a metadata request for the object server")
	}
	req.Header.Set("User-Agent", getUserAgent(""))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Follow redirects, unlike a director query: gin answers a request for a
	// bare namespace prefix (what `object ls pelican://host/ns` asks for) with
	// its own trailing-slash redirect, and that reply carries no metadata.  Only
	// within this host, though -- the reply decides which issuer the client will
	// authenticate against, and the bearer token above rides along on every hop
	// Go considers same-origin, so a redirect elsewhere would both hand that
	// token to a third party and let it name the issuer.
	client := *config.GetClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !strings.EqualFold(req.URL.Host, objectServer.Host) {
			return errors.Errorf("object server at %s redirected namespace metadata to another host (%s); refusing to follow",
				objectServer.Host, req.URL.Host)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return server_structs.DirectorResponse{},
			errors.Wrapf(error_codes.NewContact_DirectorError(err), "error while querying the object server at %s", objectServer.Host)
	}
	defer resp.Body.Close()
	// The body is metadata-free; drain it so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	parsedResponse, err = ParseDirectorInfo(resp)
	if err != nil {
		return server_structs.DirectorResponse{}, errors.Wrap(err, "failed to parse the object server's namespace metadata")
	}
	// Whatever the object's own status, a server that serves the namespace
	// describes it in these headers.  Their absence means something answered
	// that is not a Pelican object server -- a proxy error page, say -- and
	// continuing would start a transfer with no idea whether it needs a token.
	if parsedResponse.XPelNsHdr.Namespace == "" {
		return server_structs.DirectorResponse{},
			errors.Errorf("the server at %s returned no namespace metadata for %s (HTTP %d); it does not appear to serve this federation",
				objectServer.Host, pUrl.Path, resp.StatusCode)
	}

	// The object server named itself by answering; a federation of one has no
	// other candidate, and no Link headers to sort.
	parsedResponse.ObjectServers = []*url.URL{objectServer}
	return parsedResponse, nil
}

// Given the Director response, parse the headers and construct the ordered list of object
// servers.
func ParseDirectorInfo(dirResp *http.Response) (server_structs.DirectorResponse, error) {
	var xPelNs server_structs.XPelNs
	if err := (&xPelNs).ParseRawHeader(&dirResp.Header); err != nil {
		// Only suppress the specific "header not present" error.  If the header
		// exists but is malformed, return an error so the caller knows something
		// is wrong rather than silently continuing with default values.
		errStr := err.Error()
		if strings.Contains(errStr, "No ") && strings.Contains(errStr, "header found") {
			// Header not present — treat as non-fatal and default to empty namespace.
			log.Debugf("Director response missing %s header (non-fatal): %v", xPelNs.GetName(), err)
		} else {
			// Header present but malformed — return error.
			return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelNs.GetName())
		}
	} else {
		log.Debugln("Namespace path constructed from Director:", xPelNs.Namespace)
	}

	var xPelAuth server_structs.XPelAuth
	if err := (&xPelAuth).ParseRawHeader(&dirResp.Header); err != nil {
		return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelAuth.GetName())
	}

	var xPelTokGen server_structs.XPelTokGen
	if err := (&xPelTokGen).ParseRawHeader(&dirResp.Header); err != nil {
		return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelTokGen.GetName())
	}

	sortedObjectServers, err := parseServersFromDirectorResponse(dirResp)
	if err != nil {
		return server_structs.DirectorResponse{}, errors.Wrap(err, "failed to determine object servers from Director's response")
	}

	// If no Link headers were present but the response has a Location
	// header (bare 307 redirect), use the Location URL as the sole
	// object server.  This handles director health-test redirects that
	// send a plain redirect without the standard X-Pelican-* headers.
	if len(sortedObjectServers) == 0 {
		if location := dirResp.Header.Get("Location"); location != "" {
			if locUrl, parseErr := url.Parse(location); parseErr == nil {
				sortedObjectServers = []*url.URL{locUrl}
				log.Debugf("No Link headers in director response; using Location as object server: %s", location)
			}
		}
	}

	return server_structs.DirectorResponse{
		ObjectServers: sortedObjectServers,
		XPelAuthHdr:   xPelAuth,
		XPelNsHdr:     xPelNs,
		XPelTokGenHdr: xPelTokGen,
	}, nil
}
