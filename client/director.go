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
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	namespaces "github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Given the Director response, create the ordered list of caches
// and store it as namespace.SortedDirectorCaches
func CreateNsFromDirectorResp(dirResp *http.Response) (namespace namespaces.Namespace, err error) {
	pelicanNamespaceHdr := dirResp.Header.Values("X-Pelican-Namespace")
	if len(pelicanNamespaceHdr) == 0 {
		err = errors.New("Pelican director did not include mandatory X-Pelican-Namespace header in response")
		return
	}
	xPelicanNamespace := utils.HeaderParser(pelicanNamespaceHdr[0])
	namespace.Path = xPelicanNamespace["namespace"]
	namespace.UseTokenOnRead, _ = strconv.ParseBool(xPelicanNamespace["require-token"])
	namespace.ReadHTTPS, _ = strconv.ParseBool(xPelicanNamespace["readhttps"])
	namespace.DirListHost = xPelicanNamespace["collections-url"]

	xPelicanAuthorization := []string{} // map of header to x - single entry - want to create an array for issuer
	if len(dirResp.Header.Values("X-Pelican-Authorization")) > 0 {
		//For each entry,(which is an array of issuer=0)
		//So it's a map entry - HeaderParser returns a max entry
		//We want to appen the value
		for _, authEntry := range dirResp.Header.Values("X-Pelican-Authorization") {
			parsedEntry := utils.HeaderParser(authEntry)
			xPelicanAuthorization = append(xPelicanAuthorization, parsedEntry["issuer"])
		}
		namespace.Issuer = xPelicanAuthorization
	}

	var xPelicanTokenGeneration map[string]string
	if len(dirResp.Header.Values("X-Pelican-Token-Generation")) > 0 {
		xPelicanTokenGeneration = utils.HeaderParser(dirResp.Header.Values("X-Pelican-Token-Generation")[0])

		// Instantiate the cred gen struct
		namespace.CredentialGen = &namespaces.CredentialGeneration{}

		// We wind up with a duplicate issuer here as the encapsulating ns also encodes this
		issuer := xPelicanTokenGeneration["issuer"]
		namespace.CredentialGen.Issuer = &issuer

		base_path := xPelicanTokenGeneration["base-path"]
		namespace.CredentialGen.BasePath = &base_path

		if max_scope_depth, exists := xPelicanTokenGeneration["max-scope-depth"]; exists {
			max_scope_depth_int, err := strconv.Atoi(max_scope_depth)
			if err != nil {
				log.Debugln("Server sent an invalid max scope depth; ignoring:", max_scope_depth)
			} else {
				namespace.CredentialGen.MaxScopeDepth = &max_scope_depth_int
			}
		}

		strategy := xPelicanTokenGeneration["strategy"]
		namespace.CredentialGen.Strategy = &strategy

		// The Director only returns a vault server if the strategy is vault.
		if vs, exists := xPelicanTokenGeneration["vault-server"]; exists {
			namespace.CredentialGen.VaultServer = &vs
		}
	}

	// Create the caches slice
	namespace.SortedDirectorCaches, err = getCachesFromDirectorResponse(dirResp, namespace.UseTokenOnRead || namespace.ReadHTTPS)
	if err != nil {
		log.Errorln("Unable to construct ordered cache list:", err)
		return
	}
	log.Debugln("Namespace path constructed from Director:", namespace.Path)

	return
}

// Make a request to the director for a given verb/resource; return the
// HTTP response object only if a 307 is returned.
func queryDirector(ctx context.Context, verb, sourcePath, directorUrl string) (resp *http.Response, err error) {
	resourceUrl := directorUrl + sourcePath
	// Here we use http.Transport to prevent the client from following the director's
	// redirect. We use the Location url elsewhere (plus we still need to do the token
	// dance!)
	var client *http.Client
	tr := config.GetTransport()
	client = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, verb, resourceUrl, nil)
	if err != nil {
		log.Errorln("Failed to create an HTTP request:", err)
		return nil, err
	}

	// Include the Client's version as a User-Agent header. The Director will decide
	// if it supports the version, and provide an error message in the case that it
	// cannot.
	req.Header.Set("User-Agent", getUserAgent(""))

	// Perform the HTTP request
	resp, err = client.Do(req)

	if err != nil {
		log.Errorln("Failed to get response from the director:", err)
		return
	}

	defer resp.Body.Close()
	log.Tracef("Director's response: %#v\n", resp)
	// Check HTTP response -- should be 307 (redirect), else something went wrong
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("Failed to read the body from the director response:", err)
		return resp, err
	}
	errMsg := string(body)
	// The Content-Type will be alike "application/json; charset=utf-8"
	if utils.HasContentType(resp, "application/json") {
		var respErr server_structs.SimpleApiResp
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			log.Errorln("Failed to unmarshal the director's JSON response:", err)
			return resp, unmarshalErr
		}
		// In case we have old director returning "error": "message content"
		if respErr.Msg != "" {
			errMsg = respErr.Msg
		}
	}

	// If we get a 404, the director will hopefully tell us why. It might be that the namespace doesn't exist
	if resp.StatusCode == 404 && verb == "PROPFIND" {
		// If we get a 404 response from a PROPFIND, we are likely working with an old director so we should return a response
		return resp, errors.New("404: " + errMsg)
	} else if resp.StatusCode == 404 {
		// If we get a 404 response when we are not doing a PROPFIND, just return the 404 error without a response
		return nil, errors.New("404: " + errMsg)
	} else if resp.StatusCode == http.StatusMethodNotAllowed && verb == "PROPFIND" {
		// If we get a 405 with a PROPFIND, the client will handle it
		return
	} else if resp.StatusCode == http.StatusMultiStatus && verb == "PROPFIND" {
		// This is a director >7.9 proxy the PROPFIND response instead of redirect to the origin
		return
	} else if resp.StatusCode != 307 {
		return resp, errors.Errorf("%d: %s", resp.StatusCode, errMsg)
	}

	return
}

func getCachesFromDirectorResponse(resp *http.Response, needsToken bool) (caches []namespaces.DirectorCache, err error) {
	// Get the Link header
	linkHeader := resp.Header.Values("Link")
	if len(linkHeader) == 0 {
		return []namespaces.DirectorCache{}, nil
	}

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
		var cache namespaces.DirectorCache
		cache.AuthedReq = needsToken
		cache.EndpointUrl = endpoint
		cache.Priority = pri
		caches = append(caches, cache)
	}

	// Making the assumption that the Link header doesn't already provide the caches
	// in order (even though it probably does). This sorts the caches and ensures
	// we're using the "pri" tag to order them
	sort.Slice(caches, func(i, j int) bool {
		val1 := caches[i].Priority
		val2 := caches[j].Priority
		return val1 < val2
	})

	return caches, err
}

// NewTransferDetails creates the TransferDetails struct with the given cache
func newTransferDetailsUsingDirector(cache namespaces.DirectorCache, opts transferDetailsOptions) []transferAttemptDetails {
	details := make([]transferAttemptDetails, 0)
	cacheEndpoint := cache.EndpointUrl

	// Form the URL
	cacheURL, err := url.Parse(cacheEndpoint)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Scheme == "unix" && cacheURL.Host != "" {
		cacheURL.Path = path.Clean("/" + path.Join(cacheURL.Host, cacheURL.Path))
	} else if cacheURL.Scheme != "unix" && cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cacheEndpoint
		cacheURL.Path = ""
		cacheURL.Scheme = ""
		cacheURL.Opaque = ""
	}
	if opts.NeedsToken {
		// Unless we're using the local Unix domain socket cache, force HTTPS
		if cacheURL.Scheme != "unix" {
			cacheURL.Scheme = "https"
			if !hasPort(cacheURL.Host) {
				// Add port 8444 and 8443
				urlCopy := *cacheURL
				urlCopy.Host += ":8444"
				details = append(details, transferAttemptDetails{
					Url:        &urlCopy,
					Proxy:      false,
					PackOption: opts.PackOption,
				})
				// Strip the port off and add 8443
				cacheURL.Host = cacheURL.Host + ":8443"
			}
		}
		det := transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if cacheURL.Scheme == "unix" {
			det.UnixSocket = cacheURL.Path
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, det)
	} else if cacheURL.Scheme == "" || cacheURL.Scheme == "http" {
		// Assume a transfer not needing a token and not specifying a scheme is HTTP
		// WARNING: This is legacy code; we should always specify a scheme
		cacheURL.Scheme = "http"
		if !hasPort(cacheURL.Host) {
			cacheURL.Host += ":8000"
		}
		isProxyEnabled := isProxyEnabled()
		details = append(details, transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      isProxyEnabled,
			PackOption: opts.PackOption,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, transferAttemptDetails{
				Url:        cacheURL,
				Proxy:      false,
				PackOption: opts.PackOption,
			})
		}
	} else {
		// A non-HTTP scheme is specified and a token is not needed; this wasn't possible
		// in the legacy cases.  Simply use the provided config
		det := transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		}
		if cacheURL.Scheme == "unix" {
			det.UnixSocket = cacheURL.Path
		}
		details = append(details, det)
	}

	return details
}
