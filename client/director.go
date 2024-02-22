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

package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	namespaces "github.com/pelicanplatform/pelican/namespaces"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type directorResponse struct {
	Error string `json:"error"`
}

// Simple parser to that takes a "values" string from a header and turns it
// into a map of key/value pairs
func HeaderParser(values string) (retMap map[string]string) {
	retMap = map[string]string{}

	// Some headers might not have values, such as the
	// X-OSDF-Authorization header when the resource is public
	if values == "" {
		return
	}

	mapPairs := strings.Split(values, ",")
	for _, pair := range mapPairs {
		// Remove any unwanted spaces
		pair = strings.ReplaceAll(pair, " ", "")

		// Break out key/value pairs and put in the map
		split := strings.Split(pair, "=")
		retMap[split[0]] = split[1]
	}

	return retMap
}

// Given the Director response, create the ordered list of caches
// and store it as namespace.SortedDirectorCaches
func CreateNsFromDirectorResp(dirResp *http.Response) (namespace namespaces.Namespace, err error) {
	pelicanNamespaceHdr := dirResp.Header.Values("X-Pelican-Namespace")
	if len(pelicanNamespaceHdr) == 0 {
		err = errors.New("Pelican director did not include mandatory X-Pelican-Namespace header in response")
		return
	}
	xPelicanNamespace := HeaderParser(pelicanNamespaceHdr[0])
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
			parsedEntry := HeaderParser(authEntry)
			xPelicanAuthorization = append(xPelicanAuthorization, parsedEntry["issuer"])
		}
		namespace.Issuer = xPelicanAuthorization
	}

	var xPelicanTokenGeneration map[string]string
	if len(dirResp.Header.Values("X-Pelican-Token-Generation")) > 0 {
		xPelicanTokenGeneration = HeaderParser(dirResp.Header.Values("X-Pelican-Token-Generation")[0])

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
	namespace.SortedDirectorCaches, err = GetCachesFromDirectorResponse(dirResp, namespace.UseTokenOnRead || namespace.ReadHTTPS)
	if err != nil {
		log.Errorln("Unable to construct ordered cache list:", err)
		return
	}
	log.Debugln("Namespace path constructed from Director:", namespace.Path)

	return
}

// Make a request to the director for a given verb/resource; return the
// HTTP response object only if a 307 is returned.
func queryDirector(verb, source, directorUrl string) (resp *http.Response, err error) {
	resourceUrl := directorUrl + source
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

	req, err := http.NewRequest(verb, resourceUrl, nil)
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
	log.Debugln("Director's response:", resp)

	// Check HTTP response -- should be 307 (redirect), else something went wrong
	body, _ := io.ReadAll(resp.Body)

	// If we get a 404, the director will hopefully tell us why. It might be that the namespace doesn't exist
	if resp.StatusCode == 404 {
		return nil, errors.New("404: " + string(body))
	} else if resp.StatusCode != 307 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return nil, errors.Wrap(unmarshalErr, "Could not unmarshall the director's response")
		}
		return resp, errors.Errorf("The director reported an error: %s", respErr.Error)
	}

	return
}

func GetCachesFromDirectorResponse(resp *http.Response, needsToken bool) (caches []namespaces.DirectorCache, err error) {
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
func NewTransferDetailsUsingDirector(cache namespaces.DirectorCache, opts transferDetailsOptions) []transferAttemptDetails {
	details := make([]transferAttemptDetails, 0)
	cacheEndpoint := cache.EndpointUrl

	// Form the URL
	cacheURL, err := url.Parse(cacheEndpoint)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cacheEndpoint
		cacheURL.Path = ""
		cacheURL.Scheme = ""
		cacheURL.Opaque = ""
	}
	log.Debugf("Parsed Cache: %s", cacheURL.String())
	if opts.NeedsToken {
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
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, transferAttemptDetails{
			Url:        cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		})
	} else {
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
	}

	return details
}
