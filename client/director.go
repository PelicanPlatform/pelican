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
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Make a request to the director for a given verb/resource; return the
// HTTP response object only if a 307 is returned.
func queryDirector(ctx context.Context, verb string, pUrl *pelican_url.PelicanURL, token string) (resp *http.Response, err error) {
	resourceUrl, err := url.Parse(pUrl.FedInfo.DirectorEndpoint)
	if err != nil {
		log.Errorln("Failed to parse the director URL:", err)
		return nil, err
	}
	resourceUrl.Path = pUrl.Path
	resourceUrl.RawQuery = pUrl.RawQuery

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

	req, err := http.NewRequestWithContext(ctx, verb, resourceUrl.String(), nil)
	if err != nil {
		log.Errorln("Failed to create an HTTP request:", err)
		return nil, err
	}

	// Include the Client's version as a User-Agent header. The Director will decide
	// if it supports the version, and provide an error message in the case that it
	// cannot.
	req.Header.Set("User-Agent", getUserAgent(""))

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

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

	if resp.StatusCode == http.StatusMultiStatus && verb == "PROPFIND" {
		// This is a director >7.9 proxy the PROPFIND response instead of redirect to the origin
		return
	} else if resp.StatusCode != 307 {
		return resp, errors.Errorf("%d: %s", resp.StatusCode, errMsg)
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
func GetDirectorInfoForPath(ctx context.Context, pUrl *pelican_url.PelicanURL, isPut bool, token string) (parsedResponse server_structs.DirectorResponse, err error) {
	if pUrl.FedInfo.DirectorEndpoint == "" {
		return server_structs.DirectorResponse{},
			errors.Errorf("unable to retrieve information from a Director for object %s because none was found in pelican URL metadata.", pUrl.Path)
	}

	log.Debugln("Will query director at", pUrl.FedInfo.DirectorEndpoint, "for object", pUrl.Path)
	verb := "GET"
	if isPut {
		verb = "PUT"
	}

	var dirResp *http.Response
	dirResp, err = queryDirector(ctx, verb, pUrl, token)
	if err != nil {
		if isPut && dirResp != nil && dirResp.StatusCode == 405 {
			err = errors.New("error 405: No writeable origins were found")
			return
		} else {
			err = errors.Wrapf(err, "error while querying the director at %s", pUrl.FedInfo.DirectorEndpoint)
			return
		}
	}

	parsedResponse, err = ParseDirectorInfo(dirResp)
	if err != nil {
		err = errors.Wrap(err, "failed to parse director response")
		return
	}

	return
}

// Given the Director response, parse the headers and construct the ordered list of object
// servers.
func ParseDirectorInfo(dirResp *http.Response) (server_structs.DirectorResponse, error) {
	var xPelNs server_structs.XPelNs
	if err := (&xPelNs).ParseRawResponse(dirResp); err != nil {
		return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelNs.GetName())
	}
	log.Debugln("Namespace path constructed from Director:", xPelNs.Namespace)

	var xPelAuth server_structs.XPelAuth
	if err := (&xPelAuth).ParseRawResponse(dirResp); err != nil {
		return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelAuth.GetName())
	}

	var xPelTokGen server_structs.XPelTokGen
	if err := (&xPelTokGen).ParseRawResponse(dirResp); err != nil {
		return server_structs.DirectorResponse{}, errors.Wrapf(err, "failed to parse %s header", xPelTokGen.GetName())
	}

	sortedObjectServers, err := parseServersFromDirectorResponse(dirResp)
	if err != nil {
		return server_structs.DirectorResponse{}, errors.Wrap(err, "failed to determine object servers from Director's response")
	}

	return server_structs.DirectorResponse{
		ObjectServers: sortedObjectServers,
		XPelAuthHdr:   xPelAuth,
		XPelNsHdr:     xPelNs,
		XPelTokGenHdr: xPelTokGen,
	}, nil
}
