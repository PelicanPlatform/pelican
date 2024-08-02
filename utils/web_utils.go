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

package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

// MakeRequest makes an http request with our custom http client. It acts similarly to the http.NewRequest but
// it only takes json as the request data.
func MakeRequest(ctx context.Context, url string, method string, data map[string]interface{}, headers map[string]string) ([]byte, error) {
	payload, _ := json.Marshal(data)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, val := range headers {
		req.Header.Set(key, val)
	}
	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	body, _ := io.ReadAll(resp.Body)
	if method == "POST" && resp.StatusCode != 201 && resp.StatusCode != 200 {
		return body, errors.Errorf("The POST attempt to %s resulted in status code %d", url, resp.StatusCode)
	} else if method != "POST" && resp.StatusCode != 200 {
		return body, errors.Errorf("The %s attempt to %s replied with status code %d", method, url, resp.StatusCode)
	}

	return body, nil
}

// Copy headers from proxied src to dst, removing those defined
// by HTTP as "hop-by-hop" and not to be forwarded (see
// https://www.rfc-editor.org/rfc/rfc9110#field.connection)
func CopyHeader(dst, src http.Header) {
	hopByHop := make(map[string]bool)
	hopByHop["Proxy-Connection"] = true
	hopByHop["Keep-Alive"] = true
	hopByHop["TE"] = true
	hopByHop["Transfer-Encoding"] = true
	hopByHop["Upgrade"] = true
	for _, value := range src["Connection"] {
		hopByHop[http.CanonicalHeaderKey(value)] = true
	}
	for headerName, headerValues := range src {
		if hopByHop[headerName] {
			continue
		}
		for _, value := range headerValues {
			dst.Add(headerName, value)
		}
	}
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

// Determine whether the response `content-type` includes a
// server-acceptable mime-type
//
// Failure should yield an HTTP 415 (`http.StatusUnsupportedMediaType`)
//
// Source: https://gist.github.com/rjz/fe283b02cbaa50c5991e1ba921adf7c9
func HasContentType(r *http.Response, mimetype string) bool {
	contentType := r.Header.Get("Content-type")
	if contentType == "" {
		return mimetype == "application/octet-stream"
	}

	for _, v := range strings.Split(contentType, ",") {
		t, _, err := mime.ParseMediaType(v)
		if err != nil {
			break
		}
		if t == mimetype {
			return true
		}
	}
	return false
}

func GetJwks(ctx context.Context, location string) (jwk.Set, error) {
	if location == "" {
		return nil, errors.New("jwks location is empty")
	}
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("request failed with response code %d and response body: %s", res.StatusCode, string(bodyByte))
	}
	if len(bodyByte) == 0 {
		return nil, fmt.Errorf("request failed with response returns 200 but with empty response body")
	}
	key, err := jwk.Parse(bodyByte)
	if err != nil {
		return nil, err
	} else {
		return key, nil
	}
}

// Equivalent to c.ClientIP() except that it returns netip.Addr instead of net.IP
//
// If the IP string is invalid, it returns netip.Addr{}. Use netip.Addr.ISValid() to
// check the validity of the returned value
func ClientIPAddr(c *gin.Context) netip.Addr {
	ipStr := c.ClientIP()
	ip, _ := netip.ParseAddr(ipStr)
	return ip
}
