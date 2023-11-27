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

package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
)

func MakeRequest(url string, method string, data map[string]interface{}, headers map[string]string) ([]byte, error) {
	payload, _ := json.Marshal(data)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
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

func GetIssuerURL() (*url.URL, error) {
	// If Origin.Mode is set to anything that isn't "posix" or "", assume we're running a plugin and
	// that the origin's issuer URL actually uses the same port as OriginUI instead of XRootD. This is
	// because under that condition, keys are being served by the Pelican process instead of by XRootD
	originMode := param.Origin_Mode.GetString()
	if originMode == "" || originMode == "posix" {
		// In this case, we use the default set up by config.go, which uses the xrootd port
		issuerUrl, err := url.Parse(param.Origin_Url.GetString())
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse the issuer URL from the default origin URL")
		}
		return issuerUrl, nil
	} else {
		// to parse the URL, we first must prepend it with a scheme
		issuerUrlStr := "https://" + param.Server_ExternalWebUrl.GetString()

		issuerUrl, err := url.Parse(issuerUrlStr)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse the issuer URL generated using ComputeExternalAddress")
		}

		return issuerUrl, nil
	}
}
