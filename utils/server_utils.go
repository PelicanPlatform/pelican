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

	"github.com/pelicanplatform/pelican/config"
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
