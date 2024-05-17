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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_utils"
)

// Run one object transfer to a cache from the director. Since director-based cache tests require a different
// workflow than the origin tests. We can't reuse server_utils.RunTests(), but we want to keep common
// pieces together
func runCacheTest(ctx context.Context, cacheUrl url.URL) error {
	nowStr := time.Now().Format(time.RFC3339)
	dirMonPath := path.Join(server_utils.MonitoringBaseNs, "directorTest")
	cacheUrl = *cacheUrl.JoinPath(path.Join(dirMonPath, server_utils.DirectorTest.String()+"-"+nowStr+".txt"))
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, "GET", cacheUrl.String(), nil)
	if err != nil {
		urlErr, ok := err.(*url.Error)
		if ok && urlErr.Err == context.Canceled {
			// Shouldn't return error if the error is due to context being cancelled
			return nil
		}
		return errors.Wrap(err, "failed to create an HTTP request")
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request to cache for the test file")
	}
	byteBody, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read response body. Response status code is "+res.Status)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("cache responses with non-200 status code. Body is %s", string(byteBody))
	}
	strBody := string(byteBody)

	if strings.TrimSuffix(strBody, "\n") == server_utils.DirectorTestBody {
		return nil
	} else {
		return fmt.Errorf("cache response file does not match expectation. Expected:%s, Got:%s", server_utils.DirectorTestBody, strBody)
	}
}
