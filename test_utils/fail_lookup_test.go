/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package test_utils

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

func TestFailLookupsOf(t *testing.T) {
	t.Cleanup(config.ResetConfig)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)

	// localhost resolves for real, so a "no such host" can only come from
	// the injected dialer, never from a resolver.
	FailLookupsOf(t, "localhost")
	client := &http.Client{Transport: config.GetTransport()}

	_, err = client.Get("http://localhost:" + port + "/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lookup localhost: no such host")
	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	assert.True(t, dnsErr.IsNotFound)

	resp, err := client.Get(srv.URL)
	require.NoError(t, err, "other hosts are dialed normally")
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
