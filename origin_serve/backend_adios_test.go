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

package origin_serve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAdiosPathValid(t *testing.T) {
	spec, err := parseAdiosPath("/cfs/www/KSTAR/images.bp/rads/s0n1b0r1")
	require.NoError(t, err)
	assert.Equal(t, "cfs/www/KSTAR/images.bp", spec.bpPath)
	assert.Equal(t, []string{"/rads"}, spec.varnames)
	assert.Equal(t, 0, spec.step)
	assert.Equal(t, 1, spec.stepCount)
	assert.Equal(t, 0, spec.blockID)
	assert.Equal(t, 1, spec.rmOrder)
}

func TestParseAdiosPathBatchValid(t *testing.T) {
	spec, err := parseAdiosPath("/cfs/www/KSTAR/images.bp/rads+te+jsatr/s2n3b4r0")
	require.NoError(t, err)
	assert.Equal(t, []string{"/rads", "/te", "/jsatr"}, spec.varnames)
	assert.Equal(t, 2, spec.step)
	assert.Equal(t, 3, spec.stepCount)
	assert.Equal(t, 4, spec.blockID)
	assert.Equal(t, 0, spec.rmOrder)
}

func TestParseAdiosPathInvalid(t *testing.T) {
	_, err := parseAdiosPath("/cfs/www/KSTAR/images.bp/rads/s0n1b0")
	require.Error(t, err)

	_, err = parseAdiosPath("/cfs/www/KSTAR/notbp/rads/s0n1b0r1")
	require.Error(t, err)

	_, err = parseAdiosPath("/cfs/www/KSTAR/images.bp/rads/s0n1b0r2")
	require.Error(t, err)
}

func TestBuildUpstreamURL(t *testing.T) {
	fs := &adiosFileSystem{
		serviceURL:    "https://example.org/adios",
		storagePrefix: "/cfs/www",
	}

	singleURL := fs.buildUpstreamURL(adiosRequestSpec{
		bpPath:    "KSTAR/images.bp",
		varnames:  []string{"/rads"},
		step:      0,
		stepCount: 1,
		blockID:   0,
		rmOrder:   1,
	})
	assert.Contains(t, singleURL, "?get&")
	assert.Contains(t, singleURL, "RMOrder=1")
	assert.Contains(t, singleURL, "Varname=%2Frads")

	batchURL := fs.buildUpstreamURL(adiosRequestSpec{
		bpPath:    "KSTAR/images.bp",
		varnames:  []string{"/te", "/rads"},
		step:      5,
		stepCount: 2,
		blockID:   7,
		rmOrder:   0,
	})
	assert.Contains(t, batchURL, "?batchget&")
	assert.Contains(t, batchURL, "RMOrder=0")
	assert.Contains(t, batchURL, "NVars=2")
}

func TestAdiosOpenFileSingle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "get", r.URL.RawQuery[:3])
		assert.Equal(t, "1", r.URL.Query().Get("RMOrder"))
		assert.Equal(t, "/rads", r.URL.Query().Get("Varname"))
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    srv.URL,
		StoragePrefix: "/cfs/www",
	})

	f, err := backend.fs.OpenFile(context.Background(), "/KSTAR/images.bp/rads/s0n1b0r1", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(data))
}

func TestAdiosOpenFileBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "batchget", r.URL.RawQuery[:8])
		assert.Equal(t, "0", r.URL.Query().Get("RMOrder"))
		assert.Equal(t, "3", r.URL.Query().Get("NVars"))
		_, _ = w.Write([]byte("batch"))
	}))
	defer srv.Close()

	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    srv.URL,
		StoragePrefix: "/cfs/www",
	})

	f, err := backend.fs.OpenFile(context.Background(), "/KSTAR/images.bp/rads+te+jsatr/s1n2b3r0", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "batch", string(data))
}
