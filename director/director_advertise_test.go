//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package director_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Test for a director disappearing
func TestDirectorShutdown(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	var listDirectorCount atomic.Int32
	dirAd := &server_structs.DirectorAd{}
	dirAd.Initialize("fake-director")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Debugln("Fake director received", req.Method, "for path", req.URL.Path)
		if req.Method == "GET" && req.URL.Path == "/api/v1.0/director/directors" {
			newVal := listDirectorCount.Add(1)
			ads := make([]server_structs.DirectorAd, 0, 1)
			if newVal == 1 {
				ads = append(ads, *dirAd)
			}
			buf, err := json.Marshal(ads)
			require.NoError(t, err)
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(buf)
			require.NoError(t, err)
		} else if req.Method == "POST" {
			_, err := io.Copy(io.Discard, req.Body)
			assert.NoError(t, err)
			req.Body.Close()
			w.WriteHeader(http.StatusOK)
		}
	}))
	dirAd.AdvertiseUrl = ts.URL
	require.NoError(t, param.Set(param.Server_DirectorUrls.GetName(), ts.URL))
	defer ts.Close()

	require.NoError(t, param.Set(param.Server_AdLifetime.GetName(), "100ms"))
	fed_test_utils.NewFedTest(t, "")
	time.Sleep(time.Duration(110 * time.Millisecond))
	ads := server_utils.GetDirectorAds()
	assert.Equal(t, 1, len(ads), "Unexpected directors showing up in response: %+v", ads)
}

// Significantly decrease the ad lifetime; ensure forwarding from director and
// multiple servers works.
func TestExpirationDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	var listDirectorCount atomic.Int32
	var directorPostCount atomic.Int32
	var originPostCount atomic.Int32
	dirAd := &server_structs.DirectorAd{}
	dirAd.Initialize("fake-director")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Debugln("Fake director received", req.Method, "for path", req.URL.Path)
		if req.Method == "GET" && req.URL.Path == "/api/v1.0/director/directors" {
			listDirectorCount.Add(1)
			ads := []server_structs.DirectorAd{*dirAd}
			buf, err := json.Marshal(ads)
			require.NoError(t, err)
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(buf)
			require.NoError(t, err)
		} else if req.Method == "POST" && (req.URL.Path == "/api/v1.0/director/registerDirector") {
			directorPostCount.Add(1)
			w.WriteHeader(http.StatusOK)
		} else if req.Method == "POST" && (req.URL.Path == "/api/v1.0/director/registerOrigin") {
			originPostCount.Add(1)
			w.WriteHeader(http.StatusOK)
		} else if req.Method == "POST" && (req.URL.Path == "/api/v1.0/director/registerCache") {
			w.WriteHeader(http.StatusOK)
		}
	}))
	dirAd.AdvertiseUrl = ts.URL
	require.NoError(t, param.Set(param.Server_DirectorUrls.GetName(), ts.URL))
	defer ts.Close()

	require.NoError(t, param.Set(param.Server_AdLifetime.GetName(), "100ms"))
	fed_test_utils.NewFedTest(t, "")
	time.Sleep(time.Duration(500 * time.Millisecond))
	assert.Less(t, 10, int(listDirectorCount.Load()))
	log.Debugln("Fake director received", directorPostCount.Load(), "ads from the director")
	assert.Less(t, 10, int(directorPostCount.Load()))
	log.Debugln("Fake director received", originPostCount.Load(), "ads from the origin")
	assert.Less(t, 10, int(originPostCount.Load()))
}

func TestForwardDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	var listDirectorCount atomic.Int32
	var adPostCount atomic.Int32
	dirAd := &server_structs.DirectorAd{}
	dirAd.Initialize("fake-director")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Debugln("Fake director received", req.Method, "for path", req.URL.Path)
		if req.Method == "GET" && req.URL.Path == "/api/v1.0/director/directors" {
			listDirectorCount.Add(1)
			ads := []server_structs.DirectorAd{*dirAd}
			buf, err := json.Marshal(ads)
			require.NoError(t, err)
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(buf)
			require.NoError(t, err)
		} else if req.Method == "POST" && (req.URL.Path == "/api/v1.0/director/registerDirector" || req.URL.Path == "/api/v1.0/director/registerOrigin" || req.URL.Path == "/api/v1.0/director/registerCache") {
			adPostCount.Add(1)
			_, err := io.Copy(io.Discard, req.Body)
			assert.NoError(t, err)
			req.Body.Close()
			w.WriteHeader(http.StatusOK)
		}
	}))
	dirAd.AdvertiseUrl = ts.URL
	require.NoError(t, param.Set(param.Server_DirectorUrls.GetName(), ts.URL))
	defer ts.Close()

	fed_test_utils.NewFedTest(t, "")
	assert.Equal(t, 1, int(listDirectorCount.Load()))
	assert.Equal(t, 7, int(adPostCount.Load()))
}
