//go:build !windows

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

// TestDirectorShutdown verifies that a peer director which was previously
// known disappears from directorEndpoints after it shuts down (connection
// refused).
func TestDirectorShutdown(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	dirAd := &server_structs.DirectorAd{}
	dirAd.Initialize("fake-director")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Debugln("Fake director received", req.Method, "for path", req.URL.Path)
		if req.Method == "GET" && req.URL.Path == "/api/v1.0/director/directors" {
			// Set Expiration dynamically per-response so the entry in directorAds
			// has a short, finite lifetime. Without this, Initialize above stamps
			// the ad with the default expiration time (15m).
			adCopy := *dirAd
			adCopy.Expiration = time.Now().Add(param.Server_AdLifetime.GetDuration())
			buf, err := json.Marshal([]server_structs.DirectorAd{adCopy})
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
	require.NoError(t, param.Server_DirectorUrls.Set([]string{ts.URL}))
	defer ts.Close()

	// AdLifetime of 300ms: discovery ticker fires every ~100ms; the
	// fake-director ad expires after 300ms, giving the test comfortable
	// margins.
	require.NoError(t, param.Server_AdLifetime.SetString("300ms"))
	fed_test_utils.NewFedTest(t, "")

	// Confirm the fake director's ad is visible in directorEndpoints
	// before simulating its shutdown.
	require.Eventually(t, func() bool {
		for _, ad := range server_utils.GetDirectorAds() {
			if ad.AdvertiseUrl == ts.URL {
				return true
			}
		}
		return false
	}, 10*time.Second, 50*time.Millisecond,
		"fake director should appear in directorEndpoints after initial contact")

	// Close the listener to simulate a real peer shutdown (connection refused).
	ts.Close()

	// After shutdown, every subsequent discovery attempt for ts.URL will
	// fail at the transport level.
	require.Eventually(t, func() bool {
		for _, ad := range server_utils.GetDirectorAds() {
			if ad.AdvertiseUrl == ts.URL {
				return false
			}
		}
		return true
	}, 10*time.Second, 50*time.Millisecond,
		"fake director should disappear from directorEndpoints after shutdown")

	// Only the local director's own self-entry should remain.
	ads := server_utils.GetDirectorAds()
	assert.Equal(t, 1, len(ads), "only local director should remain after peer shutdown, got: %+v", ads)
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
	require.NoError(t, param.Server_DirectorUrls.Set([]string{ts.URL}))
	defer ts.Close()

	require.NoError(t, param.Server_AdLifetime.SetString("100ms"))
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
	var registerOriginCount, registerCacheCount, registerDirectorCount atomic.Int32
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
		} else if req.Method == "POST" {
			switch req.URL.Path {
			case "/api/v1.0/director/registerOrigin":
				registerOriginCount.Add(1)
			case "/api/v1.0/director/registerCache":
				registerCacheCount.Add(1)
			case "/api/v1.0/director/registerDirector":
				registerDirectorCount.Add(1)
			default:
				return
			}
			_, err := io.Copy(io.Discard, req.Body)
			assert.NoError(t, err)
			req.Body.Close()
			w.WriteHeader(http.StatusOK)
		}
	}))
	dirAd.AdvertiseUrl = ts.URL
	require.NoError(t, param.Server_DirectorUrls.Set([]string{ts.URL}))
	defer ts.Close()

	fed_test_utils.NewFedTest(t, "")
	assert.Equal(t, 1, int(listDirectorCount.Load()))
	// The director forwards each server ad it receives to peer directors.
	// The origin (2) and cache (1) forwards are deterministic. The
	// director's own ad, however, is re-advertised on a periodic timer, so
	// the number of registerDirector forwards that land within the
	// fed-test startup window races with how long startup takes: a fast
	// run sees 4, a slower run sees 5+. Asserting an exact grand total
	// (previously `== 7`) is therefore timing-flaky and fails
	// intermittently on slow CI runners — the more so as unrelated startup
	// work (migrations, bootstrap) grows. Assert the deterministic
	// per-type forwards exactly and the periodic director forward as a
	// lower bound, which still verifies forwarding happens without
	// depending on wall-clock timing.
	assert.Equal(t, 2, int(registerOriginCount.Load()), "origin ad should be forwarded to the peer director")
	assert.Equal(t, 1, int(registerCacheCount.Load()), "cache ad should be forwarded to the peer director")
	assert.GreaterOrEqual(t, int(registerDirectorCount.Load()), 4, "director ad should be forwarded to the peer director")
}
