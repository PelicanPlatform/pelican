//go:build server && !windows

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

package launchers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// fakeAdDirector stands in for the director's origin-redirect endpoint. Each
// ad it receives covers only a limited number of lookups before it "expires",
// which models an ad whose (short) lifetime runs out before the check.
type fakeAdDirector struct {
	mu            sync.Mutex
	lookupsPerAd  int
	lookupsLeft   int
	advertised    int
	lookedUpPaths []string
}

func (d *fakeAdDirector) advertise(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.advertised++
	d.lookupsLeft = d.lookupsPerAd
	return nil
}

func (d *fakeAdDirector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lookedUpPaths = append(d.lookedUpPaths, r.URL.Path)
	if d.lookupsLeft > 0 {
		d.lookupsLeft--
		w.Header().Set("Location", "https://origin.example/")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	http.Error(w, `{"status":"error","msg":"no origins found"}`, http.StatusNotFound)
}

func TestAdvertiseOriginBeforeCache(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	// No subtest waits for the timeout; it only bounds a hung test.
	require.NoError(t, param.Server_StartupTimeout.Set(time.Minute))
	prefixes := []string{"/first", "/second"}

	t.Run("ad-visible-on-first-check", func(t *testing.T) {
		dir := &fakeAdDirector{lookupsPerAd: 2}
		svr := httptest.NewServer(dir)
		t.Cleanup(svr.Close)

		require.NoError(t, advertiseOriginBeforeCache(context.Background(), dir.advertise, svr.URL, prefixes))
		assert.Equal(t, 1, dir.advertised)
		assert.Equal(t, []string{"/api/v1.0/director/origin/first", "/api/v1.0/director/origin/second"}, dir.lookedUpPaths)
	})

	t.Run("expired-ad-is-re-sent", func(t *testing.T) {
		// The first ad lapses after one lookup, so the second prefix's check
		// finds nothing; startup must re-advertise rather than fail.
		dir := &fakeAdDirector{lookupsPerAd: 1}
		svr := httptest.NewServer(dir)
		t.Cleanup(svr.Close)
		advertise := func(ctx context.Context) error {
			if err := dir.advertise(ctx); err != nil {
				return err
			}
			dir.mu.Lock()
			defer dir.mu.Unlock()
			if dir.advertised > 1 {
				dir.lookupsLeft = len(prefixes) // later ads live long enough
			}
			return nil
		}

		require.NoError(t, advertiseOriginBeforeCache(context.Background(), advertise, svr.URL, prefixes))
		assert.Equal(t, 2, dir.advertised, "the origin must re-advertise after its ad expired")
	})

	t.Run("gives-up-with-the-directors-answer", func(t *testing.T) {
		// The director never redirects. Startup gives up during the second
		// advertisement (here by cancellation, so no wall-clock deadline is
		// involved); the error must still carry the director's 404 from the
		// completed first round, not the interrupted advertisement's error.
		dir := &fakeAdDirector{lookupsPerAd: 0}
		svr := httptest.NewServer(dir)
		t.Cleanup(svr.Close)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		advertise := func(ctx context.Context) error {
			_ = dir.advertise(ctx)
			dir.mu.Lock()
			defer dir.mu.Unlock()
			if dir.advertised < 2 {
				return nil
			}
			cancel()
			return ctx.Err()
		}

		err := advertiseOriginBeforeCache(ctx, advertise, svr.URL, prefixes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/first")
		assert.Contains(t, err.Error(), "404")
		assert.Equal(t, 2, dir.advertised, "the origin re-advertises after a round that found nothing")
	})

	t.Run("advertise-failure-is-returned", func(t *testing.T) {
		boom := errors.New("director unreachable")
		err := advertiseOriginBeforeCache(context.Background(), func(context.Context) error { return boom }, "https://director.example", prefixes)
		require.ErrorIs(t, err, boom)
	})
}
