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

package local_cache

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

// TestTierRedirectSelfTest covers the check that stands between minting URLs
// and handing them out.  The fake door here speaks dCache's macaroon protocol
// but checks path: caveats the way XRootD does, without the name: caveat that
// would give it away -- a server the cache's model of dCache is wrong about.
// Every URL minted for it would fail at the server, so the target must be
// proxied, visibly; and once the server behaves, redirects resume.
func TestTierRedirectSelfTest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("WorkingURLsAreHandedOut", func(t *testing.T) {
		f := newFakeDCache(t)
		target := registerFakeDCacheTarget(t, ctx, f)
		assert.True(t, target.redirectUsable())
		assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		_, reads, _ := f.stats()
		assert.Equal(t, 1, reads, "the self-test fetched a minted URL")
	})

	t.Run("FailingURLsAreNot", func(t *testing.T) {
		f := newFakeDCache(t)
		f.set(func(f *fakeDCache) { f.xrootd = true })
		target := registerFakeDCacheTarget(t, ctx, f)
		assert.True(t, target.canRedirect, "the door issues macaroons the cache can parse...")
		assert.False(t, target.redirectUsable(), "...but the URLs minted from them do not work")
		assert.Equal(t, 0.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		lastErr, _ := target.lastRedirectError.Load().(string)
		assert.Contains(t, lastErr, "403")
		assert.NotContains(t, lastErr, "authz", "the minted URL must not reach the log")

		// The health component says why the target is being proxied.
		u := &tierUploader{storage: &StorageManager{tierTargets: map[StorageID]*tierTarget{target.id: target}}}
		u.publishHealth()
		status, err := metrics.GetComponentStatus(metrics.Cache_TieringStorage)
		require.NoError(t, err)
		assert.Equal(t, metrics.StatusWarning.String(), status)
		message := metrics.GetHealthStatus().ComponentStatus[metrics.Cache_TieringStorage].Message
		assert.Contains(t, message, "redirect URLs do not work")

		// Once the server accepts the URLs, the next check restores
		// redirects.
		f.set(func(f *fakeDCache) { f.xrootd = false })
		require.NoError(t, target.checkRedirect(ctx))
		assert.True(t, target.redirectUsable())
		assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
		u.publishHealth()
		status, err = metrics.GetComponentStatus(metrics.Cache_TieringStorage)
		require.NoError(t, err)
		assert.Equal(t, metrics.StatusOK.String(), status)
	})
}

// signingTierBackend stands in for a bucket that can sign URLs, on a host
// that no client could reach: it reports an https destination and counts the
// URLs it is asked to mint.
type signingTierBackend struct {
	TierBackend
	minted atomic.Int32
}

func (b *signingTierBackend) probeRedirect(context.Context) (string, bool) {
	return "https://bucket.invalid/probe", true
}

func (b *signingTierBackend) RedirectURL(context.Context, string, time.Duration, *TierObjectInfo) (string, error) {
	b.minted.Add(1)
	return "https://bucket.invalid/object", nil
}

// TestTierRedirectSelfTestSkippedWhenRedirectsDisabled: with
// Cache.TieringDisableRedirect set, no client is redirected, so a target that
// could sign URLs is neither self-tested at registration nor by the liveness
// probe, and neither the log nor the health component complains about URLs
// that would not work.
func TestTierRedirectSelfTestSkippedWhenRedirectsDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, param.Cache_TieringDisableRedirect.Set(true))
	t.Cleanup(func() { _ = param.Cache_TieringDisableRedirect.Set(false) })
	var backend *signingTierBackend
	wrapTierBackendForTest = func(inner TierBackend) TierBackend {
		backend = &signingTierBackend{TierBackend: inner}
		return backend
	}
	t.Cleanup(func() { wrapTierBackendForTest = nil })
	warnings := captureWarnings(t)

	env := newMemTierEnv(t, ctx)
	wrapTierBackendForTest = nil
	require.NotNil(t, backend)
	assert.False(t, env.target.canRedirect)
	require.NoError(t, env.target.checkRedirect(ctx))
	assert.Zero(t, backend.minted.Load(), "no URL was minted for a self-test")
	assert.Equal(t, 0.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(env.target.metricLabel())))
	for _, w := range warnings() {
		assert.False(t, strings.Contains(w, "Redirect URLs"), "unexpected warning: %s", w)
	}
	env.uploader.publishHealth()
	status, err := metrics.GetComponentStatus(metrics.Cache_TieringStorage)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusOK.String(), status)
}
