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

package director

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestSendMyAdInsertsIntoDirectorAds verifies that sendMyAd inserts the
// local director's own entry into directorAds without requiring a gossip
// round-trip from a peer.
func TestSendMyAdInsertsIntoDirectorAds(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	const selfName = "test-self-director"
	require.NoError(t, param.Server_ExternalWebUrl.Set("http://self.example.com"))

	setupForwardingState(t)
	directorName = selfName

	ResetState()
	t.Cleanup(ResetState)

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	sendMyAd(ctx)

	item := directorAds.Get(selfName)
	require.NotNil(t, item, "directorAds must contain the self-entry after sendMyAd")
	require.NotNil(t, item.Value())
	require.NotNil(t, item.Value().ad)
	assert.Equal(t, selfName, item.Value().ad.Name)
	assert.Equal(t, "http://self.example.com", item.Value().ad.AdvertiseUrl)
}

// TestListDirectorsReturnsSelfAfterPeerExpires verifies the key
// recoverability invariant: after all peer ads expire, the next sendMyAd
// call ensures the self-entry is present in directorAds so that
// listDirectors returns it.
func TestListDirectorsReturnsSelfAfterPeerExpires(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	const selfName = "test-self-director"
	require.NoError(t, param.Server_ExternalWebUrl.Set("http://self.example.com"))

	setupForwardingState(t)
	directorName = selfName

	ResetState()
	t.Cleanup(ResetState)

	// Register a peer with a very short TTL to simulate it expiring.
	makeTestDirector(t, "peer-director", 1*time.Millisecond)

	// Wait for the peer entry to be lazily evicted via Items() — no time.Sleep.
	require.Eventually(t, func() bool {
		return len(directorAds.Items()) == 0
	}, 1*time.Second, 5*time.Millisecond, "peer ad should expire")

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	sendMyAd(ctx)

	items := directorAds.Items()
	require.Len(t, items, 1, "directorAds must contain exactly the self-entry")
	selfItem, ok := items[selfName]
	require.True(t, ok, "self-entry must be keyed by the director name")
	require.NotNil(t, selfItem.Value())
	require.NotNil(t, selfItem.Value().ad)
	assert.Equal(t, selfName, selfItem.Value().ad.Name)
}
